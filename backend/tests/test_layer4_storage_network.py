"""Layer 4 local-storage + network-config modules with a mocked adb."""
from __future__ import annotations

import pytest

from app.layers import layer4_android as l4
from app.layers.layer4_android import harness

from .test_layer4_android import FakeAdb, _ctx, _instr_stdout, _payload, apk, use_fake  # noqa: F401

CLEAN_STORAGE = {
    "targetSdkVersion": 34, "allowBackup": False, "debuggable": False, "usesCleartextTraffic": False,
    "requestLegacyExternalStorage": False, "fullBackupContentSet": False, "dataExtractionRulesSet": True,
    "externalStoragePermissions": [],
    "dataDir": {"path": "/data/user/0/x", "readable": False, "listable": False, "readableEntries": []},
    "filesDir": {"path": "/data/user/0/x/files", "readable": False, "listable": False, "readableEntries": []},
    "sharedPrefsDir": {"path": "/data/user/0/x/shared_prefs", "readable": False, "listable": False, "readableEntries": []},
    "externalAppDir": {"path": "/storage/emulated/0/Android/data/x", "readable": False, "listable": False, "readableEntries": []},
}
PINNED = {"cleartextTrafficPermitted": False, "trustAnchors": ["system"], "domains": [{"name": "api.example.com", "includeSubdomains": True}], "pins": 2}
CLEAN_NET = {
    "targetSdkVersion": 34, "usesCleartextTraffic": False, "debuggable": False, "networkSecurityConfigPresent": True,
    "networkSecurityConfig": {"baseConfig": {"cleartextTrafficPermitted": False, "trustAnchors": ["system"], "domains": [], "pins": 0},
                              "domainConfigs": [PINNED], "debugOverrides": None},
}


def _run(use_fake, apk, fn, **sections):
    use_fake(FakeAdb(instr=_instr_stdout(_payload(**sections))))
    return fn(_ctx(apk))


def _sev(r):
    return {f.title: f.severity for f in r.findings}


# --- local storage --------------------------------------------------------

def test_storage_clean(use_fake, apk):
    r = _run(use_fake, apk, l4.run_local_storage, localStorage=CLEAN_STORAGE)
    assert r.passed and not r.skipped and r.findings == []


def test_storage_findings(use_fake, apk):
    bad = dict(CLEAN_STORAGE, allowBackup=True, debuggable=True, requestLegacyExternalStorage=True,
               usesCleartextTraffic=True, dataExtractionRulesSet=False,
               externalStoragePermissions=["android.permission.WRITE_EXTERNAL_STORAGE"],
               sharedPrefsDir={"path": "/d/shared_prefs", "readable": True, "listable": True, "readableEntries": ["prefs.xml"]})
    r = _run(use_fake, apk, l4.run_local_storage, localStorage=bad)
    s = _sev(r)
    assert not r.passed and not r.skipped
    assert s["Application is debuggable"] == "high"
    assert s["Backup of app data allowed"] == "medium"
    assert s["Legacy external storage requested"] == "medium"
    assert s["Cleartext traffic enabled"] == "medium"
    assert s["External storage permissions requested"] == "low"
    assert s["Files readable by other apps in shared_prefs/"] == "high"


def test_storage_backup_with_rules_is_low(use_fake, apk):
    r = _run(use_fake, apk, l4.run_local_storage, localStorage=dict(CLEAN_STORAGE, allowBackup=True))
    assert _sev(r) == {"Backup of app data allowed": "low"} and not r.passed


def test_storage_manifest_unparsed_is_info_not_fail(use_fake, apk):
    s = dict(CLEAN_STORAGE, requestLegacyExternalStorage=None, manifestParseError="IOException: x")
    r = _run(use_fake, apk, l4.run_local_storage, localStorage=s)
    assert r.passed and _sev(r) == {"Manifest attributes could not be determined": "info"}


# --- network config -------------------------------------------------------

def test_network_clean_with_pinning(use_fake, apk):
    r = _run(use_fake, apk, l4.run_network_config, networkConfig=CLEAN_NET)
    assert r.passed and r.findings == [] and "pins=2" in r.summary


def test_network_findings(use_fake, apk):
    nsc = {"baseConfig": {"cleartextTrafficPermitted": True, "trustAnchors": ["system", "user"], "domains": [], "pins": 0},
           "domainConfigs": [dict(PINNED, cleartextTrafficPermitted=True, pins=0)],
           "debugOverrides": {"trustAnchors": ["user"], "domains": [], "pins": 0}}
    net = dict(CLEAN_NET, networkSecurityConfig=nsc, debuggable=True)
    r = _run(use_fake, apk, l4.run_network_config, networkConfig=net)
    s = _sev(r)
    assert not r.passed
    assert s["Cleartext traffic permitted app-wide"] == "high"
    assert s["Cleartext permitted for domain-config(api.example.com)"] == "medium"
    assert s["User-installed CAs trusted in base-config"] == "high"
    assert s["debug-overrides present"] == "high"
    assert s["No certificate pinning in network security config"] == "low"


def test_network_no_nsc_uses_manifest_flag(use_fake, apk):
    net = {"targetSdkVersion": 23, "usesCleartextTraffic": True, "debuggable": False, "networkSecurityConfigPresent": False}
    r = _run(use_fake, apk, l4.run_network_config, networkConfig=net)
    s = _sev(r)
    assert s["Cleartext traffic permitted app-wide"] == "high"
    assert s["User CAs trusted by default (targetSdk < 24)"] == "high"
    assert not r.passed


def test_network_debug_overrides_release_is_info(use_fake, apk):
    nsc = dict(CLEAN_NET["networkSecurityConfig"], debugOverrides={"trustAnchors": ["user"], "domains": [], "pins": 0})
    r = _run(use_fake, apk, l4.run_network_config, networkConfig=dict(CLEAN_NET, networkSecurityConfig=nsc))
    assert r.passed and _sev(r) == {"debug-overrides present": "info"}


def test_network_nsc_parse_error_raises(use_fake, apk):
    net = {"usesCleartextTraffic": False, "networkSecurityConfigPresent": True, "nscParseError": "XmlPullParserException: x"}
    use_fake(FakeAdb(instr=_instr_stdout(_payload(networkConfig=net))))
    with pytest.raises(harness.HarnessError, match="network security config"):
        l4.run_network_config(_ctx(apk))


# --- shared: skips, malformed / missing / errored sections -----------------

@pytest.mark.parametrize("fn", [l4.run_local_storage, l4.run_network_config])
def test_skips_when_adb_missing(monkeypatch, fn):
    monkeypatch.delenv("IDENTITYSHIELD_ADB", raising=False)
    monkeypatch.setattr(harness.shutil, "which", lambda _: None)
    r = fn(_ctx())
    assert r.skipped and not r.passed and r.summary.startswith("skipped: no device")


@pytest.mark.parametrize("fn", [l4.run_local_storage, l4.run_network_config])
def test_skips_when_no_device(use_fake, apk, fn):
    use_fake(FakeAdb(devices=""))
    r = fn(_ctx(apk))
    assert r.skipped and not r.passed and "no device" in r.summary


@pytest.mark.parametrize("fn", [l4.run_local_storage, l4.run_network_config])
def test_malformed_json_raises(use_fake, apk, fn):
    use_fake(FakeAdb(instr="INSTRUMENTATION_RESULT: identityshield_json={not json\nINSTRUMENTATION_CODE: -1\n"))
    with pytest.raises(harness.HarnessError, match="Malformed JSON"):
        fn(_ctx(apk))


@pytest.mark.parametrize("fn,key", [(l4.run_local_storage, "localStorage"), (l4.run_network_config, "networkConfig")])
@pytest.mark.parametrize("value,msg", [(None, "no valid"), ("oops", "no valid"), ({"error": "NameNotFoundException: x"}, "check failed")])
def test_bad_section_raises(use_fake, apk, fn, key, value, msg):
    data = _payload()
    if value is not None:
        data[key] = value
    use_fake(FakeAdb(instr=_instr_stdout(data)))
    with pytest.raises(harness.HarnessError, match=msg):
        fn(_ctx(apk))


def test_runner_records_skipped_for_both(monkeypatch):
    from app.orchestrator import runner
    from tests.helpers import run_module

    monkeypatch.setattr(runner, "assert_in_scope", lambda db, t, **kw: None)
    monkeypatch.delenv("IDENTITYSHIELD_ADB", raising=False)
    monkeypatch.setattr(harness.shutil, "which", lambda _: None)
    for mid in ("android.storage.local_data_at_rest", "android.network.transport_security_config"):
        snap = run_module("com.example.kyc", mid)
        assert snap.status == "skipped" and snap.summary.startswith("skipped: no device")

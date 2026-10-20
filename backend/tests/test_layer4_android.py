"""Layer 4 harness tests with a mocked adb (no device needed)."""
from __future__ import annotations

import json
import subprocess

import pytest

from app.layers import layer4_android as l4
from app.layers.layer4_android import harness
from app.orchestrator.registry import TestContext

PKG = "com.example.kyc"
SHA = "ab" * 32


def _payload(**over):
    data = {
        "targetPackage": PKG,
        "signature": {"packageName": PKG, "signingCertSha256": SHA},
        "permissions": [
            {"permission": "android.permission.CAMERA", "isDangerous": True, "granted": True},
            {"permission": "android.permission.INTERNET", "isDangerous": False, "granted": True},
        ],
        "deviceTrustSignals": {"build_tags_test_keys": False, "known_emulator_fingerprint": True, "su_binary_present": False},
    }
    data.update(over)
    return data


def _instr_stdout(data, code="-1"):
    return f"INSTRUMENTATION_RESULT: identityshield_json={json.dumps(data)}\nINSTRUMENTATION_CODE: {code}\n"


class FakeAdb:
    """Records calls and answers like adb would."""

    def __init__(self, devices="emulator-5554\tdevice\n", install="Success\n", instr=None, instr_rc=0):
        self.devices, self.install, self.instr, self.instr_rc = devices, install, instr, instr_rc
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if cmd[1:] == ["devices"]:
            out = "List of devices attached\n" + self.devices
            return subprocess.CompletedProcess(cmd, 0, out, "")
        if "install" in cmd:
            return subprocess.CompletedProcess(cmd, 0, self.install, "")
        if "instrument" in cmd:
            out = self.instr if self.instr is not None else _instr_stdout(_payload())
            return subprocess.CompletedProcess(cmd, self.instr_rc, out, "")
        raise AssertionError(f"unexpected adb call {cmd}")


@pytest.fixture
def apk(tmp_path):
    p = tmp_path / "app-debug.apk"
    p.write_bytes(b"PK")
    return str(p)


def _ctx(apk=None, **params):
    if apk:
        params["apk_path"] = apk
    return TestContext(target=PKG, db=None, evidence_dir="/tmp", params=params)


@pytest.fixture
def use_fake(monkeypatch):
    def install(fake, adb="/usr/bin/adb"):
        real = harness.run_integrity_checks
        monkeypatch.setattr(
            harness, "run_integrity_checks", lambda *a, **k: real(*a, runner=fake, adb=adb, **k)
        )
        return fake
    return install


# --- skip paths: honest, never a pass ------------------------------------

def test_skips_when_adb_missing(monkeypatch):
    monkeypatch.delenv("IDENTITYSHIELD_ADB", raising=False)
    monkeypatch.setattr(harness.shutil, "which", lambda _: None)
    r = l4.run_permission_audit(_ctx())
    assert r.skipped and not r.passed
    assert r.summary.startswith("skipped: no device")


def test_skips_when_no_device(use_fake, apk):
    fake = use_fake(FakeAdb(devices=""))
    r = l4.run_permission_audit(_ctx(apk))
    assert r.skipped and not r.passed and "no device" in r.summary
    assert not any("install" in c for c in fake.calls)


def test_unauthorized_device_is_not_usable(use_fake, apk):
    use_fake(FakeAdb(devices="R58M\tunauthorized\n"))
    r = l4.run_trust_signals(_ctx(apk))
    assert r.skipped and not r.passed


def test_skips_when_apk_not_built(use_fake, tmp_path):
    use_fake(FakeAdb())
    r = l4.run_permission_audit(_ctx(str(tmp_path / "missing.apk")))
    assert r.skipped and "APK not built" in r.summary


def test_signature_skips_without_expected_hash(use_fake, apk):
    fake = use_fake(FakeAdb())
    r = l4.run_signature_check(_ctx(apk))
    assert r.skipped and not r.passed
    assert fake.calls == []


# --- real execution path (mocked adb) ------------------------------------

def test_install_and_instrument_commands(use_fake, apk):
    fake = use_fake(FakeAdb())
    l4.run_permission_audit(_ctx(apk))
    assert fake.calls[1] == ["/usr/bin/adb", "-s", "emulator-5554", "install", "-r", "-t", apk]
    assert fake.calls[2][-1] == harness.INSTRUMENTATION
    assert ["-e", "target_package", PKG] == fake.calls[2][7:10]


def test_permission_audit_flags_dangerous(use_fake, apk):
    use_fake(FakeAdb())
    r = l4.run_permission_audit(_ctx(apk))
    assert not r.skipped and not r.passed
    assert [f.title for f in r.findings] == ["Dangerous permission requested: android.permission.CAMERA"]
    assert r.findings[0].severity == "medium"


def test_permission_audit_passes_when_clean(use_fake, apk):
    use_fake(FakeAdb(instr=_instr_stdout(_payload(permissions=[
        {"permission": "android.permission.INTERNET", "isDangerous": False, "granted": True}]))))
    r = l4.run_permission_audit(_ctx(apk))
    assert r.passed and not r.skipped and r.findings == []


def test_signature_match_and_mismatch(use_fake, apk):
    use_fake(FakeAdb())
    ok = l4.run_signature_check(_ctx(apk, expected_signing_sha256=SHA.upper()))
    assert ok.passed and not ok.skipped
    bad = l4.run_signature_check(_ctx(apk, expected_signing_sha256="cd" * 32))
    assert not bad.passed and bad.findings[0].severity == "critical"


def test_trust_signals_reported(use_fake, apk):
    use_fake(FakeAdb())
    r = l4.run_trust_signals(_ctx(apk))
    assert r.passed and [f.title for f in r.findings] == ["Device trust indicator present: known_emulator_fingerprint"]


def test_specific_serial_must_be_attached(use_fake, apk):
    use_fake(FakeAdb())
    r = l4.run_permission_audit(_ctx(apk, serial="other"))
    assert r.skipped


def test_multiple_devices_requires_serial(use_fake, apk):
    use_fake(FakeAdb(devices="a\tdevice\nb\tdevice\n"))
    with pytest.raises(harness.HarnessError, match="Multiple devices"):
        l4.run_permission_audit(_ctx(apk))


@pytest.mark.parametrize("fake_kwargs,msg", [
    ({"install": "Failure [INSTALL_FAILED]\n"}, "install failed"),
    ({"instr": "INSTRUMENTATION_FAILED: x\n"}, "failed"),
    ({"instr": "garbage\n"}, "No IdentityShield result"),
    ({"instr": _instr_stdout({"error": "NameNotFoundException: x"}, code="0")}, "Companion reported an error"),
    ({"instr": _instr_stdout(_payload(), code="0")}, "code"),
])
def test_errors_raise_not_pass(use_fake, apk, fake_kwargs, msg):
    use_fake(FakeAdb(**fake_kwargs))
    with pytest.raises(harness.HarnessError, match=msg):
        l4.run_permission_audit(_ctx(apk))


# --- runner integration: SKIPPED status is persisted, never PASSED ---------

def test_runner_records_skipped(monkeypatch):
    from app.orchestrator import runner
    from tests.helpers import run_module

    monkeypatch.setattr(runner, "assert_in_scope", lambda db, t: None)
    monkeypatch.delenv("IDENTITYSHIELD_ADB", raising=False)
    monkeypatch.setattr(harness.shutil, "which", lambda _: None)
    snap = run_module(PKG, "android.permissions.dangerous_permission_audit")
    assert snap.status == "skipped"
    assert snap.summary.startswith("skipped: no device")


def test_runner_blocks_out_of_scope_package():
    from tests.helpers import run_module

    snap = run_module("com.not.allowlisted", "android.permissions.dangerous_permission_audit")
    assert snap.status == "blocked_scope"


def test_self_target_does_not_flag_own_data_dir(use_fake, apk):
    # Captured from a real API 34 emulator: the companion targeting itself can
    # always list its own data dir; that must not be reported as cross-app exposure.
    probe = lambda p, ok: {"path": p, "readable": ok, "listable": ok, "readableEntries": []}  # noqa: E731
    base = "/data/user/0/" + harness.COMPANION_PACKAGE
    storage = {
        "targetSdkVersion": 36, "allowBackup": False, "debuggable": False, "usesCleartextTraffic": False,
        "requestLegacyExternalStorage": None, "fullBackupContentSet": False, "dataExtractionRulesSet": False,
        "externalStoragePermissions": [], "dataDir": probe(base, True), "filesDir": probe(base + "/files", False),
        "sharedPrefsDir": probe(base + "/shared_prefs", False), "externalAppDir": probe("/storage/x", False),
    }
    use_fake(FakeAdb(instr=_instr_stdout(_payload(localStorage=storage))))
    self_ctx = TestContext(target=harness.COMPANION_PACKAGE, db=None, evidence_dir="/tmp", params={"apk_path": apk})
    r = l4.run_local_storage(self_ctx)
    assert r.passed
    assert [f.title for f in r.findings] == ["Cross-app readability not assessed"]
    # The same probe for any other package is still flagged.
    r2 = l4.run_local_storage(_ctx(apk))
    assert any("listable by other apps" in f.title for f in r2.findings)

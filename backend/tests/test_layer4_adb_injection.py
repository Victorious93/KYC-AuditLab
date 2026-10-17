"""Regression tests for audit F2: the raw Layer 4 target reached
`adb shell am instrument ... -e target_package <target>`, and `adb shell`
re-parses its joined argv with the device's /system/bin/sh. A target such as
`com.android.settings/ ;touch /data/local/tmp/x` passed scope (host
`com.android.settings`) and would have run the extra command on the device.

All adb calls here are mocked; no device is needed."""
from __future__ import annotations

import shlex
import subprocess

import pytest

from app.layers import layer4_android as l4
from app.layers.layer4_android import harness
from app.orchestrator import scope
from app.orchestrator.registry import TestContext
from app.orchestrator.scope import ScopeViolation, validate_android_package

from .test_layer4_android import FakeAdb, _instr_stdout, _payload

INJECTIONS = [
    "com.android.settings/ ;touch /data/local/tmp/x",
    "com.android.settings;touch /data/local/tmp/x",
    "com.android.settings && reboot",
    "com.android.settings|id",
    "com.android.settings`id`",
    "com.android.settings$(id)",
    "com.android.settings\nid",
    "com.android.settings'",
    'com.android.settings"',
    "com.android.settings>/sdcard/x",
    "com.android.settings -e x y",
    "com.android.settings:8000",
    "com.android.settings\\@localhost",
    "-ecom.android.settings",
]

INVALID = [
    "",
    "settings",                 # needs at least two segments
    "1com.example.app",         # segment must start with a letter
    "com.1example.app",
    "_com.example",
    "com..example",
    "com.example.",
    ".com.example",
    "com.exa-mple.app",
    "com.exämple.app",
    "a." + "b" * 300,
]

VALID = ["com.android.settings", "com.google.android.gm", "com.Example.KYC_App2", "a.b", "com.identityshield.companion"]


class ExplodingRunner:
    def __call__(self, cmd, **kw):  # pragma: no cover - must never run
        raise AssertionError(f"adb must not be invoked for an invalid package, got {cmd}")


@pytest.mark.parametrize("bad", INJECTIONS + INVALID)
def test_scope_rejects_invalid_package(bad):
    with pytest.raises(ScopeViolation):
        validate_android_package(bad)


@pytest.mark.parametrize("good", VALID)
def test_scope_accepts_valid_package(good):
    assert validate_android_package(good) == good


@pytest.mark.parametrize("bad", INJECTIONS + INVALID)
def test_harness_rejects_before_any_adb_call(bad, tmp_path):
    apk = tmp_path / "app-debug.apk"
    apk.write_bytes(b"PK")
    with pytest.raises(harness.InvalidPackageName):
        harness.run_integrity_checks(bad, apk_path=str(apk), runner=ExplodingRunner(), adb="/usr/bin/adb")


@pytest.mark.parametrize("bad", INJECTIONS)
def test_module_never_calls_adb_for_injected_target(bad, monkeypatch):
    real = harness.run_integrity_checks
    monkeypatch.setattr(
        harness, "run_integrity_checks", lambda *a, **k: real(*a, runner=ExplodingRunner(), adb="/usr/bin/adb", **k)
    )
    ctx = TestContext(target=bad, db=None, evidence_dir="/tmp", params={})
    with pytest.raises(harness.InvalidPackageName):
        l4.run_permission_audit(ctx)


def test_patterns_in_scope_and_harness_are_identical():
    assert scope.ANDROID_PACKAGE_RE.pattern == harness.ANDROID_PACKAGE_RE.pattern
    assert scope.ANDROID_PACKAGE_RE.pattern == r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$"


def test_remote_shell_args_are_quoted():
    assert harness.remote_shell_args("am", "x y", "a;b", "$(id)") == ["am", "'x y'", "'a;b'", "'$(id)'"]


def test_instrument_argv_is_a_list_with_quoted_remote_tokens(tmp_path):
    apk = tmp_path / "app-debug.apk"
    apk.write_bytes(b"PK")
    fake = FakeAdb(instr=_instr_stdout(_payload(targetPackage="com.android.settings")))
    harness.run_integrity_checks("com.android.settings", apk_path=str(apk), runner=fake, adb="/usr/bin/adb")
    instr = fake.calls[2]
    assert isinstance(instr, list)
    assert instr[:4] == ["/usr/bin/adb", "-s", "emulator-5554", "shell"]
    remote = instr[4:]
    # What the device shell would see after adb joins the argv:
    assert shlex.split(" ".join(remote)) == [
        "am", "instrument", "-w", "-e", "target_package", "com.android.settings", harness.INSTRUMENTATION,
    ]
    assert all(t == shlex.quote(t) for t in remote)  # valid inputs need no quoting


@pytest.mark.parametrize("bad", INJECTIONS)
def test_runner_blocks_injection_even_if_host_allowlisted_and_scoped(bad, monkeypatch, live_server):
    """End to end through the runner: the host part (`com.android.settings`)
    is allowlisted and has a ScopeEntry, yet the run is blocked before adb."""
    import requests

    from tests.helpers import ADMIN_HEADERS, run_module

    monkeypatch.setattr(scope.settings, "allowed_targets", list(scope.settings.allowed_targets) + ["com.android.settings"])
    requests.post(f"http://{live_server}/scope", json={"target": "com.android.settings"}, headers=ADMIN_HEADERS, timeout=5)
    real = harness.run_integrity_checks
    monkeypatch.setattr(
        harness, "run_integrity_checks", lambda *a, **k: real(*a, runner=ExplodingRunner(), adb="/usr/bin/adb", **k)
    )
    snap = run_module(bad, "android.permissions.dangerous_permission_audit")
    assert snap.status == "blocked_scope", (bad, snap.status, snap.summary)
    assert "not a valid Android package name" in snap.summary

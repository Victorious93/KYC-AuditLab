"""ADB / instrumentation harness for Layer 4 (Android).

Flow: locate `adb` -> pick an attached, authorized device -> install the
companion APK -> run its `IntegrityInstrumentation` via `am instrument -w`
-> parse the JSON it returns into a dict.

Honesty contract: if `adb`, a device, or the companion APK is unavailable,
the harness returns a SKIPPED outcome with a reason. It never fabricates
check data and never reports a skip as a pass.

All subprocess access goes through an injectable `runner` so the unit tests
can mock adb without a device.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

COMPANION_PACKAGE = "com.identityshield.companion"
INSTRUMENTATION = f"{COMPANION_PACKAGE}/.IntegrityInstrumentation"
RESULT_KEY = "identityshield_json"

_REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_APK = _REPO_ROOT / "android-companion" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"

Runner = Callable[..., subprocess.CompletedProcess]

# Must match orchestrator.scope_android.ANDROID_PACKAGE_RE. Re-checked here so the
# harness is safe even when called directly (not via the runner).
ANDROID_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
ANDROID_PACKAGE_MAX_LEN = 255


class HarnessError(RuntimeError):
    """adb was present and a device attached, but something went wrong."""


class InvalidPackageName(ValueError):
    """The Layer 4 target is not a strict Android package name. Raised
    before adb is ever invoked."""


def validate_package_name(name: str) -> str:
    if not isinstance(name, str) or len(name) > ANDROID_PACKAGE_MAX_LEN or not ANDROID_PACKAGE_RE.fullmatch(name):
        raise InvalidPackageName(f"Refusing invalid Android package name {name!r}")
    return name


def remote_shell_args(*args: str) -> List[str]:
    """`adb shell` joins its argv with spaces and the DEVICE's /system/bin/sh
    re-parses the line, so every token bound for the remote shell is
    shlex-quoted. Combined with strict package validation, nothing a caller
    supplies can introduce shell syntax on the device."""
    return [shlex.quote(str(a)) for a in args]


@dataclass
class HarnessOutcome:
    status: str  # "ok" | "skipped"
    reason: str = ""
    serial: Optional[str] = None
    checks: Dict = field(default_factory=dict)
    raw_output: str = ""

    @property
    def skipped(self) -> bool:
        return self.status == "skipped"


def find_adb() -> Optional[str]:
    explicit = os.environ.get("IDENTITYSHIELD_ADB")
    if explicit:
        return explicit if Path(explicit).is_file() else None
    return shutil.which("adb")


def _run(runner: Runner, cmd: Sequence[str], timeout: int) -> subprocess.CompletedProcess:
    return runner(list(cmd), capture_output=True, text=True, timeout=timeout, check=False)


def list_devices(adb: str, runner: Runner = subprocess.run) -> List[str]:
    """Serials of devices in the `device` state (excludes `unauthorized`/`offline`)."""
    proc = _run(runner, [adb, "devices"], timeout=15)
    if proc.returncode != 0:
        return []
    serials = []
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


def parse_instrumentation_output(stdout: str) -> Dict:
    """Extract the companion's JSON payload from `am instrument -w` output.

    Expected lines (Android prints the result bundle as key=value):
        INSTRUMENTATION_RESULT: identityshield_json={...}
        INSTRUMENTATION_CODE: -1
    """
    payload = None
    code = None
    for line in stdout.splitlines():
        line = line.strip()
        prefix = f"INSTRUMENTATION_RESULT: {RESULT_KEY}="
        if line.startswith(prefix):
            payload = line[len(prefix):]
        elif line.startswith("INSTRUMENTATION_CODE:"):
            code = line.split(":", 1)[1].strip()
    if "INSTRUMENTATION_FAILED" in stdout or "INSTRUMENTATION_ABORTED" in stdout:
        raise HarnessError("Instrumentation failed/aborted:\n" + stdout[-2000:])
    if payload is None:
        raise HarnessError("No IdentityShield result in instrumentation output:\n" + stdout[-2000:])
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise HarnessError(f"Malformed JSON from companion: {exc}") from exc
    if "error" in data:
        raise HarnessError(f"Companion reported an error: {data['error']}")
    if code != "-1":  # Activity.RESULT_OK
        raise HarnessError(f"Instrumentation returned code {code!r}, expected -1 (RESULT_OK)")
    return data


def run_integrity_checks(
    target_package: str,
    *,
    serial: Optional[str] = None,
    apk_path: Optional[str] = None,
    runner: Runner = subprocess.run,
    adb: Optional[str] = None,
) -> HarnessOutcome:
    target_package = validate_package_name(target_package)  # before any adb call
    adb = adb or find_adb()
    if not adb:
        return HarnessOutcome("skipped", "skipped: no device (adb not found on PATH)")

    devices = list_devices(adb, runner)
    if serial:
        if serial not in devices:
            return HarnessOutcome("skipped", f"skipped: no device (serial {serial!r} not attached/authorized)")
    elif not devices:
        return HarnessOutcome("skipped", "skipped: no device (no authorized device/emulator attached)")
    elif len(devices) > 1:
        raise HarnessError(f"Multiple devices attached {devices}; pass params['serial'] to choose one.")
    else:
        serial = devices[0]

    apk = Path(apk_path or os.environ.get("IDENTITYSHIELD_COMPANION_APK") or DEFAULT_APK)
    if not apk.is_file():
        return HarnessOutcome(
            "skipped", f"skipped: companion APK not built ({apk}); run ./gradlew assembleDebug", serial=serial
        )

    base = [adb, "-s", serial]
    install = _run(runner, base + ["install", "-r", "-t", str(apk)], timeout=180)
    if install.returncode != 0 or "Success" not in install.stdout:
        raise HarnessError(f"APK install failed: {install.stdout}{install.stderr}")

    instr = _run(
        runner,
        base + ["shell"] + remote_shell_args("am", "instrument", "-w", "-e", "target_package", target_package, INSTRUMENTATION),
        timeout=120,
    )
    if instr.returncode != 0:
        raise HarnessError(f"am instrument exited {instr.returncode}: {instr.stdout}{instr.stderr}")
    checks = parse_instrumentation_output(instr.stdout)
    return HarnessOutcome("ok", serial=serial, checks=checks, raw_output=instr.stdout)

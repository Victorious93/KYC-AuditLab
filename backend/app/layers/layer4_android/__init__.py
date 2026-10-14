"""Layer 4 - Android Device and Application Security.

Three modules are wired to a real adb/instrumentation harness (see
`harness.py`): they install the companion APK on an attached, authorized
device, run `IntegrityInstrumentation` (which calls the Kotlin
`IntegrityChecks`), and parse the JSON it returns into findings.

The TestRun `target` is the Android package name under test (e.g.
`com.example.kyc`). Like every other target it must be allowlisted and
in scope (default-deny). Optional params: `serial`, `apk_path`,
`expected_signing_sha256`.

HONEST STATUS: when `adb`, a device, or the built companion APK is not
available, these modules return a SKIPPED run ("skipped: no device ...").
A skip is never a pass. As of this commit the harness has only been
exercised against a mocked adb in unit tests, not a real device/emulator.

Local-storage and network-security-config checks remain documented stubs:
the companion has no instrumentation for them yet.
"""
from __future__ import annotations

from ...orchestrator.registry import Capability, Finding, Layer, ModuleResult, TestContext, TestModule, registry
from . import harness


def _execute(ctx: TestContext) -> harness.HarnessOutcome:
    p = ctx.params or {}
    return harness.run_integrity_checks(ctx.target, serial=p.get("serial"), apk_path=p.get("apk_path"))


def _skip(outcome: harness.HarnessOutcome) -> ModuleResult:
    return ModuleResult(passed=False, skipped=True, summary=outcome.reason)


def run_signature_check(ctx: TestContext) -> ModuleResult:
    expected = (ctx.params or {}).get("expected_signing_sha256")
    if not expected:
        return ModuleResult(
            passed=False,
            skipped=True,
            summary="skipped: no expected_signing_sha256 param supplied; cannot verify signature",
        )
    out = _execute(ctx)
    if out.skipped:
        return _skip(out)
    actual = (out.checks.get("signature") or {}).get("signingCertSha256")
    norm = lambda s: (s or "").replace(":", "").lower()  # noqa: E731
    if not actual:
        return ModuleResult(
            passed=False,
            summary=f"No signing certificate readable for {ctx.target} on {out.serial}",
            findings=[Finding("Signing certificate unreadable", "Companion could not read the APK signer.", "high", cwe="CWE-345")],
            raw_output=out.raw_output,
        )
    if norm(actual) != norm(expected):
        return ModuleResult(
            passed=False,
            summary=f"Signing cert mismatch on {out.serial}",
            findings=[
                Finding(
                    "APK signing certificate mismatch",
                    f"Installed {ctx.target} is signed with {actual}, expected {expected}.",
                    "critical",
                    cwe="CWE-345",
                    remediation="Reinstall from a trusted source; investigate repackaging.",
                    risk_score=9.0,
                )
            ],
            raw_output=out.raw_output,
        )
    return ModuleResult(passed=True, summary=f"Signing cert matches expected on {out.serial}", raw_output=out.raw_output)


def run_permission_audit(ctx: TestContext) -> ModuleResult:
    out = _execute(ctx)
    if out.skipped:
        return _skip(out)
    perms = out.checks.get("permissions") or []
    dangerous = [p for p in perms if p.get("isDangerous")]
    findings = [
        Finding(
            f"Dangerous permission requested: {p['permission']}",
            f"{ctx.target} requests {p['permission']} (granted={p.get('granted')}). Confirm it is required.",
            "medium" if p.get("granted") else "low",
            cwe="CWE-250",
            remediation="Remove the permission if the KYC flow does not need it.",
            risk_score=5.0 if p.get("granted") else 2.0,
        )
        for p in dangerous
    ]
    return ModuleResult(
        passed=not dangerous,
        summary=f"{len(perms)} permissions requested, {len(dangerous)} dangerous (device {out.serial})",
        findings=findings,
        raw_output=out.raw_output,
    )


def run_trust_signals(ctx: TestContext) -> ModuleResult:
    out = _execute(ctx)
    if out.skipped:
        return _skip(out)
    signals = out.checks.get("deviceTrustSignals") or {}
    on = sorted(k for k, v in signals.items() if v)
    findings = [
        Finding(f"Device trust indicator present: {k}", f"Test device {out.serial} reports {k}=true.", "info")
        for k in on
    ]
    # This collects the fixture device's state; it is evidence for evaluating the
    # target app's own detection, so collection succeeding is the pass condition.
    return ModuleResult(
        passed=True,
        summary=f"Collected {len(signals)} device trust signals on {out.serial}; true: {on or 'none'}",
        findings=findings,
        raw_output=out.raw_output,
    )


registry.register(TestModule(
    id="android.integrity.apk_signature_check",
    layer=Layer.ANDROID,
    title="APK signature / integrity check",
    description="Verify the installed APK's signing certificate matches the expected release signature.",
    capability=Capability.IMPLEMENTED,
    run=run_signature_check,
))
registry.register(TestModule(
    id="android.permissions.dangerous_permission_audit",
    layer=Layer.ANDROID,
    title="Dangerous permission audit",
    description="Enumerate requested permissions via the companion's PackageManager audit and flag dangerous ones.",
    capability=Capability.IMPLEMENTED,
    run=run_permission_audit,
))
registry.register(TestModule(
    id="android.trust.root_emulator_detection_signal",
    layer=Layer.ANDROID,
    title="Root/emulator detection signal check",
    description="Collect the test device's root/emulator indicators so the app's OWN detection can be evaluated against known device state - not a bypass tool.",
    capability=Capability.IMPLEMENTED,
    run=run_trust_signals,
))

_STUB_LIMITATION = (
    "Not executed: the companion APK has no instrumentation for this check yet. "
    "Requires a debuggable build/backup or manifest extraction via adb."
)
for module_id, title, description in [
    ("android.storage.local_data_at_rest", "Local storage at-rest check",
     "Pull app-private storage (via a debuggable build or backup) and check for unencrypted PII/credentials."),
    ("android.network.transport_security_config", "Network security config check",
     "Parse the app's network_security_config.xml / manifest for cleartext traffic or certificate-pinning gaps."),
]:
    registry.register(TestModule(
        id=module_id, layer=Layer.ANDROID, title=title, description=description,
        capability=Capability.STUB_NOT_IMPLEMENTED, run=None, limitation=_STUB_LIMITATION,
    ))

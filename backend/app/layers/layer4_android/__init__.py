"""Layer 4 - Android Device and Application Security.

Five modules are wired to a real adb/instrumentation harness (see
`harness.py`): they install the companion APK on an attached, authorized
device, run `IntegrityInstrumentation` (which calls the Kotlin
`IntegrityChecks`), and parse the JSON it returns into findings.

The TestRun `target` is the Android package name under test (e.g.
`com.example.kyc`). Like every other target it must be allowlisted and
in scope (default-deny). Optional params: `serial`, `apk_path`,
`expected_signing_sha256`.

HONEST STATUS: when `adb`, a device, or the built companion APK is not
available, these modules return a SKIPPED run ("skipped: no device ...").
A skip is never a pass. All five modules have been run end-to-end against
a real Android 14 (API 34, google_apis x86_64) emulator with KVM, targeting
com.android.settings and com.google.android.gm; outputs were cross-checked
with aapt2/apksigner. Not yet run on physical hardware or other API levels.

Local-storage and network-security-config modules use the companion's
`AppExposureChecks` (non-root: PackageManager flags, the target's binary
manifest and network_security_config resources, readability probes).
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



def _section(out: harness.HarnessOutcome, key: str) -> dict:
    """Return a companion JSON section, raising HarnessError if it is missing,
    not an object, or reports an error (an error is never a pass)."""
    sec = out.checks.get(key)
    if not isinstance(sec, dict):
        raise harness.HarnessError(f"Companion output has no valid {key!r} section (old companion APK?)")
    if "error" in sec:
        raise harness.HarnessError(f"Companion {key} check failed: {sec['error']}")
    return sec


def _unknown(fields) -> Finding:
    return Finding(
        "Manifest attributes could not be determined",
        f"Companion could not parse the binary manifest; unknown: {', '.join(fields)}.",
        "info",
    )


def run_local_storage(ctx: TestContext) -> ModuleResult:
    out = _execute(ctx)
    if out.skipped:
        return _skip(out)
    s = _section(out, "localStorage")
    t = ctx.target
    f: list = []
    if s.get("debuggable"):
        f.append(Finding("Application is debuggable", f"{t} has android:debuggable=true; app data is reachable via run-as/JDWP.",
                         "high", cwe="CWE-489", remediation="Ship release builds with debuggable=false.", risk_score=8.0))
    if s.get("allowBackup"):
        ruled = s.get("dataExtractionRulesSet") or s.get("fullBackupContentSet")
        f.append(Finding("Backup of app data allowed", f"{t} has android:allowBackup=true"
                         + (" with backup/data-extraction rules set (review their scope)." if ruled else " and no fullBackupContent/dataExtractionRules restricting it."),
                         "low" if ruled else "medium", cwe="CWE-530",
                         remediation="Set allowBackup=false or exclude PII/credentials via dataExtractionRules.",
                         risk_score=3.0 if ruled else 5.0))
    if s.get("requestLegacyExternalStorage"):
        f.append(Finding("Legacy external storage requested", f"{t} sets requestLegacyExternalStorage=true (opts out of scoped storage where honored).",
                         "medium", cwe="CWE-922", remediation="Use scoped storage; keep KYC data in app-private storage.", risk_score=4.0))
    ext_perms = s.get("externalStoragePermissions") or []
    if ext_perms:
        f.append(Finding("External storage permissions requested", f"{t} requests {', '.join(ext_perms)}.",
                         "low", cwe="CWE-922", remediation="Avoid writing KYC artefacts to shared storage.", risk_score=2.0))
    if s.get("usesCleartextTraffic"):
        f.append(Finding("Cleartext traffic enabled", f"{t} has usesCleartextTraffic=true.", "medium", cwe="CWE-319",
                         remediation="Disable cleartext traffic.", risk_score=5.0))
    self_probe = t == harness.COMPANION_PACKAGE
    if self_probe:
        # The companion probing its own sandbox can always read/list it, so the
        # "readable by other apps" probes are meaningless here (found on a real
        # emulator: dataDir reported listable). Report that instead of a false positive.
        f.append(Finding("Cross-app readability not assessed",
                         f"Target {t} is the companion itself; its own data dir is always readable to it, "
                         "so the other-app readability probes were not evaluated.", "info"))
    for key, label in ([] if self_probe else [("dataDir", "app data directory"), ("filesDir", "files/"), ("sharedPrefsDir", "shared_prefs/"),
                       ("externalAppDir", "external Android/data directory")]):
        probe = s.get(key) or {}
        entries = probe.get("readableEntries") or []
        if entries:
            sev, score = ("medium", 5.0) if key == "externalAppDir" else ("high", 8.0)
            f.append(Finding(f"Files readable by other apps in {label}",
                             f"An unrelated app could read {len(entries)} file(s) in {probe.get('path')}: {', '.join(entries[:20])}.",
                             sev, cwe="CWE-276", remediation="Do not create world-readable files; keep data app-private.", risk_score=score))
        elif probe.get("listable") and key != "externalAppDir":
            f.append(Finding(f"{label} is listable by other apps", f"{probe.get('path')} can be listed by an unrelated app.",
                             "medium", cwe="CWE-276", risk_score=4.0))
    if s.get("manifestParseError"):
        f.append(_unknown(["requestLegacyExternalStorage", "dataExtractionRules", "fullBackupContent", "storage permissions"]))
    actionable = [x for x in f if x.severity != "info"]
    return ModuleResult(
        passed=not actionable,
        summary=f"Local storage exposure on {out.serial}: {len(actionable)} issue(s) (non-root view; app-private file contents not inspected)",
        findings=f, raw_output=out.raw_output,
    )


def _blocks(nsc: dict):
    yield "base-config", nsc.get("baseConfig") or {}
    for d in nsc.get("domainConfigs") or []:
        names = ",".join(x.get("name", "?") for x in d.get("domains") or []) or "?"
        yield f"domain-config({names})", d


def run_network_config(ctx: TestContext) -> ModuleResult:
    out = _execute(ctx)
    if out.skipped:
        return _skip(out)
    s = _section(out, "networkConfig")
    t = ctx.target
    f: list = []
    nsc = s.get("networkSecurityConfig") if isinstance(s.get("networkSecurityConfig"), dict) else None
    target_sdk = s.get("targetSdkVersion") or 0
    base = (nsc or {}).get("baseConfig") or {}
    base_ct = base.get("cleartextTrafficPermitted")
    if base_ct is True or (base_ct is None and s.get("usesCleartextTraffic")):
        f.append(Finding("Cleartext traffic permitted app-wide", f"{t} permits cleartext HTTP by default (base-config/usesCleartextTraffic).",
                         "high", cwe="CWE-319", remediation="Set cleartextTrafficPermitted=false.", risk_score=7.0))
    if nsc:
        for name, blk in list(_blocks(nsc))[1:]:
            if blk.get("cleartextTrafficPermitted") is True:
                f.append(Finding(f"Cleartext permitted for {name}", f"{t} allows cleartext to {name}.", "medium",
                                 cwe="CWE-319", risk_score=5.0))
        for name, blk in _blocks(nsc):
            if "user" in (blk.get("trustAnchors") or []):
                f.append(Finding(f"User-installed CAs trusted in {name}", f"{t} trusts user CAs in {name}, enabling TLS interception.",
                                 "high", cwe="CWE-295", remediation="Trust only system CAs (or pinned) in release.", risk_score=7.0))
        dbg = nsc.get("debugOverrides")
        if isinstance(dbg, dict):
            sev = "high" if s.get("debuggable") else "info"
            f.append(Finding("debug-overrides present", f"{t} declares <debug-overrides> (anchors: {dbg.get('trustAnchors')}); active only in debuggable builds.",
                             sev, cwe="CWE-295", risk_score=6.0 if sev == "high" else 0.0))
        pins = sum(blk.get("pins", 0) or 0 for _, blk in _blocks(nsc))
    else:
        pins = 0
    if s.get("networkSecurityConfigPresent") is False and target_sdk and target_sdk < 24:
        f.append(Finding("User CAs trusted by default (targetSdk < 24)", f"{t} targets SDK {target_sdk} with no network security config.",
                         "high", cwe="CWE-295", risk_score=7.0))
    if not pins:
        f.append(Finding("No certificate pinning in network security config", f"{t} declares no <pin-set> (runtime/OkHttp pinning is not visible to this check).",
                         "low", cwe="CWE-295", remediation="Consider pinning the KYC API endpoints.", risk_score=2.0))
    if s.get("manifestParseError"):
        f.append(_unknown(["networkSecurityConfig"]))
    if s.get("nscParseError"):
        raise harness.HarnessError(f"Could not parse network security config: {s['nscParseError']}")
    actionable = [x for x in f if x.severity not in ("info", "low")]
    return ModuleResult(
        passed=not actionable,
        summary=f"Network security config on {out.serial}: present={s.get('networkSecurityConfigPresent')}, pins={pins}, {len(actionable)} issue(s)",
        findings=f, raw_output=out.raw_output,
    )


registry.register(TestModule(
    id="android.storage.local_data_at_rest",
    layer=Layer.ANDROID,
    title="Local storage exposure check",
    description="Non-root inspection of backup/debuggable/legacy-storage/cleartext flags, data-extraction rules and files readable by other apps.",
    capability=Capability.IMPLEMENTED,
    run=run_local_storage,
))
registry.register(TestModule(
    id="android.network.transport_security_config",
    layer=Layer.ANDROID,
    title="Network security config check",
    description="Parse the app's network security config and manifest for cleartext, user-CA trust, pinning and debug-overrides.",
    capability=Capability.IMPLEMENTED,
    run=run_network_config,
))

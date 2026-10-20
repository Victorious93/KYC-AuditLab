# IdentityShield Android Companion

**Status: builds (`assembleDebug`) in CI, and was run once on an emulator.** The module is a
real Gradle project (AGP 9.3.1, Gradle 9.5.0 wrapper, compileSdk/targetSdk 36,
minSdk 28) and CI compiles it on every push/PR. On 2026-10-15 the backend harness
installed it on an Android 14 / API 34 `google_apis` x86_64 emulator (KVM) and
ran all five Layer 4 modules against `com.android.settings` and
`com.google.android.gm`; results were cross-checked with `aapt2`/`apksigner`
(see `../docs/LAYER4_EMULATOR_RUN.md`). **Not yet run on a physical device,
another API level, or a rooted device.** Do not treat any Android-layer claim
in reports produced by this project as a verified result unless it names a
real device/emulator (`adb devices` output) and attaches command output as
evidence.

## What's here

- `app/src/main/kotlin/com/identityshield/companion/IntegrityChecks.kt` —
  on-device inspection utilities: signing-certificate digest, permission
  audit (requested vs. dangerous vs. granted), and device-trust signals
  (root/emulator indicators of the *test device itself*, used to confirm a
  target app's own detection reacts correctly to a known device state).

## What's intentionally not here

No tooling to defeat SafetyNet/Play Integrity, hide root from a target app,
bypass certificate pinning, or instrument/patch a target APK. Those are
textbook anti-fraud-evasion capabilities; building them in a generic
framework is out of scope regardless of stated authorization (see
`../docs/LIMITATIONS.md`). If a specific authorized engagement needs one of
these (e.g. confirming your own app's pinning actually blocks a
Frida-based MITM you're running against your own test build), that is a
narrower, engagement-specific request to raise explicitly — it is not
something this general framework ships by default.

## To actually build and run this

1. Build: `cd android-companion && ANDROID_HOME=/path/to/sdk ./gradlew assembleDebug`
   (JDK 17+, SDK platform 36). Output: `app/build/outputs/apk/debug/app-debug.apk`.
   Install with `adb install -r app/build/outputs/apk/debug/app-debug.apk`.
   The APK has no launcher activity yet; checks are exposed as a library class
   (`IntegrityChecks`) for an instrumentation/UI Automator harness (step 3).
2. Attach a device or start an emulator; `adb devices` must show it.
3. Run the Layer 4 modules through the backend (`POST /tests/run` with the
   target app's package name, which must be allowlisted and scoped). The
   harness (`backend/app/layers/layer4_android/harness.py`) installs the APK
   with `adb install -r -t` and runs `adb shell am instrument -w -e
   target_package <pkg> com.identityshield.companion/.IntegrityInstrumentation`.
   Optional params: `serial`, `apk_path`, `expected_signing_sha256`.
4. Everything must still pass `orchestrator.scope.assert_in_scope()` before
   touching a device, the same as network-facing modules. Layer 4 targets
   must also be strict package names (`orchestrator/scope_android.py`, #19).

## Exposure checks

`AppExposureChecks.kt` adds `localStorage` and `networkConfig` sections to the instrumentation JSON (non-root: ApplicationInfo flags, the target's binary manifest and network_security_config XML, readability probes). Compiled in CI; run on the API 34 emulator (2026-10-15), where it correctly resolved Gmail's obfuscated NSC (`res/8GD.xml`).

## API access

The companion **does not call the IdentityShield API**: it has no `INTERNET`
permission and no HTTP client. The backend harness drives it over adb and
parses its instrumentation output, so no API key or session token is ever on
the device. Never add a key to `BuildConfig`, resources or assets. If a future
feature needs API access from the device, follow "Future APK clients" in
`../docs/CONTROLLER_INTEGRATION.md` (host passes a short-lived token at
runtime; token kept in memory only).

## Debug signing key (public, debug-only)

`app/debug.keystore` is a **public, debug-only** key committed on purpose so every
builder gets the same debug signing fingerprint (RSA 2048, alias `androiddebugkey`,
store/key password `android`, `CN=Android Debug,O=Android,C=US`, valid 30 years).
Its credentials are the standard, publicly known Android debug values, so it
offers no protection. **Never use it to sign a release build.** No release key is
configured in this repo; release signing must use a separate, private key.

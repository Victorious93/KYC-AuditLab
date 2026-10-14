# IdentityShield Android Companion

**Status: builds (`assembleDebug`), not yet run on a device.** The module is a
real Gradle project (AGP 9.3.1, Gradle 9.5.0 wrapper, compileSdk/targetSdk 36,
minSdk 28) and CI compiles it on every push/PR. No emulator or physical device
has executed it, so no on-device check has produced a result yet. Do not treat any Android-layer claim
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
3. Wire the backend's `layer4_android` registry modules to shell out to
   `adb shell am instrument ...` or a UI Automator test APK that exercises
   `IntegrityChecks`, following the pattern in
   `backend/app/orchestrator/runner.py`.
4. Everything must still pass `orchestrator.scope.assert_in_scope()` before
   touching a device, the same as network-facing modules.

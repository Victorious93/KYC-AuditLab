# IdentityShield Android Companion

**Status: source only, not built or run.** This development environment has
no Android SDK, emulator, or physical device attached, so nothing in this
module has been compiled or executed. Do not treat any Android-layer claim
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

1. Open `android-companion/` in Android Studio, or set up a Gradle wrapper
   + `build.gradle.kts` (not yet created - this is source scaffolding, not
   a complete buildable module yet).
2. Attach a device or start an emulator; `adb devices` must show it.
3. Wire the backend's `layer4_android` registry modules to shell out to
   `adb shell am instrument ...` or a UI Automator test APK that exercises
   `IntegrityChecks`, following the pattern in
   `backend/app/orchestrator/runner.py`.
4. Everything must still pass `orchestrator.scope.assert_in_scope()` before
   touching a device, the same as network-facing modules.

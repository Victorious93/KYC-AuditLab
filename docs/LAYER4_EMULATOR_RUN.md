# Layer 4 – real emulator run (2026-10-15)

Device: Android Emulator AVD, `system-images;android-34;google_apis;x86_64`
(Android 14, API 34, fingerprint `google/sdk_gphone64_x86_64/emu64xa:14/UE1A.230829.050/12077443:userdebug/dev-keys`),
headless (`-no-window -no-audio -no-snapshot`), **KVM accelerated**, swiftshader GPU.
Companion: `./gradlew assembleDebug` (compile/target SDK 36), installed by the harness via `adb install -r -t`.
Run via the API (`POST /tests/run`, dev admin+operator key, targets in
`IDENTITYSHIELD_ALLOWED_TARGETS` and authorized via `POST /scope`).

Ground truth cross-checked with `aapt2 dump xmltree` and `apksigner verify --print-certs`
on the APKs pulled from the device; every value below matched.

| Module | com.android.settings | com.google.android.gm |
|---|---|---|
| apk_signature_check (expected = Settings cert `301aa3cb…66aa`) | passed (match) | failed – critical mismatch (expected: deliberate negative test) |
| dangerous_permission_audit | failed – 135 perms, 18 dangerous | failed – 64 perms, 15 dangerous |
| root_emulator_detection_signal | passed – `known_emulator_fingerprint=true` | same |
| local_data_at_rest | failed – allowBackup (medium), ext-storage perms (low), cleartext (medium) | failed – allowBackup, requestLegacyExternalStorage, ext-storage perms, cleartext |
| transport_security_config | failed – no NSC, cleartext app-wide (high), no pinning (low) | failed – NSC present (obfuscated `res/8GD.xml` resolved correctly), cleartext permitted (high), user CAs trusted (high), no pinning (low) |

No data-dir/shared_prefs/files readability exposure was observed for either target (non-root view).

## Bug found on device
Targeting the companion itself (`com.identityshield.companion`) produced a false
"app data directory is listable by other apps" finding: the companion can always list
its own sandbox. Fixed: self-targets skip the cross-app readability probes and emit an
info finding instead.

## Not verified
Physical devices, other API levels (≤33, 35+), rooted devices, apps with
world-readable files, and NSCs with pins / domain-configs / debug-overrides.

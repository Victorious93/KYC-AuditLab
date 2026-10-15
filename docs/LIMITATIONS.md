# Known Limitations (Phase 1)

This file is the single source of truth for what is and isn't real in this
project right now. Update it in the same commit as any capability change.

## Not implemented at all

- **Layer 4 (Android)** - signature, permission-audit, device-trust,
  local-storage and network-security-config modules are wired to an adb harness (`layer4_android/harness.py`) that
  installs the companion APK and runs `IntegrityInstrumentation` via
  `am instrument`. When adb, an authorized device, or the built APK is
  missing they record **SKIPPED** ("skipped: no device ..."), never PASSED.
  The harness is unit-tested against a mocked adb only; it has **not yet
  been run on a real device/emulator**, so the companion's binary-manifest
  and network_security_config parsing (`AppExposureChecks.kt`) is compiled
  but unverified on hardware.
  Local-storage limits (non-root): app-private files are NOT pulled or
  content-scanned; the check only reports flags (allowBackup, debuggable,
  requestLegacyExternalStorage, usesCleartextTraffic, fullBackupContent /
  dataExtractionRules presence, external-storage permissions) and whether an
  unrelated app can list/read the target's data, shared_prefs, files and
  external Android/data dirs. Backup/extraction rule *contents* are not
  evaluated, only their presence. Network-config limits: only the declared
  XML config is parsed; runtime pinning (OkHttp CertificatePinner, custom
  TrustManagers) and native TLS stacks are invisible, so "no pinning" is a
  low-severity observation, not proof. If manifest parsing fails the
  affected fields are reported as an info finding rather than guessed.
  Existing Postgres databases need
  `ALTER TYPE runstatus ADD VALUE 'skipped';` (fresh DBs via create_all are fine).

## Intentionally not implemented (by design, not by oversight)

- **Counterfeit document generation** (Layer 1) - not built. Layer 1 only
  ever sends structurally-invalid synthetic fixtures (bad length/charset,
  expired dates, wrong type), never anything resembling a forged
  credential.
- **Biometric impersonation/spoofing generators** (Layer 2) - not built.
  The FAR/FRR/EER computation engine is real and tested; it runs against a
  bundled synthetic placeholder score distribution by default, or a real
  dataset supplied via `params["scores_csv_path"]`.
- **Presentation-attack media generation** (Layer 3) - not built. The
  APCER/BPCER/ACER evaluation engine is real and tested; it runs against
  bundled synthetic placeholder metadata (numeric mock confidence values,
  no imagery) unless a real dataset/detector is supplied.
- **Root/Play-Integrity/certificate-pinning bypass tooling** (Layer 4) -
  not built, even once Layer 4 device execution exists. The
  `deviceTrustSignals()` function in the Kotlin companion reads the *test
  device's own* state so you can confirm a target app's detection reacts
  correctly to a known rooted/emulated device - it does not hide that
  state from the target app.

## Tested only against the bundled simulator

Layers 5, 6, 7, and the document-fixture checks in Layer 1 are fully
implemented and have real, passing `pytest` runs (`backend/tests/`) against
`backend/app/simulator`. They have not been run against any other system.
Pointing them at a different target requires that target to implement a
compatible API surface and, regardless, requires an explicit `ScopeEntry`
and allowlisted hostname - see `THREAT_MODEL.md`.

## Known gaps within what IS implemented

- `workflow.session.expiry_mechanism` verifies that an unknown/forged
  session id is rejected, but does **not** exercise real TTL-expiry timing
  (the default policy TTL is 300s, too long for a fast unit test). A
  real expiry-timing test needs a short-TTL integration run, not yet added.
- The rate-limiter is intentionally left keyed per-identity in the
  simulator's default ("vulnerable") mode, and `api.rate_limit.
  identity_rotation_bypass` demonstrates that this is bypassable by
  rotating the client-supplied identity value - this is a deliberate,
  documented fixture flaw for the framework to detect, not a bug in
  IdentityShield itself.
- Dashboard has no auth and talks to the backend directly - fine for local
  use, not meant for a shared/multi-tenant deployment yet.
- `docker-compose.yml` has not been run end-to-end in this environment (no
  Docker daemon available here); it was written and reviewed, not executed.
  `backend/tests/` were run directly against a locally-started process via
  `uvicorn`/pytest instead, and that run is the one covered by
  `docs/TEST_RESULTS.md`.

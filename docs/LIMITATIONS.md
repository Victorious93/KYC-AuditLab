# Known Limitations

This file is the single source of truth for what is and isn't real in this
project right now. Update it in the same commit as any capability change.

_Last refreshed 2026-10-17 against `main` @ `bbb5129` plus the open fix PRs
#18-#22 (marked below where a statement depends on one of them)._

## Implemented, with significant limits

- **Layer 4 (Android)** - all five modules (signature, permission-audit,
  device-trust, local-storage, network-security-config) are implemented and
  wired to an adb harness (`layer4_android/harness.py`) that installs the
  companion APK and runs `IntegrityInstrumentation` via `am instrument`.
  When adb, an authorized device, or the built APK is missing they record
  **SKIPPED** ("skipped: no device ..."), never PASSED. The suite tests the
  harness against a mocked adb; CI builds the companion (`assembleDebug`)
  but runs no device. All five modules **have been run once on a real
  Android 14 / API 34 `google_apis` x86_64 emulator** (KVM, 2026-10-15)
  against `com.android.settings` and `com.google.android.gm`, cross-checked
  with `aapt2`/`apksigner` - see `LAYER4_EMULATOR_RUN.md`. That run has not
  been repeated since. **Not run on:** physical devices, other API levels
  (<=33, 35+), rooted devices. Layer 4 targets must be strict Android
  package names (`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`);
  anything else is `blocked_scope` before adb is touched, and remote-shell
  arguments are `shlex`-quoted (#19).
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
  Existing Postgres databases created before `SKIPPED` was added need
  `ALTER TYPE runstatus ADD VALUE IF NOT EXISTS 'SKIPPED';` (upper-case:
  SQLAlchemy stores enum member *names*, so the labels are `'PENDING'`, ...,
  `'SKIPPED'`). The backend now runs this automatically at startup (see
  "Postgres enum migration" in the README); fresh DBs via create_all are fine.
  An earlier version of this note said `ADD VALUE 'skipped'` (lower-case):
  that label is never written by the app, so it does not fix the error. A stray
  `'skipped'` label is harmless but cannot be dropped without recreating the type.

## Intentionally not implemented (by design, not by oversight)

- **Counterfeit document generation** (Layer 1) - not built. Layer 1 only
  ever sends structurally-invalid synthetic fixtures (bad length/charset,
  expired dates, wrong type), never anything resembling a forged
  credential.
- **Biometric impersonation/spoofing generators** (Layer 2) - not built.
  The FAR/FRR/EER engine is real and tested. By default it pushes each
  score in the SYNTHETIC fixture `layer2_match_scores.csv` through the
  simulator's full flow (/face -> /decision) and computes FAR/FRR from the
  simulator's real decisions (FAR=0.0300, FRR=0.2000, offline EER~0.09 at
  0.73). The scores themselves are synthetic. No real matcher or face data
  is involved, so these numbers describe the simulator's 0.80 threshold
  policy, not any real face matcher. See docs/DATASETS.md.
- **Presentation-attack media generation** (Layer 3) - not built. The
  APCER/BPCER/ACER engine is real and tested. By default it replays the
  SYNTHETIC challenge-response fixture `layer3_pad_cases.csv` against the
  simulator's /liveness endpoint. Vulnerable mode: APCER=0.3333,
  BPCER=0.0000, ACER=0.1667, because all 20 `client_asserts_live` attacks
  get through. Hardened mode: APCER=0.0000, BPCER=0.0000, ACER=0.0000.
  With #21 the simulator issues, stores and burns a single-use challenge
  per session, and the attack cases also send a self-consistent forged
  `expected_challenge`, so the hardened 0.0 now covers that forgery.
  Without #21 the hardened check compared two client-supplied values and
  its 0.0 only showed the fixture's attackers played fair. This evaluates
  the liveness *protocol*, not an image-based PAD model. No attack media
  or public PAD dataset is used.
- **Root/Play-Integrity/certificate-pinning bypass tooling** (Layer 4) -
  not built, even though Layer 4 device execution now exists. The
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
- The simulator's rate-limiter is keyed per client-supplied identity in
  **both** modes (vulnerable and hardened; there is no hardened per-client
  or global limiter yet), so `api.rate_limit.identity_rotation_bypass`
  fails in both: rotating `identity_key` on every request bypasses it.
  This is a deliberate, documented fixture flaw for the framework to
  detect, not a bug in
  IdentityShield itself.
- The dashboard no longer has an API key in its bundle: the operator enters
  a key at runtime, it is exchanged at `POST /auth/session` for a
  short-lived signed token, and only the token is kept (tab
  `sessionStorage`). Remaining limits: session tokens are stateless, so
  there is no server-side sign-out or per-token revocation (a leaked token
  is valid until it expires, default 1 h, or until its API key is
  rotated/removed); there is no rate limit on `/auth/session`; the token in
  `sessionStorage` is readable by any script running on the dashboard
  origin (XSS would expose it, though not the long-lived key); there are no
  narrower dashboard-specific roles. With `IDENTITYSHIELD_SESSION_SECRET`
  unset, a random per-process secret is used, so tokens do not work across
  several uvicorn workers or restarts. Mitigations still in place: compose
  binds 8000 and 5173 to `127.0.0.1`, and the CORS allowlist
  (`IDENTITYSHIELD_CORS_ORIGINS`, never `*`) admits only the dashboard
  origin. The Droidcommand-AI controller and Android APKs do not use
  session tokens yet.
- `docker-compose.yml` has not been run end-to-end in this environment (no
  Docker daemon available here); it was written and reviewed, not executed.
  `backend/tests/` were run directly against a locally-started process via
  `uvicorn`/pytest instead, and that run is the one covered by
  `docs/TEST_RESULTS.md`.
- **Postgres is not exercised by the test suite or CI** - every test uses
  SQLite, which stores enums as VARCHAR and hides enum-label problems.
  Schema comes from `create_all()`; there is no Alembic/migration tool.
- **Operator-supplied server paths** (`scores_csv_path`, `cases_csv_path`,
  `apk_path`) are opened/installed as given; `params` is an untyped dict
  with no per-module schema or data-directory confinement.
- **Scope entries are host-only** (any port on an authorized host) and have
  no expiry; `revoked` is a string flag.
- **Simulator vulnerable mode is on by default** and `docker-compose.yml`
  does not set `IDENTITYSHIELD_SIM_VULNERABLE` or `IDENTITYSHIELD_ENV`
  (which defaults to `local`).
- **Encryption at rest is documented only** (`EVIDENCE_POLICY.md` section 3);
  nothing in code or compose enforces it. The `0600` evidence-file writer
  exists but no module calls it; evidence lives in the database.
- **No dashboard tests** and no dashboard build job in CI.
- `datetime.utcnow()` and Pydantic class-based `Config` produce ~4,000
  deprecation warnings per test run.

# Test Results

_Last refreshed 2026-10-17. Earlier results (Phase 1, 2026-10-09: 21 tests) are in git history._

How to run:

```
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q                                   # default: simulator vulnerable mode
IDENTITYSHIELD_SIM_VULNERABLE=false python -m pytest -q   # hardened mode
```

All tests use SQLite. The suite starts its own local uvicorn instance and registers throwaway hashed API keys. Layer 4 tests use a mocked adb; no device is needed.

## Dashboard: no baked API key (`fix/dashboard-no-baked-key`, 2026-10-17)

Branch off `main` @ `1502028`, local Python 3.13.5 / Node 20.19.2:

| Check | Result |
|---|---|
| `pytest -q` (vulnerable mode) | **428 passed** (371 before + 57 in new `test_auth_session.py`) |
| `IDENTITYSHIELD_SIM_VULNERABLE=false pytest -q` (hardened) | **428 passed** |
| `npm ci && npm run build` | builds (tsc + vite) |
| `npm run check:bundle` on `dist/` | OK, no key-like content |
| `VITE_API_KEY=... vite build` | refused by `vite.config.ts` (as intended) |
| Scanner self-test | detects planted `X-API-Key` value, `VITE_API_KEY`, `identity:roles:key` entry, 64-hex digest, session token, `BUNDLE_CANARIES` value |
| Same canary check on `main`'s dashboard built with `VITE_API_KEY` set | canary found in bundle (the original problem) |
| Headless Chrome against a live local backend | sign-in prompt; wrong key rejected; sign-in with a dev key; 23 modules listed; scope authorized and one module run; `sessionStorage` holds only the token (never the key), `localStorage` empty; session survives reload; tampered token → 401 → back to sign-in; 60 s TTL token expired → 401 server-side and dashboard re-prompts; sign-out clears storage; `X-API-Key` sent only on `POST /auth/session` |

## `main` @ `bbb5129` (merge of #17)

| Run | Result |
|---|---|
| Local, Python 3.13.5, vulnerable mode (2026-10-17) | **146 passed**, 0 failed |
| Local, Python 3.13.5, hardened mode (2026-10-17 audit) | 145 passed, **1 failed** (`test_liveness_pad_flags_client_assertion_in_vulnerable_mode` was not mode-aware; fixed in #21) |
| CI `backend-tests`, Python 3.12, run `38663042944` | **146 passed**, 4177 warnings in 5.48s; all 5 CI jobs succeeded |

| Test file | Tests |
|---|---|
| `test_api_auth.py` | 43 |
| `test_layer4_storage_network.py` | 22 |
| `test_layer4_android.py` | 20 |
| `test_scope_hostname.py` | 19 |
| `test_evidence_policy.py` | 18 |
| `test_layer2_biometric_layer3_liveness.py` | 6 |
| `test_layer5_api.py` | 6 |
| `test_layer6_workflow.py` | 6 |
| `test_layer1_document.py` | 2 |
| `test_layer7_fraud.py` | 2 |
| `test_scope_enforcement.py` | 2 |
| **Total** | **146** |

## Open fix PRs (2026-10-17)

Each PR's own branch, run locally (Python 3.13.5) and in CI (Python 3.12):

| PR | Branch | Local pytest | CI `backend-tests` | CI jobs (backend-tests, pip-audit, npm-audit, gitleaks, android-build) |
|---|---|---|---|---|
| #18 | `fix/scope-url-bypass` | 241 passed | 241 passed | all 5 success (run `39051785581`) |
| #19 | `fix/layer4-adb-injection` | 233 passed | 233 passed | all 5 success (run `39052034221`) |
| #20 | `docs/postgres-migration` | 149 passed | 149 passed | all 5 success (run `39052182263`) |
| #21 | `fix/sim-liveness-hardened` | 169 passed (vulnerable), 169 passed (hardened) | 169 passed | all 5 success (run `39052438047`) |
| #22 | `fix/compose-bind-cors` | 163 passed | 163 passed | all 5 success (run `39052579523`) |

**#18–#22 merged together.** This was a local octopus merge onto `main` and was not pushed. It merges with no conflicts and gives **371 passed** in vulnerable mode and **371 passed** in hardened mode.

| New or changed test file (combined tree) | Tests | PR |
|---|---|---|
| `test_scope_url_bypass.py` | 92 | #18 |
| `test_scope_hostname.py` | 22 (was 19) | #18 |
| `test_layer4_adb_injection.py` | 87 | #19 |
| `test_db_enum_migration.py` | 3 | #20 |
| `test_simulator_liveness_challenge.py` | 22 | #21 |
| `test_layer2_biometric_layer3_liveness.py` | 7 (was 6) | #21 |
| `test_cors.py` | 17 | #22 |

## Module results (all 23 modules via the runner, against the bundled simulator)

Combined tree (#18–#22). HTTP modules target the test server at `127.0.0.1:<port>`. Layer 4 targets `com.android.settings` (allowlisted and scoped), with no adb on `PATH`.

| Layer | Module | Vulnerable mode | Hardened mode |
|---|---|---|---|
| L1 | `document.validation.malformed_fixtures_rejected` | passed | passed |
| L1 | `document.validation.error_no_leak` | passed | passed |
| L2 | `biometric.benchmark.far_frr` | passed (info): FAR 0.0300, FRR 0.2000, offline EER 0.0900 at 0.73 | same |
| L3 | `liveness.pad.apcer_bpcer_evaluation` | **failed (high)**: APCER 0.3333, BPCER 0.0000, ACER 0.1667; `client_asserts_live` 20/20 accepted | passed: APCER 0.0000, BPCER 0.0000, ACER 0.0000 |
| L4 | `android.integrity.apk_signature_check` | skipped (no `expected_signing_sha256`) | skipped |
| L4 | other 4 Android modules | skipped: no device (adb not found on PATH) | skipped |
| L5 | `api.auth.*`, `api.authz.*`, `api.input_validation.*`, `api.rate_limit.session_creation` (5) | passed | passed |
| L5 | `api.rate_limit.identity_rotation_bypass` | **failed (medium)** | **failed (medium)**: the limiter is per-identity in both modes |
| L6 | `workflow.state.*`, `workflow.session.expiry_mechanism`, `workflow.race.concurrent_submission` (4) | passed | passed |
| L6 | `workflow.decision.client_cannot_override` | **failed (critical)** | passed |
| L6 | `workflow.liveness.client_assertion_ignored` | **failed (critical)** | passed |
| L7 | `fraud.velocity.identity_reuse_flagged`, `fraud.monitoring.audit_trail_completeness` | passed | passed |
| **Totals** | 23 | **14 passed, 4 failed, 5 skipped** | **17 passed, 1 failed, 5 skipped** |

Vulnerable-mode failures are the intended detections of the simulator's planted flaws. With #19, a Layer 4 module run against a `host:port` target (rather than a package name) is `blocked_scope`.

Layer 4 on a real emulator (API 34, 2026-10-15) is recorded separately in `LAYER4_EMULATOR_RUN.md`. It was not re-run for this refresh.

## Other verification for the fix PRs

- **#18.** On unmodified `main`, the scope-bypass PoC (`127.0.0.2:<port>\@localhost`, with `localhost` scoped) reached a canary listener on `127.0.0.2`, which received `POST /%5C@localhost/simulator/session`. With #18 the run is `blocked_scope` and the canary gets no connection.
- **#20.** On a scratch PostgreSQL 17.11 cluster (unix socket only, deleted afterwards) with a pre-`SKIPPED` schema, inserting a `SKIPPED` run failed with `invalid input value for enum runstatus: "SKIPPED"` before `init_db()` and succeeded after it.
- **#21.** On unmodified `main`, a self-consistent forgery (`expected_challenge == challenge_response`) returned `passed: true` in both modes. With #21 it is rejected in both.

## Not run / not executed

- `docker compose up`: there is no Docker daemon on the box. The compose port mappings in #22 were checked only by parsing the YAML.
- The dashboard has not been run in a real browser against a live backend. CORS (#22) is verified at the HTTP level only.
- Layer 4 on a physical device, another API level, or a rooted device. Device-side execution of the adb injection (F2) was not attempted.
- The suite has never been run against Postgres in CI.
- Layer 2/3 have only been run on the bundled synthetic fixtures, never on real datasets.

# IdentityShield — Architecture

## Components

```
backend/app/
  main.py                 FastAPI app (lifespan: init_db + load modules); mounts the simulator +
                           orchestrator routers; CORS allowlist for the dashboard (#22)
  auth.py                  X-API-Key auth: SHA-256-hashed keys, admin / operator roles (non-hierarchical);
                           short-lived HMAC session tokens (Authorization: Bearer)
  config.py                Settings (DB URL, allowlist, local-only flag, evidence dir, CORS origins)
  db.py / models.py        SQLAlchemy models: TestRun, Finding, ScopeEntry; init_db() = create_all()
                           + PostgreSQL enum-label helper (#20)
  evidence/                redact.py (PII redaction before persist), store.py (0600 writer),
                           retention.py (CLI: delete runs/evidence older than N days)
  orchestrator/
    registry.py             TestModule/Capability/Layer definitions + the module registry;
                            TestContext carries the scoped (host, port) and builds request URLs (#18)
    runner.py                execute_module(): stub check -> scope check -> [Layer 4 package gate]
                             -> run -> redact -> persist TestRun/Finding rows
    scope.py                  parse_target() (one strict canonical parser, #18) + assert_in_scope():
                              hard allowlist + explicit ScopeEntry check
    scope_android.py          validate_android_package() for Layer 4 targets (#19)
  simulator/
    app.py                    The local KYC simulator (FastAPI router, mounted at /simulator);
                              server-issued single-use liveness challenge (#21)
    store.py                   In-memory session/audit-event store, reset between runs
    policies.py                 Configurable verification policy (thresholds, TTLs, limits)
  layers/
    layer1_document .. layer7_fraud   One package per attack layer, each registering
                                        TestModule entries against the registry on import
    layer4_android/harness.py          adb discovery, device selection, APK install,
                                        `am instrument`, JSON parsing; SKIPPED when unavailable
    fixtures/                          SYNTHETIC L2/L3 CSV fixtures + simulator flow driver
  routers/
    tests.py    GET /tests/modules, POST /tests/run, POST /tests/run-layer   (operator)
    results.py   GET /results/runs, GET /results/runs/{id}                   (operator)
    scope_admin.py POST/GET/DELETE /scope                                    (admin)
dashboard/        React + TypeScript SPA: lists modules, triggers runs, shows findings
android-companion/  Kotlin companion APK + IntegrityInstrumentation (built in CI; run on an
                    API 34 emulator 2026-10-15 - see LAYER4_EMULATOR_RUN.md)
docs/              This directory
evidence/          Raw output / artifacts written by test modules (gitignored)
```

## Request flow for "run a test"

1. Dashboard (or any HTTP client) calls `POST /tests/run {module_id, target}`.
2. `runner.execute_module` looks up the `TestModule` in the registry.
3. If the module has no `run()` callable (a documented stub), it records an
   `error` status with the limitation text and returns immediately -
   **nothing is ever claimed to have executed if it didn't.**
4. Otherwise, `scope.assert_in_scope(db, target)` runs:
   - Parse `target` with the strict canonical parser `parse_target()`
     (`[http(s)://]host[:port][/]`; host = DNS name, dotted-quad or
     `[IPv6]`). Userinfo/`@`, backslashes, whitespace/control/non-ASCII
     characters, paths, queries, fragments and ambiguous numeric hosts are
     rejected (#18).
   - Reject if `target`'s hostname is not in the server-side
     `IDENTITYSHIELD_ALLOWED_TARGETS` env var (default: localhost only).
   - Reject if there is no active, non-revoked `ScopeEntry` row for that
     host in the database.
   - All checks must pass; any can block the run (`blocked_scope`).
   - For Layer 4 modules, the target must additionally be a strict Android
     package name (`scope_android.validate_android_package`, #19).
5. The module's `run(ctx)` executes, returns a `ModuleResult`
   (passed/failed/skipped, summary, structured `Finding`s). HTTP modules
   build every request URL with `ctx.url(path)` from the parsed, validated
   host/port, never from the raw target string; the built URL is re-parsed
   with urllib3 as a backstop (#18). The Layer 4 harness passes only the
   validated package name and `shlex`-quotes every remote-shell argument
   (#19).
6. The runner redacts summary/raw output/finding descriptions, then
   persists a `TestRun` row and one `Finding` row per finding. A module
   whose prerequisite is missing (e.g. no adb/device) is recorded as
   `skipped`, never `passed`.
7. The dashboard/API surfaces the result; `GET /results/runs/{id}` gives
   the full finding list with severity/CWE/remediation/risk_score.

## Why one process serves both the simulator and the orchestrator

The simulator is not a "real" third system to be attacked opportunistically
- it is a fixture the orchestrator owns and resets between runs
(`POST /simulator/admin/reset`). Running them in one FastAPI app keeps that
relationship explicit instead of implying the orchestrator is generic
infrastructure for probing arbitrary external targets.

## Extending with new modules

Add a new file under the relevant `layers/<name>/` package, write a
function `def run(ctx: TestContext) -> ModuleResult`, and call
`registry.register(TestModule(id=..., layer=..., run=run, capability=Capability.IMPLEMENTED, ...))`
at import time. `load_all_modules()` in `registry.py` imports every layer
package once at app startup, so a new module file just needs importing
from its layer's `__init__.py`.

A module that cannot be safely or completely implemented yet must still be
registered, with `capability=Capability.STUB_NOT_IMPLEMENTED` (or
`EVALUATION_ONLY`) and a non-empty `limitation` string - enforced by
`TestModule.__post_init__`. This is how the registry stays an honest,
complete map of all seven layers even where execution isn't there yet.

## Simulator liveness protocol

`POST /simulator/liveness/challenge` issues a per-session nonce, stores it
server-side with a TTL (`liveness_challenge_ttl_seconds`, default 120s) and
returns it. `POST /simulator/liveness` grades `challenge_response` only
against the stored value and clears it on every attempt, so each challenge
is single-use. A client-supplied `expected_challenge` is accepted for
backward compatibility and ignored. Vulnerable mode keeps exactly one planted
liveness flaw: it honors `client_asserts_live=true` (#21).

## Network exposure

`docker-compose.yml` publishes the backend (8000) and dashboard (5173) on
`127.0.0.1` only. The backend allows cross-origin calls only from
`IDENTITYSHIELD_CORS_ORIGINS` (default `http://localhost:5173`,
`http://127.0.0.1:5173`; `*` refused).

## Dashboard authentication

The dashboard bundle contains no credentials. The operator types an API key
at runtime; the dashboard sends it once to `POST /auth/session` (in
`X-API-Key`) and gets back a short-lived token
`iss1.<base64url payload>.<HMAC-SHA256>` with payload `{sub, kfp, iat, exp}`.
`kfp` is a keyed fingerprint of the issuing key, so on every request the
token is re-bound to a key that is still configured; rotating or removing
the key revokes its tokens, and roles come from the current key config.
`/auth/session` accepts only an API key, never a token. The token is sent as
`Authorization: Bearer` and kept in the tab's `sessionStorage`; any 401
returns the dashboard to its sign-in screen. `vite.config.ts` refuses
secret-looking `VITE_*` variables, and CI's `dashboard-build` job scans the
built bundle for key-like content (`scripts/check-bundle-secrets.mjs`).

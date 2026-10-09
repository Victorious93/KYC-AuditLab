# IdentityShield — Architecture

## Components

```
backend/app/
  main.py                 FastAPI app: mounts the simulator + orchestrator routers
  config.py                Settings (DB URL, allowlist, local-only flag, evidence dir)
  db.py / models.py        SQLAlchemy models: TestRun, Finding, ScopeEntry
  orchestrator/
    registry.py             TestModule/Capability/Layer definitions + the module registry
    runner.py                execute_module(): scope check -> run -> persist Finding rows
    scope.py                  assert_in_scope(): hard allowlist + explicit ScopeEntry check
  simulator/
    app.py                    The local KYC simulator (FastAPI router, mounted at /simulator)
    store.py                   In-memory session/audit-event store, reset between runs
    policies.py                 Configurable verification policy (thresholds, TTLs, limits)
  layers/
    layer1_document .. layer7_fraud   One package per attack layer, each registering
                                        TestModule entries against the registry on import
  routers/
    tests.py    GET /tests/modules, POST /tests/run, POST /tests/run-layer
    results.py   GET /results/runs, GET /results/runs/{id}
    scope_admin.py POST/GET/DELETE /scope
dashboard/        React + TypeScript SPA: lists modules, triggers runs, shows findings
android-companion/  Kotlin source for on-device checks (NOT built/run - see LIMITATIONS.md)
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
   - Reject if `target`'s hostname is not in the server-side
     `IDENTITYSHIELD_ALLOWED_TARGETS` env var (default: localhost only).
   - Reject if there is no active, non-revoked `ScopeEntry` row for that
     host in the database.
   - Both checks must pass; either can block the run (`blocked_scope`).
5. The module's `run(ctx)` executes, returns a `ModuleResult`
   (passed/failed, summary, structured `Finding`s).
6. The runner persists a `TestRun` row and one `Finding` row per finding.
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

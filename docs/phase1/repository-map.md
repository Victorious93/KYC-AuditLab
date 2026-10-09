# Repository Map (M0)

Generated against commit `0d54a9a` on branch `ccr-31178ee0-1mdrhl`, via the
discovery commands specified in the Phase 1 delivery model. Raw command
output is below each section rather than paraphrased, per M0 Task 6.

**Status note, read first:** this repository map is produced retroactively.
The code it describes (backend, simulator, 7 layer packages, dashboard,
Kotlin stub, docs) was built in a prior session, before this M0–M6
governance process existed. Nothing below should be read as "M1–M6 were
followed" - they were not. This is an honest discovery pass over what
exists, which is the correct M0 input regardless of how it got there.

## `git status --short` / `git branch --show-current`

```
(clean working tree)
ccr-31178ee0-1mdrhl
```

## Top-level inventory

```
.gitignore
README.md
android-companion/          Kotlin source, NOT built or run (see docs/LIMITATIONS.md)
  README.md
  app/src/main/kotlin/com/identityshield/companion/IntegrityChecks.kt
backend/                    FastAPI orchestrator + the KYC simulator
  Dockerfile
  requirements.txt            (no coverage/lint/security-scan packages)
  requirements-postgres.txt   (psycopg2-binary, split out - see tooling-baseline.md)
  app/
    __init__.py, config.py, db.py, main.py, models.py
    orchestrator/  registry.py, runner.py, scope.py
    simulator/     app.py, store.py, policies.py
    layers/        layer1_document .. layer7_fraud (__init__.py each)
    routers/       tests.py, results.py, scope_admin.py
  tests/           conftest.py, helpers.py, test_layer1/2+3/5/6/7, test_scope_enforcement.py
dashboard/                  React + TypeScript SPA (Vite)
  Dockerfile, package.json, package-lock.json, tsconfig.json, vite.config.ts, index.html
  src/  App.tsx, api.ts, main.tsx
docker-compose.yml          Postgres + backend + dashboard (not run - no Docker daemon here)
docs/
  ARCHITECTURE.md, THREAT_MODEL.md, LIMITATIONS.md, ROADMAP.md, TEST_RESULTS.md
  phase1/   (this directory - created now, for the M0-M6 process)
evidence/.gitkeep           Empty - no formal evidence package exists yet (see risk register)
```

No `.github/workflows/` directory exists. No CI is configured anywhere in
the repository (confirmed by `find . -path '*/.github/workflows/*'`
returning nothing).

## Existing seven-layer implementation locations

| Layer | Location | Status (as implemented, not yet M1-M6 validated) |
|---|---|---|
| 1 — Document | `backend/app/layers/layer1_document/__init__.py` | Implemented; 2 modules; tests in `test_layer1_document.py` |
| 2 — Biometric | `backend/app/layers/layer2_biometric/__init__.py` | Evaluation-only (synthetic placeholder data); 1 module |
| 3 — Liveness | `backend/app/layers/layer3_liveness/__init__.py` | Evaluation-only (synthetic placeholder data); 1 module |
| 4 — Android | `backend/app/layers/layer4_android/__init__.py` + `android-companion/` | Stub only; 5 registered modules, all `STUB_NOT_IMPLEMENTED`; Kotlin source unbuilt |
| 5 — API | `backend/app/layers/layer5_api/__init__.py` | Implemented; 6 modules; tests in `test_layer5_api.py` |
| 6 — Workflow | `backend/app/layers/layer6_workflow/__init__.py` | Implemented; 6 modules; tests in `test_layer6_workflow.py` |
| 7 — Fraud | `backend/app/layers/layer7_fraud/__init__.py` | Implemented; 2 modules; tests in `test_layer7_fraud.py` |

Cross-cutting: `orchestrator/scope.py` (allowlist + ScopeEntry enforcement),
`orchestrator/runner.py` (execution + capability gating),
`orchestrator/registry.py` (module/capability model).

## Ambiguous or missing ownership, coverage, and release checks (M0 Task 5)

- **No human ownership roles exist yet.** The milestone model requires a
  Technical lead, Security lead, QA lead, Platform engineer, DevOps/CI
  owner, Reporting owner, and 7 layer owners. None are assigned in this
  repository or in this conversation - see `ownership-map.md` for the gap
  and a proposed single-operator interim mapping.
- **No CI** exists to enforce anything in M5.
- **No coverage tool** is wired up (`pytest` runs with no `--cov`).
- **No linter, type checker, or security scanner** is configured for
  either the Python backend or the TypeScript dashboard (tsc is used for
  type-checking only as part of the Vite build, not as a standalone gate).
- **No formal evidence package** exists under `evidence/` (empty).
- **No traceability or risk register** existed before this M0 pass; both
  are seeded for the first time in this delivery (see
  `traceability.csv`, `risk-register.csv`).

# Tooling Baseline (M0)

Every row below was verified by actually running the command in this
environment, not inferred from file contents. "Unknown" is never used
silently - a missing tool is marked **Missing**, with the gap it creates.

## Language / package manager / build system

| Area | Finding | Verified by |
|---|---|---|
| Backend language | Python 3.13 (`.venv` built against it) | `python3 -m venv .venv` succeeded |
| Backend package manager | pip, `requirements.txt` / `requirements-postgres.txt` | `pip install -r requirements.txt` succeeded |
| Backend build system | None (pure Python, no packaging/build step) | n/a |
| Dashboard language | TypeScript (React 18) | `dashboard/tsconfig.json`, `.tsx` sources |
| Dashboard package manager | npm, `package.json` + `package-lock.json` | `npm install` succeeded (67 packages) |
| Dashboard build system | Vite 5.4.6 | `npm run build` succeeded: `tsc -b && vite build` |
| Android | Gradle (implied by `android-companion/`) | **Not verified** - no Gradle wrapper/build file exists yet; `android-companion/README.md` says so explicitly |

## Test runners

| Tool | Status | Command that was actually run | Result |
|---|---|---|---|
| pytest 8.3.3 | Present, configured, run | `python -m pytest tests/ -v` (from `backend/`) | 21 passed, 0 failed (see `docs/TEST_RESULTS.md`) |
| A dashboard test runner (Jest/Vitest) | **Missing** | n/a | `dashboard/package.json` has no `test` script and no test runner dependency. Gap: zero unit test coverage for `App.tsx`/`api.ts`. |
| Android instrumentation / UI Automator | **Missing / unavailable** | n/a | No device, emulator, or Gradle build exists. |

## Linters / formatters / type checkers

| Tool | Status |
|---|---|
| ruff / flake8 (Python) | **Missing.** Not in `requirements.txt`, no config file. |
| black / a Python formatter | **Missing.** |
| mypy (Python types) | **Missing.** The codebase uses type hints but nothing checks them. |
| eslint (TypeScript) | **Missing.** No `.eslintrc*`. |
| tsc (TypeScript type check) | **Present**, but only as part of `npm run build` (`tsc -b && vite build`), not as a standalone gate a CI job could run independently for a fast fail. |

## Security scanners

| Tool | Status |
|---|---|
| bandit (Python SAST) | **Missing.** |
| semgrep | **Missing.** |
| trivy / dependency scanning | **Missing.** `pip-audit`/`npm audit` were not run as part of this delivery; `npm install` reported "2 vulnerabilities (1 moderate, 1 high)" in transitive dashboard dependencies that have **not been triaged** (see risk register, `SEC-1`). |

## Report generators

| Tool | Status |
|---|---|
| pytest's own text/JUnit output | Present (default pytest reporter); JUnit XML not currently emitted (`--junitxml` not passed anywhere). |
| Coverage report | **Missing** - `pytest-cov`/`coverage.py` not installed. |
| HTML/PDF report generator for findings | **Missing.** `GET /results/runs/{id}` returns JSON only; no template renderer exists (tracked in `docs/ROADMAP.md` item 4). |

## CI

| Area | Status |
|---|---|
| `.github/workflows/` | **Does not exist.** Confirmed via `find . -path '*/.github/workflows/*' -type f`. |
| Any other CI config (`.gitlab-ci.yml`, `Jenkinsfile`, etc.) | **Does not exist** - not found in the top-level or `-maxdepth 3` scan. |

## Docker / local automation

| Area | Status |
|---|---|
| `docker` CLI | Present (`/usr/bin/docker`). |
| Docker daemon | **Unavailable** in this environment (`docker ps` fails: no `/var/run/docker.sock`). `docker-compose.yml` has been written and reviewed but not executed end-to-end anywhere. |
| `Makefile` / `Taskfile` | **Missing.** No single `make test` / `task test` entry point exists; commands are documented in `README.md` prose only. |

## Net effect on the Phase 1 plan

M5 ("CI/CD and local automation enforcement") and most of the security-test
row of the M4 test matrix are **not started** - this is the single biggest
gap between what exists today and what the uploaded Phase 1 delivery model
requires for a release decision. See `risk-register.csv` rows `DEP-1` and
`SEC-1`, and `traceability.csv` for the corresponding `blocked`/`not-run`
requirement rows.

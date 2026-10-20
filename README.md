<!-- victorious-fleet-readme-refresh:start -->
<p align="center">
  <img src="assets/logo.png" alt="KYC-AuditLab / IdentityShield logo" width="200">
</p>

# KYC-AuditLab / IdentityShield

Local KYC / identity audit lab companion (policy hold on remote surfaces).

**Package id:** `com.identityshield.companion`

> **Package note:** From `android-companion/app/build.gradle.kts`.

**Status:** blocked (policy hold) *(from [fleet-manifest ROADMAP](https://github.com/Victorious93/fleet-manifest/blob/main/ROADMAP.md))*

## Install / build

Android companion under `android-companion/`. Typical: `cd android-companion && ./gradlew :app:assembleDebug` if wrapper present — verify in-repo.

_Steps above are taken from this repo’s build files / existing docs; anything not exercised in this refresh is unlabeled as verified on a device._

## Victorious fleet

- Monorepo: [https://github.com/Victorious93/victorious-fleet](https://github.com/Victorious93/victorious-fleet)
- Fleet site: [https://victorious-framework.pages.dev](https://victorious-framework.pages.dev)

<!-- victorious-fleet-readme-refresh:end -->

A **local-first** security research framework for evaluating a KYC / identity-verification system’s resistance across seven layers: document validation, facial biometrics, liveness, Android client security, API/network, verification workflow/session, and fraud monitoring.

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688)](https://fastapi.tiangolo.com/)
![Status: Phase 1](https://img.shields.io/badge/status-Phase%201-orange)

> **Repo slug:** GitHub repository name is `KYC-AuditLab`; the product name in-tree is **IdentityShield**.

**Out of the box, this targets only its own bundled simulator.** No third-party production identity-verification system is in scope by default. Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) before trusting any claim about what the framework “found”.

## Quick start (no Docker)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Authorize the simulator as a test target (**default-deny** — nothing runs without this):

```bash
curl -X POST localhost:8000/scope \
  -H 'Content-Type: application/json' \
  -d '{"target": "localhost", "authorized_by": "you"}'
```

```bash
curl localhost:8000/tests/modules
curl -X POST localhost:8000/tests/run \
  -H 'Content-Type: application/json' \
  -d '{"module_id": "workflow.liveness.client_assertion_ignored", "target": "localhost:8000"}'
curl localhost:8000/results/runs
```

## Tests

```bash
cd backend
pip install -r requirements.txt
python -m pytest tests/ -v
```

Documented as **21/21 pass** in [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) (against a live local instance).

## Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Set `VITE_API_BASE_URL` if the backend is not on `localhost:8000`.

## Docker Compose (Postgres)

```bash
docker compose up --build
```

Written and reviewed; **not run end-to-end** in the environment that wrote these docs (no Docker daemon). See `docs/LIMITATIONS.md`.

## Screenshots

| Dashboard | Module list | Run results | Scope authorization |
|---|---|---|---|
| *TODO* | *TODO* | *TODO* | *TODO* |

## Safety model (brief)

- `IDENTITYSHIELD_ALLOWED_TARGETS` (server env, not settable via API) caps hostnames.
- Every module run needs an explicit, non-revoked `ScopeEntry` (`POST /scope`) — default-deny.
- Unimplemented modules (e.g. Layer 4 Android execution) report explicit errors; they never silently no-op as success.

Does **not** implement counterfeit-document generators, biometric spoofing media, presentation-attack media, or root/Play-Integrity bypass tooling (by design). See LIMITATIONS.md.

## Project structure

```text
backend/             FastAPI orchestrator + KYC simulator + layer packages + pytest
android-companion/   Kotlin source for on-device checks (not built/run yet)
dashboard/           React + TypeScript SPA
docs/                Architecture, threat model, limitations, roadmap, test results
evidence/            Raw output dir (contents gitignored)
docker-compose.yml   Postgres + backend + dashboard
```

## Contributing

Update `docs/LIMITATIONS.md` in the same change as any capability claim. Keep scope/authorization fail-closed. Do not add generators for counterfeit identity documents or biometric attack media.

## License

**No `LICENSE` file is present.** Add an SPDX license before treating the project as redistributable open source.

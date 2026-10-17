<p align="center">
  <img src="docs/logo-512.png" alt="IdentityShield logo" width="200">
</p>

# IdentityShield

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

### API authentication (required)

The control-plane API is protected by API keys sent in the `X-API-Key` header. Two roles, **not hierarchical**:

| Role | Routes |
|---|---|
| `admin` | `/scope` (add / list / revoke), `/simulator/admin/*` |
| `operator` | `/tests/*` (list modules, run), `/results/*` |

The deliberately vulnerable simulator KYC flow (`/simulator/session`, `/document`, `/face`, `/liveness`, `/decision`, `/audit/*`) and `/health` stay unauthenticated — they are lab targets.

- Missing/wrong key → **401**; valid key without the required role → **403**.
- **Fail closed:** if no valid keys are configured, every protected route returns **503**.
- Keys are configured only via env, stored as SHA-256 hashes, compared in constant time (`hmac.compare_digest`):

```bash
# entries: identity:roles:sha256hex   (roles: admin, operator, or admin+operator)
python -m app.auth hash "$(openssl rand -hex 32)"   # prints the hash of a key you generate
export IDENTITYSHIELD_API_KEYS="alice:admin:<hash>,ci-bot:operator:<hash>"
```

- `authorized_by` on scope entries is set from the authenticated key's identity (`alice` above). Any client-supplied `authorized_by` is ignored.
- **Local dev option:** `IDENTITYSHIELD_DEV_API_KEYS` takes the same format with a *plaintext* key (e.g. `dev:admin+operator:devkey`). It is honoured **only** when `IDENTITYSHIELD_ENV=local` (the default) and ignored otherwise. Never use it in a shared deployment.

See [`.env.example`](.env.example).

Authorize the simulator as a test target (**default-deny** — nothing runs without this):

```bash
export IDENTITYSHIELD_DEV_API_KEYS="dev:admin+operator:devkey"   # before starting uvicorn
curl -X POST localhost:8000/scope \
  -H 'X-API-Key: devkey' -H 'Content-Type: application/json' \
  -d '{"target": "localhost"}'
```

```bash
curl -H 'X-API-Key: devkey' localhost:8000/tests/modules
curl -X POST localhost:8000/tests/run \
  -H 'X-API-Key: devkey' -H 'Content-Type: application/json' \
  -d '{"module_id": "workflow.liveness.client_assertion_ignored", "target": "localhost:8000"}'
curl -H 'X-API-Key: devkey' localhost:8000/results/runs
```

## Tests

```bash
cd backend
pip install -r requirements.txt
python -m pytest tests/ -v
```

On `main` @ `bbb5129` the suite is **146 tests, all passing** (locally and in CI). With the open fix PRs #18–#22 merged together it is **371 tests, all passing in both simulator modes** (default vulnerable mode and `IDENTITYSHIELD_SIM_VULNERABLE=false`). See [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md). The suite starts its own local uvicorn instance and configures its own throwaway hashed API keys.

## Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Set `VITE_API_BASE_URL` if the backend is not on `localhost:8000`, and `VITE_API_KEY` to a key with the roles you need (the dashboard uses both `admin` and `operator` routes). This embeds the key in the browser bundle — local use only.

## Docker Compose (Postgres)

```bash
cp .env.example .env   # then set a strong POSTGRES_PASSWORD (and API keys)
docker compose up --build
```

Database credentials are read from `.env` (git-ignored) — nothing is hard-coded in `docker-compose.yml`, and compose fails fast if `POSTGRES_USER`/`POSTGRES_PASSWORD` are unset. Postgres is **not** published on the host; only the backend reaches it over the internal compose network. To inspect the DB locally, uncomment the `127.0.0.1:5432:5432` mapping in `docker-compose.yml` (loopback only). Note: if the password contains URL-special characters (`@ : / %`), URL-encode it, since it is interpolated into `DATABASE_URL`.

Written and reviewed; **not run end-to-end** in the environment that wrote these docs (no Docker daemon). See `docs/LIMITATIONS.md`.

## Screenshots

| Dashboard | Module list | Run results | Scope authorization |
|---|---|---|---|
| *TODO* | *TODO* | *TODO* | *TODO* |

## Safety model (brief)

- `IDENTITYSHIELD_ALLOWED_TARGETS` (server env, not settable via API) caps hostnames.
- Control-plane routes require an API key with the right role (`admin` / `operator`); no keys configured → fail closed.
- Every module run needs an explicit, non-revoked `ScopeEntry` (`POST /scope`) — default-deny.
- Targets are parsed once by a strict canonical parser, and HTTP modules build request URLs only from the parsed host/port. Userinfo, `@`, backslashes, whitespace and paths are rejected (#18). Layer 4 targets must be strict Android package names, and adb remote-shell arguments are quoted (#19).
- Unimplemented modules report explicit errors; Layer 4 Android modules (signature, permissions, device trust, local-storage exposure, network security config) report `skipped` when no adb/device is available. Neither is ever reported as success.

Layers 2/3 score bundled SYNTHETIC fixtures (match scores, liveness challenge cases) end-to-end against the simulator. See `docs/DATASETS.md` for sources and licenses. Current metrics: L2 FAR 0.03 / FRR 0.20; L3 APCER 0.333 / BPCER 0.0 / ACER 0.167 in vulnerable mode, and 0.0 / 0.0 / 0.0 in hardened mode. With #21 the hardened figure is measured against a server-issued, single-use challenge.

Does **not** implement counterfeit-document generators, biometric spoofing media, presentation-attack media, or root/Play-Integrity bypass tooling (by design). See LIMITATIONS.md.

## Project structure

```text
backend/             FastAPI orchestrator + KYC simulator + layer packages + pytest
android-companion/   Kotlin companion APK + instrumentation for on-device checks (builds in CI; run on an API 34 emulator, see docs/LAYER4_EMULATOR_RUN.md)
dashboard/           React + TypeScript SPA
docs/                Architecture, threat model, limitations, roadmap, test results
evidence/            Raw output dir (contents gitignored)
docker-compose.yml   Postgres + backend + dashboard
```

## Contributing

Update `docs/LIMITATIONS.md` in the same change as any capability claim. Keep scope/authorization fail-closed. Do not add generators for counterfeit identity documents or biometric attack media.

## License

**No `LICENSE` file is present.** Add an SPDX license before treating the project as redistributable open source.

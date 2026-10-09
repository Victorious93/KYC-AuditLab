# IdentityShield

A local-first security research framework for evaluating a KYC/identity-
verification system's resistance to seven classes of weakness: document
validation, facial biometrics, liveness detection, Android client security,
API/network security, verification-workflow/session security, and fraud
monitoring.

**Out of the box, this targets only its own bundled simulator.** No
third-party production identity-verification system is in scope by
default; see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for why, and
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for what is and isn't
implemented (read this before trusting any claim about what the framework
"found").

## Quickstart (no Docker needed)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

In another terminal, authorize the simulator as a test target (default-deny
is enforced - nothing runs without this):

```bash
curl -X POST localhost:8000/scope \
  -H 'Content-Type: application/json' \
  -d '{"target": "localhost", "authorized_by": "you"}'
```

List and run test modules:

```bash
curl localhost:8000/tests/modules
curl -X POST localhost:8000/tests/run \
  -H 'Content-Type: application/json' \
  -d '{"module_id": "workflow.liveness.client_assertion_ignored", "target": "localhost:8000"}'
curl localhost:8000/results/runs
```

## Run the automated test suite

```bash
cd backend
pip install -r requirements.txt
python -m pytest tests/ -v
```

21/21 pass as of this writing - see [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)
for the real, current run output and the bugs that were found and fixed
while getting there.

## Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Builds and type-checks cleanly (`npm run build`); set `VITE_API_BASE_URL`
if the backend isn't on `localhost:8000`.

## Docker Compose (Postgres-backed)

```bash
docker compose up --build
```

Written and reviewed, **not run end-to-end** in this development
environment (no Docker daemon available here) - see `docs/LIMITATIONS.md`.

## Repository layout

```
backend/            FastAPI orchestrator + the KYC simulator it targets
  app/orchestrator/    registry, runner, scope/authorization enforcement
  app/simulator/       the local, resettable KYC test target
  app/layers/          one package per attack layer (layer1..layer7)
  tests/               pytest suite, runs against a live local instance
android-companion/   Kotlin source for on-device checks (not built/run - see LIMITATIONS.md)
dashboard/           React + TypeScript SPA
docs/                Architecture, threat model, limitations, roadmap, test results
evidence/            Raw test output (gitignored contents)
```

## Safety model, briefly

- `IDENTITYSHIELD_ALLOWED_TARGETS` (server-side env, not settable via API)
  is a hard ceiling on what hostnames can ever be tested from a given
  deployment.
- Every module run additionally requires an explicit, non-revoked
  `ScopeEntry` row (`POST /scope`) - default-deny, not default-allow.
- A module that isn't really implemented (see Layer 4) always reports an
  explicit error naming the limitation; it never silently no-ops as if it
  had run.

Full detail in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

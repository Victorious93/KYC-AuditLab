# Controller integration (Droidcommand-AI and other host tools)

This is the contract for an **external controller** - e.g. Droidcommand-AI
calling IdentityShield as a host tool - that drives the lab through its
HTTP API. It covers authentication, the token lifecycle, which roles each
call needs, error handling and scope rules.

## What exists in this repo (as of this change)

- **No controller code lives here.** Before this change the repo had no CLI,
  Python client, MCP/tool manifest or controller harness; Droidcommand-AI
  was only mentioned in the roadmap/limitations as a future token client.
  The only API client was the dashboard (`dashboard/src/api.ts`, session
  tokens since #24).
- **Reference client:** `backend/app/client/` (`IdentityShieldClient`) plus a
  small CLI (`python -m app.client ...`). It depends only on `requests` and
  the standard library, so a controller can import it from a checkout or
  vendor the package. It implements everything below.
- **The Android companion APK does not call the API.** It has no `INTERNET`
  permission and no HTTP code. The backend's Layer 4 harness
  (`backend/app/layers/layer4_android/harness.py`) installs it with
  `adb install -r -t`, runs `adb shell am instrument -w ...
  com.identityshield.companion/.IntegrityInstrumentation` and parses the
  JSON the instrumentation prints. Results flow device → adb → backend; the
  APK never authenticates, so it needs no key or token. A controller that
  wants Android results calls `POST /tests/run` with a Layer 4 module; it
  does not talk to the APK. See "Future APK clients" below.

## Endpoints

Base URL: `http://127.0.0.1:8000` by default (`IDENTITYSHIELD_API_URL`).

| Call | Auth | Role | Notes |
|---|---|---|---|
| `POST /auth/session` | `X-API-Key: <key>` | any valid key | Returns `{token, token_type: "Bearer", expires_at (ISO 8601 UTC), identity, roles}`. Only accepts an API key, never a token. |
| `POST /auth/logout` | `Authorization: Bearer <token>` | any | Revokes that token (`{"revoked": true}`). |
| `GET /tests/modules` | Bearer | `operator` | Module catalogue (`id`, `layer`, `title`, `capability`, `limitation`). |
| `POST /tests/run` | Bearer | `operator` | Body `{module_id, target, params?}` → `{run_id, status, summary, finding_count}`. |
| `POST /tests/run-layer` | Bearer | `operator` | Body `{layer, target}` (`layer1_document` .. `layer7_fraud`). |
| `GET /results/runs`, `GET /results/runs/{id}` | Bearer | `operator` | Run history / one run with findings. |
| `GET /scope`, `POST /scope`, `DELETE /scope/{target}` | Bearer | `admin` | Scope allowlist entries. `POST` body `{target, note?}`; `authorized_by` is taken from the key's identity. |
| `GET /health` | none | - | Liveness. |

Roles are **not hierarchical**. A controller that only runs tests and reads
results should get an `operator`-only key. Give it `admin` too only if it must
manage scope entries itself; prefer a human operator authorizing scope.

`/simulator/*` (except `/simulator/admin/*`, which is `admin`) is the bundled
*target*. It is not part of the control-plane contract.

## Token lifecycle

1. **Get the key at runtime** from the environment (`IDENTITYSHIELD_API_KEY`)
   or a secret store. Never put it on a command line, in a config file
   checked into a repo, in logs, or in an app bundle.
2. **Exchange it once:** `POST /auth/session` with `X-API-Key`. Keep the
   returned token **in memory only**. Keep the key in memory only if you need
   to re-authenticate unattended. Otherwise drop it.
3. **Call the API** with `Authorization: Bearer <token>`. Do not send
   `X-API-Key` on any other request.
4. **Refresh proactively:** the reference client signs in again ~30 s before
   `expires_at`. Default TTL is 3600 s (server: 60-43200 s,
   `IDENTITYSHIELD_SESSION_TTL_SECONDS`).
5. **On 401 from a Bearer call:** drop the token, sign in again **once**, and
   retry the request once. A 401 can mean the token expired, was revoked, the
   server restarted with a random secret, or the key was rotated. If the
   re-sign-in itself returns 401 the key is no longer valid. Stop and surface
   the error (do not loop).
6. **On exit:** `POST /auth/logout` with the token (best effort), then forget
   it. Revocation is server-side until the token's own expiry.

```python
from app.client import IdentityShieldClient  # backend/ on sys.path

with IdentityShieldClient() as lab:  # key from IDENTITYSHIELD_API_KEY, URL from IDENTITYSHIELD_API_URL
    lab.list_modules()
    run = lab.run_module("api.auth.missing_token_rejected", "127.0.0.1:8000")
    lab.get_run(run["run_id"])
# token revoked here
```

CLI (JSON on stdout. Exit codes: 0 ok, 1 API error, 2 config error, 3 auth error
(401/403), 4 rate limited):

```bash
export IDENTITYSHIELD_API_KEY=...   # from your secret store, at runtime
cd backend && python -m app.client whoami
python -m app.client run --module api.auth.missing_token_rejected --target 127.0.0.1:8000
```

## Error handling

| Status | Meaning | Controller action |
|---|---|---|
| 401 on `/auth/session` | wrong/missing key | Stop. Do not retry with the same key (failed attempts count toward the rate limit). |
| 401 on a Bearer call | token expired/revoked/unknown | Re-sign-in once, retry once (see above). |
| 403 | key lacks the role | Stop. Use a key with the right role. Re-signing in will not help. |
| 404 | unknown module/layer/run | Fix the request. |
| 429 + `Retry-After` | too many **failed** sign-ins from this IP (default 10 per 300 s) | Wait `Retry-After` seconds before signing in again. While the window lasts, even a correct key gets 429 (no oracle). The reference client waits once if `Retry-After` ≤ 30 s (configurable), otherwise raises `RateLimited` with `retry_after`. |
| 503 | server has no keys configured, or session tokens disabled (secret too short) | Operator configuration problem. Stop. |
| Run `status: "blocked"` / scope error in summary | target not on the allowlist or not scoped | Ask the operator to authorize scope. Do not try other targets. |

## Scope rules (non-negotiable)

- IdentityShield is a **local lab**. Targets are the bundled simulator
  (`127.0.0.1`/`localhost`) or an allowlisted, explicitly scoped emulator /
  test device package for Layer 4. Every module goes through
  `assert_in_scope()` server-side. A controller must not try to widen scope or
  probe other hosts.
- The reference client **refuses non-loopback base URLs** unless the caller
  opts in (`allow_non_loopback=True` or
  `IDENTITYSHIELD_CLIENT_ALLOW_NON_LOOPBACK=1`), which is meant only for a
  trusted local network such as the compose service name `backend`.
- Compose binds the API to `127.0.0.1:8000`. Do not expose it publicly.
  Plain HTTP is acceptable only on loopback.
- Layer 4 targets must be strict Android package names on an attached
  emulator/test device (`adb devices`). No physical customer devices.
- No real personal data. Use only the simulator's synthetic identities and
  bundled fixtures.

## Keys never go in app bundles

- No API key in an APK (`BuildConfig`, `res/values`, assets, `local.properties`
  baked into the build), in a dashboard/JS bundle, in a container image or in a
  controller's shipped config. CI runs gitleaks and the dashboard
  `check:bundle` scan.
- One key per controller/identity, so rotating or removing one key (server
  env `IDENTITYSHIELD_API_KEYS`) revokes that controller's tokens immediately
  without affecting others.

## Future APK clients

If a future companion feature needs to call the API from the device (e.g. to
push results instead of printing them for the harness):

- Get credentials **at runtime only**: preferably the host/controller mints a
  short-lived token (`POST /auth/session`) and passes **the token** (not the
  key) to the instrumentation via `am instrument -e token ...` or an
  `adb reverse`-scoped local channel. Never put a key in `BuildConfig`,
  resources or assets.
- Keep the token in memory only (no `SharedPreferences`/files). Treat 401 as
  "ask the host for a new token". Call `POST /auth/logout` when done.
- Reach the backend via `adb reverse tcp:8000 tcp:8000` (device sees
  `127.0.0.1:8000`) and a debug-only network security config that permits
  cleartext to `127.0.0.1` only. Add `INTERNET` permission only in that change.
- Give it an `operator`-only key's token. It never needs `admin`.

## Known limitations

The token denylist and the sign-in rate limiter are in-memory and per worker
(see `docs/LIMITATIONS.md`). Behind a reverse proxy all clients share one
rate-limit bucket. A leaked token that nobody signs out stays valid until it
expires or its key is rotated.

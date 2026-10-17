# IdentityShield — Threat Model & Scope Boundaries

## Intended use

IdentityShield is a **local-first security research framework** for
evaluating a KYC/identity-verification system's resistance to a defined
set of weaknesses. Out of the box it ships with, and is tested against,
**one target: its own bundled simulator.** It is not a generic internet
scanning tool and does not ship with capability to target a third-party
production identity-verification service.

## Who/what this framework assumes

- **The operator** controls the deployment, the simulator, and the scope
  database. They are the only party who can add a `ScopeEntry`.
- **The simulator** is a synthetic, resettable fixture representing "a KYC
  backend," not a real identity-verification provider.
- **Test modules** are considered semi-trusted code running with the
  orchestrator's own privileges - the registry/runner enforce scope on
  their behalf, but a malicious module *could* ignore `ctx.target` and do
  something else. Modules in this repo are reviewed; third-party modules
  should be reviewed before being added to the registry.

## Enforced controls

| Control | Where | What it stops |
|---|---|---|
| Hostname allowlist (`IDENTITYSHIELD_ALLOWED_TARGETS`, server-side env only) | `orchestrator/scope.py` | A test-run request naming a target outside the deployment's intended set, even if an API caller tries to widen scope |
| One canonical target parser for the scope decision **and** request URLs (#18) | `orchestrator/scope.py` (`parse_target`, `target_url`), `TestContext.url()` | Parser-differential bypasses such as `127.0.0.2:18080\@localhost` (scope sees `localhost`, the HTTP client connects to `127.0.0.2:18080`) |
| Strict Android package names + quoted adb shell args (#19) | `orchestrator/scope_android.py`, `layers/layer4_android/harness.py` | Shell injection on the test device via the Layer 4 target (`com.android.settings/ ;<cmd>`) |
| Explicit `ScopeEntry` requirement (default-deny) | same | Running against a target with no recorded authorization, even if it happens to be allowlisted |
| `capability` gate on every registered module | `orchestrator/runner.py` | Claiming a result for a module that has no real implementation (stub modules always report an explicit "not executed" error) |
| Simulator reset between runs (`/simulator/admin/reset`) | `simulator/store.py` | State leaking between test runs producing misleading results |

## What is explicitly NOT built, and why

See `LIMITATIONS.md` for the full list. In short: anything whose output
would be a tool for defeating a *real* liveness/biometric/document check
(synthetic document forgery generators, presentation-attack media,
biometric spoofing pipelines, anti-root-detection evasion) is out of scope
for this project regardless of how the request is framed, because the
artifact itself is identical whether used once against your own test
target or reused against a real system. Layers 2 and 3 instead ship a
fully functional *measurement* harness (FAR/FRR/APCER/BPCER) that the
operator points at their own detector/dataset.

## Residual risk / what this framework does NOT guarantee

- Passing all bundled tests against your real KYC system (once you've
  ported the test logic to target it, outside this framework's default
  scope) does not mean it is secure - these are representative checks for
  the classes of bugs named in the seven layers, not an exhaustive audit.
- The Android layer has been executed only on one API 34 emulator (see
  `LAYER4_EMULATOR_RUN.md`), never on physical hardware; no Android-layer
  claim should be trusted without real device evidence attached to the run.
- The biometric/liveness harnesses are only as good as the dataset/detector
  supplied to them; the bundled defaults are synthetic placeholders, not
  evidence of any real system's performance.

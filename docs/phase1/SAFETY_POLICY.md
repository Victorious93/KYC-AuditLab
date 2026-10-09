# Safety, Execution, and Release Policy (M1)

This is the policy documentation M1 requires. It describes what's
enforced, where, and how it's tested - not aspirational language.

## 1. Local-only execution contract

Enforced in `backend/app/orchestrator/scope.py:assert_in_scope`, called at
the top of every module execution in `runner.py`. Two independent checks,
both required:

1. **Hostname allowlist** (`is_host_allowlisted`): the target's hostname
   must appear in `Settings.allowed_targets`, which comes only from the
   server-side `IDENTITYSHIELD_ALLOWED_TARGETS` env var - never from a
   request body. This is the hard ceiling; nothing in the API can widen it.
2. **Explicit authorization** (`is_explicitly_authorized`): a non-revoked
   `ScopeEntry` row for that host must exist. Default-deny: no row means
   not authorized, full stop.

Formalized as a schema in `backend/app/schemas/execution_config.py`
(`ExecutionConfigV1`): rejects an empty allowlist, rejects any hostname
containing a production-looking substring (`production`, `prod.`, `.prod`,
`live.`), and rejects `environment="production"` outright.

**Tested (negative/fail-closed):** `backend/tests/test_scope_enforcement.py`
(`test_unscoped_target_is_blocked`, `test_non_allowlisted_host_is_blocked`)
and `backend/tests/test_schemas.py` (`test_execution_config_rejects_*`).

## 2. Fail-closed behavior

| Situation | Behavior | Enforced in | Tested in |
|---|---|---|---|
| Missing authorization | `RunStatus.BLOCKED`, run aborted before module code executes | `runner.py` | `test_scope_enforcement.py` |
| Target outside hostname allowlist | Same as above | `runner.py`/`scope.py` | `test_scope_enforcement.py` |
| Capability not executable (no `run()`) | `RunStatus.UNAVAILABLE` or `UNSUPPORTED`, never silently skipped or reported as pass | `runner.py` | `test_android_modules_are_honest_stubs` |
| Module raises an unhandled exception | `RunStatus.ERROR`, traceback captured as evidence, never converted to pass | `runner.py` | (exercised implicitly; no module in this repo currently raises, by design - see note below) |
| Malformed execution config | Pydantic `ValidationError` at load time, nothing starts | `schemas/execution_config.py` | `test_schemas.py` |
| Fixture without a classification | Pydantic `ValidationError` | `schemas/fixture_metadata.py` | `test_schemas.py` |

Note on the ERROR path: no real, registered module has been observed to
actually raise during a test run. `backend/tests/test_runner_failure_injection.py`
closes the gap by constructing a throwaway, non-registered `TestModule`
with a deliberately raising `run()` and asserting `RunStatus.ERROR` with
the traceback captured in `raw_output` - the ERROR row above is now a
reproduced result, not just code inspection.

## 3. Completion-state vocabulary

`backend/app/models.py:RunStatus` implements the delivery model's required
vocabulary (M1 Task 7) as the system's actual status enum, not a parallel
label applied afterward:

`pending`, `running` (transient) -> `pass`, `fail`, `blocked`,
`unsupported`, `skipped`, `flaky`, `unavailable`, `not-run`, `error`
(terminal).

A module with no `run()` callable is classified at registration time via
`TestModule.unexecuted_status` (`orchestrator/registry.py:UnexecutedStatus`)
as either `UNAVAILABLE` (environment/dependency missing right now - e.g.
Layer 4's lack of an Android device) or `UNSUPPORTED` (intentionally never
built, by design). This distinction is real, not cosmetic: `UNAVAILABLE`
says "would work elsewhere," `UNSUPPORTED` says "won't be built here."

No code path sets a run to `pass` except `runner.py`'s
`result.passed`-derived assignment after a module actually executed -
there is no "optimistic" or default-pass behavior anywhere.

## 4. Fixture/dataset provenance

Every fixture bundled with this project must be declared via
`FixtureMetadataV1` (`backend/app/schemas/fixture_metadata.py`) with an
explicit `classification` (`synthetic` / `consented` / `approved` /
`preexisting_approved`). `backend/app/schemas/fixtures_registry.py` lists
every fixture actually shipped; `test_all_bundled_fixtures_are_synthetic`
asserts every one of them is `SYNTHETIC` and declares
`contains_real_imagery_or_biometrics=False` - this project ships no real
dataset, by design (see `docs/LIMITATIONS.md`). The schema itself rejects
the contradictory combination (`SYNTHETIC` + real data declared True).

## 5. Evidence manifest

`EvidenceManifestV1` (`backend/app/schemas/evidence_manifest.py`) defines
the structure for the "Final evidence package" `manifest.json` the
delivery model specifies (release ID, commit, timestamps, tool versions,
config hash, fixture IDs, artifact hashes, test statuses, approval
references). **Not yet wired to an actual evidence-package build step** -
the schema exists and is tested; nothing currently populates and writes a
real `manifest.json` for a release. Tracked as a gap, not claimed as done.

## 6. What is NOT covered by this policy yet

- Adapter-interface rules for future capabilities (M1 Task 5) - no
  adapter abstraction exists yet beyond the `TestModule`/`run()` contract
  itself.
- Evidence naming/retention/redaction rules (M1 Task 6, partially) - the
  manifest schema exists; naming/retention/redaction conventions do not.
- A release-gate specification enforcing these schemas in CI (M1 Task 8) -
  no CI exists at all yet (see `tooling-baseline.md`).

These are recorded in `risk-register.csv` and `traceability.csv` rather
than silently left out of this document.

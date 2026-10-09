# Development Roadmap / Implementation Status

| Phase | Scope | Status |
|---|---|---|
| 1 — Foundation | Repo, backend API, DB models, scope/safety controls, simulator, test registry, docker-compose, docs | **Done** (this delivery). Postgres path written, not execution-tested here (no Docker daemon); SQLite path fully tested. |
| 2 — API & Workflow (Layers 5, 6) | Automated tests, reproducible findings | **Done.** 11 modules, all `IMPLEMENTED`, all passing against the simulator in both vulnerable and hardened modes. |
| 3 — Android (Layer 4) | Device connectivity, instrumentation, integrity checks | **Not started execution-wise.** Interface registered (5 modules, `STUB_NOT_IMPLEMENTED`), Kotlin source written but not built/run. Needs: Gradle build config, `adb`-shelling in `runner.py`, an attached device/emulator. |
| 4 — Document & Biometric (Layers 1, 2, 3) | Controlled datasets, measurable criteria | **Partially done.** Layer 1 fully implemented (synthetic fixtures). Layers 2/3 have fully implemented, tested metric engines (FAR/FRR/EER, APCER/BPCER/ACER) running on synthetic placeholder data by design - real-dataset wiring is a config/param change away, not new code, but has not been exercised with real data here. |
| 5 — Fraud & Reporting (Layer 7) | Reporting, dashboard, history, correlation | **Partially done.** Layer 7 implemented and tested (2 modules). Dashboard exists (lists modules, runs them, shows findings) and builds cleanly; no cross-layer correlation view, no PDF/HTML export yet - only JSON via the API. |
| 6 — Validation & Hardening | Full test pass, security checks, limitations documented | **In progress.** 21/21 backend tests passing (see `TEST_RESULTS.md`); dashboard build verified; Docker Compose stack not run end-to-end; no `security-review` pass performed yet on this diff. |

## Concrete next steps, in priority order

1. **Run a `/security-review` pass** on this diff before treating it as
   done - this delivery has not had one yet.
2. **Stand up the Docker Compose stack for real** in an environment with a
   Docker daemon; confirm the Postgres path (currently only SQLite-tested)
   and that `IDENTITYSHIELD_ALLOWED_TARGETS=backend` actually resolves
   correctly for container-to-container calls.
3. **Layer 4 execution**: add a Gradle build for `android-companion/`, get
   it running against at least one emulator via `adb`, and replace the
   `STUB_NOT_IMPLEMENTED` registrations with real `run()` callables gated
   through `scope.assert_in_scope()`.
4. **PDF/HTML report export** (`routers/`): currently only JSON via
   `/results/runs`; add a report-template renderer per the original ask's
   "Security assessment report templates" deliverable.
5. **Cross-layer correlation**: a view/endpoint that groups findings by
   run-session or by simulated identity across layers (e.g. "this identity
   tripped a Layer 7 velocity flag AND a Layer 6 override attempt").
6. **Real TTL-expiry test** for `workflow.session.expiry_mechanism` using a
   short-TTL policy override, instead of only checking forged-id rejection.
7. **Risk scoring rollup**: findings carry a `risk_score` already; add an
   aggregate score per run/target rather than only per-finding.

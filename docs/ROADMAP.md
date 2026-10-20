# Development Roadmap / Implementation Status

_Last refreshed 2026-10-17 against `main` @ `bbb5129` plus the open fix PRs #18-#22. Rows marked with a PR number depend on that PR being merged._

| Phase | Scope | Status |
|---|---|---|
| 1 — Foundation | Repo, backend API, DB models, scope/safety controls, simulator, test registry, docker-compose, docs | **Done.** API-key auth with admin/operator roles (#4); Postgres credentials from env (#5); IPv6-safe scope parsing (#6), replaced by one strict canonical parser for both the scope check and request URLs (#18); evidence policy, redaction and retention (#8). The SQLite path is fully tested. The Postgres path is not covered by CI; the enum-label migration for existing DBs is corrected and automated at startup (#20). Docker Compose has still not been run end to end. |
| 2 — API & Workflow (Layers 5, 6) | Automated tests, reproducible findings | **Done.** 12 modules (6 + 6), all `IMPLEMENTED`, run against the simulator in both modes. The only failure in hardened mode is the documented rate-limit rotation bypass (F14). |
| 3 — Android (Layer 4) | Device connectivity, instrumentation, integrity checks | **Implemented; emulator-verified once.** 5 modules wired to the adb/instrumentation harness (#14, #15). The companion builds in CI (`assembleDebug`, #12). There was one real run on an Android 14 / API 34 emulator (#16, `LAYER4_EMULATOR_RUN.md`). The modules skip honestly when there is no adb, device or APK. Strict package-name validation and quoted adb shell args (#19). Not run on physical devices, other API levels or rooted devices. |
| 4 — Document & Biometric (Layers 1, 2, 3) | Controlled datasets, measurable criteria | **Done on synthetic data.** L1 implemented with synthetic fixtures. L2/L3 score bundled synthetic fixtures end to end against the simulator (#17): L2 FAR 0.0300 / FRR 0.2000. L3 vulnerable APCER 0.3333 / BPCER 0.0000 / ACER 0.1667, and hardened 0.0 / 0.0 / 0.0 against a server-issued single-use challenge (#21). No real dataset, matcher or image-based PAD. |
| 5 — Fraud & Reporting (Layer 7) | Reporting, dashboard, history, correlation | **Partially done.** Layer 7 implemented and tested (2 modules). The dashboard exists (lists modules, runs them, shows findings) and builds. The backend now has a CORS allowlist for it, and compose binds to loopback (#22). The dashboard no longer has an API key in its bundle: operators sign in at runtime and it holds only a short-lived session token (`POST /auth/session`); CI builds it and scans the bundle for key-like content. There is no cross-layer correlation view and no PDF/HTML export, only JSON via the API. |
| 6 — Validation & Hardening | Full test pass, security checks, limitations documented | **In progress.** `main`: 146 backend tests pass locally and in CI. With #18–#22 merged together: 371 pass locally, in both simulator modes (see `TEST_RESULTS.md`). CI runs backend-tests, pip-audit, npm-audit, gitleaks and android-build. A security audit was done on 2026-10-17, and its High/Medium findings F1–F6 are addressed by #18–#22. Docker Compose has not been run end to end. |

## Concrete next steps, in priority order

1. **Merge and verify #18–#22**, then re-run the full module set in both simulator modes and update `TEST_RESULTS.md`.
2. **Alembic + a Postgres CI job.** Add a baseline migration and a `postgres:16` service-container job that runs the suite. Today SQLite hides enum and type issues.
3. **Dashboard follow-ups.** Serve a static build in Docker instead of the dev server. Have Droidcommand-AI adopt the token client / contract in `docs/CONTROLLER_INTEGRATION.md` (the reference client `backend/app/client/` exists; the APK does not call the API). Rate limit on `/auth/session` and server-side sign-out are done (#25); still open: a shared (Redis/DB) denylist and limiter, and narrower dashboard roles.
4. **Typed per-module params** with paths confined to a data directory (`scores_csv_path`, `cases_csv_path`, `apk_path`).
5. **Container hardening.** Run as a non-root `USER`, drop the baked default `DATABASE_URL`, and set `IDENTITYSHIELD_ENV` and `IDENTITYSHIELD_SIM_VULNERABLE` explicitly in compose.
6. **Stand up the Docker Compose stack for real** and confirm that `IDENTITYSHIELD_ALLOWED_TARGETS=backend` resolves for container-to-container calls.
7. **Scope entries with port and expiry**, a boolean `revoked` and a revocation audit trail.
8. **CI supply chain.** SHA-pin the actions, pin pip-audit, add Gradle wrapper validation, Dependabot, CodeQL/Semgrep and an SBOM. Re-enable artifact uploads now that billing is fixed.
9. **Broaden Layer 4.** Cover a physical device, API ≤33 and 35+, a rooted test device, and NSCs with pins, domain-configs and debug-overrides.
10. **Real TTL-expiry test** for `workflow.session.expiry_mechanism`, plus a hardened rate limiter (per client or global).
11. **Fix the deprecations** (`datetime.utcnow`, Pydantic class `Config`) using timezone-aware columns.
12. **PDF/HTML report export, cross-layer correlation and risk-score rollups.**

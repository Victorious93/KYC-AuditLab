# Contributing

## Definition of done

A feature PR is done only when **all** of these hold:

1. Tests pass: backend `python -m pytest tests/` in both simulator modes (default and
   `IDENTITYSHIELD_SIM_VULNERABLE=0`), the dashboard `npm run build && npm run check:bundle`, and the
   Android `./gradlew assembleDebug` when those parts change.
2. **The manual is updated.** Any user-visible change (a feature, endpoint, setting, environment
   variable, permission, error behaviour or UI change) is described in
   [`docs/MANUAL.md`](docs/MANUAL.md). Update the dashboard Help page (`dashboard/src/Help.tsx`) and
   the companion Help screen (`android-companion/app/src/main/res/values/strings.xml`) when their
   summaries are affected. Manual screenshots in `docs/manual/img/` must be real captures against the
   simulator with synthetic data. Never fabricate them.
3. No secrets or real personal data are committed.

The PR template (`.github/pull_request_template.md`) repeats this checklist.

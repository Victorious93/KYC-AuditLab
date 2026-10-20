## What changed

<!-- One or two sentences. -->

## How it was tested

- [ ] `cd backend && python -m pytest tests/` (default vulnerable mode)
- [ ] `IDENTITYSHIELD_SIM_VULNERABLE=0 python -m pytest tests/` (hardened mode)
- [ ] `cd dashboard && npm ci && npm run build && npm run check:bundle` (if the dashboard changed)
- [ ] `cd android-companion && ./gradlew assembleDebug` (if the companion changed)

## Definition of done

- [ ] **Manual updated.** User-visible features, settings, routes, permissions or behaviour changes are reflected in `docs/MANUAL.md`, plus the dashboard Help page and the companion Help screen where relevant. A feature PR without its manual update is not done.
- [ ] No secrets, keys, tokens or real personal data are committed. Only synthetic data is used.
- [ ] No new Android permissions, unless explicitly justified here and in the manual's permissions section.

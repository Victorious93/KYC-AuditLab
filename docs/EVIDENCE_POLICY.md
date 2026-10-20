# Evidence Policy

IdentityShield stores test output (`test_runs.raw_output`, `summary`,
finding descriptions) and evidence files under `IDENTITYSHIELD_EVIDENCE_DIR`.
KYC testing can touch identity data, so this output is treated as sensitive.

## 1. Minimize
- Modules should test against the bundled simulator and synthetic identities.
- Capture only what is needed to demonstrate a finding (status codes, field
  names, counts) — not full documents, selfies, or response bodies with PII.

## 2. Redaction (implemented)
`app/evidence/redact.py::redact()` is applied **before persistence** by the
orchestrator (`runner.py`) to `raw_output`, `summary`, tracebacks and finding
descriptions, and by `app/evidence/store.py::write_evidence()` to evidence files
(which are also created `0600`, with path-traversal-safe names).

Patterns replaced with `[REDACTED:<kind>]`: email addresses, payment card numbers
(Luhn-validated), US SSNs (`123-45-6789`), IBANs, international phone numbers
(`+` prefix), JWTs and `Bearer` tokens.

This is a best-effort safety net for *obvious* patterns. It will not catch
names, addresses, dates of birth, national ID formats, or images. Do not rely on
it as the only control.

## 3. Encryption at rest (operator responsibility — not implemented in code)
- **Database:** run Postgres on an encrypted volume (LUKS / cloud-provider
  disk encryption, e.g. encrypted EBS/PD). Use TLS (`sslmode=require`) if the DB
  is not on the same host/network.
- **Evidence directory:** place the `evidence` volume on encrypted storage; keep
  it owner-only (`0700` dir, `0600` files).
- **Backups:** must be encrypted and are subject to the same retention.
- Credentials come from `.env` / a secret manager, never the repo.

## 4. Retention (implemented)
Default: **30 days** (`IDENTITYSHIELD_RETENTION_DAYS`).

```bash
cd backend
python -m app.evidence.retention --dry-run      # report only
python -m app.evidence.retention --days 30      # delete
```

Deletes `test_runs` (findings cascade) whose `started_at` is older than the
cutoff, and files in the evidence dir with an older mtime. It is **not**
scheduled automatically — run it from cron, a systemd timer, or a scheduled job
(e.g. `docker compose exec backend python -m app.evidence.retention`).
Scope entries (authorization records) are not deleted.

## 5. Access
Results are exposed only through `operator`-role API endpoints (see API key
auth). Share exported evidence only with people authorized for the engagement.

"""Retention cleanup: delete test runs (and their findings) and evidence files
older than N days.

    python -m app.evidence.retention [--days N] [--dry-run]

N defaults to IDENTITYSHIELD_RETENTION_DAYS (30). Intended to be run from
cron / a scheduled job; it is not run automatically.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import time
from dataclasses import dataclass

from ..config import get_settings
from ..db import SessionLocal, init_db
from ..models import TestRun


@dataclass
class CleanupReport:
    runs: int
    files: int


def cleanup(db, evidence_dir: str, days: int, dry_run: bool = False) -> CleanupReport:
    if days < 1:
        raise ValueError("retention days must be >= 1")
    cutoff = dt.datetime.utcnow() - dt.timedelta(days=days)
    old_runs = db.query(TestRun).filter(TestRun.started_at < cutoff).all()
    if not dry_run:
        for run in old_runs:
            db.delete(run)  # findings cascade
        db.commit()

    files = 0
    if os.path.isdir(evidence_dir):
        cutoff_ts = time.time() - days * 86400
        for root, _dirs, names in os.walk(evidence_dir):
            for n in names:
                p = os.path.join(root, n)
                if os.path.islink(p):
                    continue
                if os.path.getmtime(p) < cutoff_ts:
                    files += 1
                    if not dry_run:
                        os.remove(p)
    return CleanupReport(runs=len(old_runs), files=files)


def main(argv=None) -> int:
    settings = get_settings()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--days", type=int, default=settings.retention_days)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    init_db()
    db = SessionLocal()
    try:
        r = cleanup(db, settings.evidence_dir, args.days, args.dry_run)
    finally:
        db.close()
    verb = "Would delete" if args.dry_run else "Deleted"
    print(f"{verb} {r.runs} test run(s) and {r.files} evidence file(s) older than {args.days} day(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

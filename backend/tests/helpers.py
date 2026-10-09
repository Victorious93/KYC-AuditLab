"""Shared test helper: execute a module and return a plain, detached-safe
snapshot of the result (status + findings), since the ORM TestRun object
becomes unusable once its Session closes."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from app.db import SessionLocal
from app.orchestrator.runner import execute_module


@dataclass
class RunSnapshot:
    status: str
    summary: str
    finding_severities: List[str] = field(default_factory=list)


def run_module(target: str, module_id: str, params: dict | None = None) -> RunSnapshot:
    db = SessionLocal()
    try:
        run = execute_module(db, module_id, target, params)
        return RunSnapshot(
            status=run.status.value,
            summary=run.summary or "",
            finding_severities=[f.severity.value for f in run.findings],
        )
    finally:
        db.close()

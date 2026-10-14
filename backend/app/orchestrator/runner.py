from __future__ import annotations

import datetime as dt
import os
import traceback

from sqlalchemy.orm import Session

from ..config import get_settings
from ..evidence.redact import redact
from ..models import Finding as FindingModel
from ..models import RunStatus, TestRun
from .registry import Capability, TestContext, registry
from .scope import ScopeViolation, assert_in_scope

settings = get_settings()


def execute_module(db: Session, module_id: str, target: str, params: dict | None = None) -> TestRun:
    module = registry.get(module_id)

    run = TestRun(layer=module.layer.value, module_id=module.id, target=target, status=RunStatus.RUNNING)
    db.add(run)
    db.commit()

    # A module with no run() callable is a documented stub (e.g. an Android
    # action that needs a physical/emulated device not present here, or a
    # capability intentionally not built - see docs/LIMITATIONS.md). An
    # EVALUATION_ONLY module DOES have a real run() and executes normally;
    # it's just annotated that its offensive counterpart was not built or
    # that it needs real data the operator must supply.
    if module.run is None:
        run.status = RunStatus.ERROR
        run.summary = (
            f"Module '{module.id}' has no implementation to execute "
            f"(capability={module.capability.value}). Limitation: {module.limitation}"
        )
        run.finished_at = dt.datetime.utcnow()
        db.commit()
        return run

    try:
        assert_in_scope(db, target)
    except ScopeViolation as exc:
        run.status = RunStatus.BLOCKED_SCOPE
        run.summary = str(exc)
        run.finished_at = dt.datetime.utcnow()
        db.commit()
        return run

    os.makedirs(settings.evidence_dir, exist_ok=True)
    ctx = TestContext(target=target, db=db, evidence_dir=settings.evidence_dir, params=params or {})

    try:
        result = module.run(ctx)  # type: ignore[misc]
        run.status = RunStatus.PASSED if result.passed else RunStatus.FAILED
        run.summary = redact(result.summary)
        run.raw_output = redact(result.raw_output)
        for f in result.findings:
            db.add(
                FindingModel(
                    run_id=run.id,
                    title=f.title,
                    description=redact(f.description),
                    severity=f.severity,
                    cwe=f.cwe,
                    remediation=f.remediation,
                    risk_score=f.risk_score,
                )
            )
    except Exception:  # noqa: BLE001 - we want every module error captured, not crash the API
        run.status = RunStatus.ERROR
        run.summary = "Module raised an unhandled exception."
        run.raw_output = redact(traceback.format_exc())

    run.finished_at = dt.datetime.utcnow()
    db.commit()
    return run

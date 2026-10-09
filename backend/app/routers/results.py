from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import TestRun

router = APIRouter(prefix="/results", tags=["results"])


@router.get("/runs")
def list_runs(db: Session = Depends(get_db)):
    runs = db.query(TestRun).order_by(TestRun.started_at.desc()).all()
    return [
        {
            "id": r.id,
            "layer": r.layer,
            "module_id": r.module_id,
            "target": r.target,
            "status": r.status.value,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "summary": r.summary,
            "finding_count": len(r.findings),
        }
        for r in runs
    ]


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db)):
    r = db.query(TestRun).filter(TestRun.id == run_id).first()
    if r is None:
        raise HTTPException(status_code=404, detail="run not found")
    return {
        "id": r.id,
        "layer": r.layer,
        "module_id": r.module_id,
        "target": r.target,
        "status": r.status.value,
        "summary": r.summary,
        "raw_output": r.raw_output,
        "findings": [
            {
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "cwe": f.cwe,
                "remediation": f.remediation,
                "risk_score": f.risk_score,
            }
            for f in r.findings
        ],
    }

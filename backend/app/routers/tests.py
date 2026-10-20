from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import require_operator
from ..db import get_db
from ..orchestrator.registry import registry
from ..orchestrator.runner import execute_module

router = APIRouter(prefix="/tests", tags=["tests"], dependencies=[Depends(require_operator)])


@router.get("/modules")
def list_modules():
    return [
        {
            "id": m.id,
            "layer": m.layer.value,
            "title": m.title,
            "description": m.description,
            "capability": m.capability.value,
            "limitation": m.limitation,
        }
        for m in registry.all()
    ]


class RunRequest(BaseModel):
    module_id: str
    target: str
    params: dict | None = None


@router.post("/run")
def run_module(req: RunRequest, db: Session = Depends(get_db)):
    try:
        registry.get(req.module_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown module_id '{req.module_id}'")
    run = execute_module(db, req.module_id, req.target, req.params)
    return {
        "run_id": run.id,
        "status": run.status.value,
        "summary": run.summary,
        "finding_count": len(run.findings),
    }


class RunLayerRequest(BaseModel):
    layer: str
    target: str


@router.post("/run-layer")
def run_layer(req: RunLayerRequest, db: Session = Depends(get_db)):
    from ..orchestrator.registry import Layer

    try:
        layer_enum = Layer(req.layer)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Unknown layer '{req.layer}'")

    results = []
    for module in registry.by_layer(layer_enum):
        run = execute_module(db, module.id, req.target, None)
        results.append({"module_id": module.id, "run_id": run.id, "status": run.status.value})
    return {"layer": req.layer, "results": results}

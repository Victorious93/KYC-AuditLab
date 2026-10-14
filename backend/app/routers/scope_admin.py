from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import Principal, require_admin
from ..db import get_db
from ..models import ScopeEntry
from ..orchestrator.scope import ScopeViolation, _hostname


def _canonical_target(raw: str) -> str:
    # Store/look up the same canonical host form the scope check uses, so
    # "LOCALHOST ", "[::1]" and "::1" all refer to one entry.
    try:
        host = _hostname(raw)
    except ScopeViolation as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not host:
        raise HTTPException(status_code=422, detail="Empty target.")
    return host

router = APIRouter(prefix="/scope", tags=["scope"], dependencies=[Depends(require_admin)])


class ScopeCreateRequest(BaseModel):
    target: str
    # Deprecated and IGNORED: authorized_by is always taken from the
    # authenticated API key's identity. Accepted only so older clients that
    # still send it don't get a 422.
    authorized_by: str | None = None
    note: str | None = None


@router.post("")
def add_scope_entry(
    req: ScopeCreateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_admin),
):
    authorized_by = principal.identity  # never trust req.authorized_by
    target = _canonical_target(req.target)
    # True upsert by the unique `target` column. db.merge() matches on
    # primary key only, and ScopeEntry's PK is a freshly-generated uuid on
    # every construction - so merge() would INSERT a duplicate row and
    # violate the unique(target) constraint on re-authorization. Look the
    # row up by target first instead.
    entry = db.query(ScopeEntry).filter(ScopeEntry.target == target).first()
    if entry is None:
        entry = ScopeEntry(target=target, authorized_by=authorized_by, note=req.note, revoked="false")
        db.add(entry)
    else:
        entry.authorized_by = authorized_by
        entry.note = req.note
        entry.revoked = "false"
    db.commit()
    return {"status": "authorized", "target": target, "authorized_by": authorized_by}


@router.get("")
def list_scope(db: Session = Depends(get_db)):
    return db.query(ScopeEntry).all()


@router.delete("/{target}")
def revoke_scope(target: str, db: Session = Depends(get_db)):
    target = _canonical_target(target)
    entry = db.query(ScopeEntry).filter(ScopeEntry.target == target).first()
    if entry:
        entry.revoked = "true"
        db.commit()
    return {"status": "revoked", "target": target}

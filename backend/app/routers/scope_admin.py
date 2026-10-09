from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ScopeEntry

router = APIRouter(prefix="/scope", tags=["scope"])


class ScopeCreateRequest(BaseModel):
    target: str
    authorized_by: str
    note: str | None = None


@router.post("")
def add_scope_entry(req: ScopeCreateRequest, db: Session = Depends(get_db)):
    # True upsert by the unique `target` column. db.merge() matches on
    # primary key only, and ScopeEntry's PK is a freshly-generated uuid on
    # every construction - so merge() would INSERT a duplicate row and
    # violate the unique(target) constraint on re-authorization. Look the
    # row up by target first instead.
    entry = db.query(ScopeEntry).filter(ScopeEntry.target == req.target).first()
    if entry is None:
        entry = ScopeEntry(target=req.target, authorized_by=req.authorized_by, note=req.note, revoked="false")
        db.add(entry)
    else:
        entry.authorized_by = req.authorized_by
        entry.note = req.note
        entry.revoked = "false"
    db.commit()
    return {"status": "authorized", "target": req.target}


@router.get("")
def list_scope(db: Session = Depends(get_db)):
    return db.query(ScopeEntry).all()


@router.delete("/{target}")
def revoke_scope(target: str, db: Session = Depends(get_db)):
    entry = db.query(ScopeEntry).filter(ScopeEntry.target == target).first()
    if entry:
        entry.revoked = "true"
        db.commit()
    return {"status": "revoked", "target": target}

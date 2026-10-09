from __future__ import annotations

import datetime as dt
import enum
import uuid

from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from .db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    BLOCKED_SCOPE = "blocked_scope"


class TestRun(Base):
    """One execution of one test-module function against one target."""

    __tablename__ = "test_runs"

    id = Column(String, primary_key=True, default=_uuid)
    layer = Column(String, nullable=False)          # e.g. "layer5_api"
    module_id = Column(String, nullable=False)       # registry id, e.g. "api.auth.missing_token"
    target = Column(String, nullable=False)          # host:port tested
    status = Column(Enum(RunStatus), default=RunStatus.PENDING, nullable=False)
    started_at = Column(DateTime, default=dt.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    summary = Column(Text, nullable=True)
    raw_output = Column(Text, nullable=True)
    evidence_path = Column(String, nullable=True)

    findings = relationship("Finding", back_populates="run", cascade="all, delete-orphan")


class Finding(Base):
    """A specific vulnerability/weakness surfaced by a TestRun."""

    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=_uuid)
    run_id = Column(String, ForeignKey("test_runs.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(Severity), default=Severity.INFO, nullable=False)
    cwe = Column(String, nullable=True)
    remediation = Column(Text, nullable=True)
    risk_score = Column(Float, default=0.0)

    run = relationship("TestRun", back_populates="findings")


class ScopeEntry(Base):
    """Explicit authorization record. A target not listed here, or listed
    but expired/revoked, cannot be tested, regardless of what a test-run
    request claims."""

    __tablename__ = "scope_entries"

    id = Column(String, primary_key=True, default=_uuid)
    target = Column(String, nullable=False, unique=True)
    authorized_by = Column(String, nullable=False)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    revoked = Column(String, default="false")  # "true"/"false" (kept simple for sqlite)

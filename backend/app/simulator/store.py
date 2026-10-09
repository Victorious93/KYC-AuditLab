from __future__ import annotations

import datetime as dt
import threading
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class VerificationSession:
    id: str
    identity_key: str  # e.g. hash of document number, for correlation
    created_at: dt.datetime
    expires_at: dt.datetime
    state: str = "created"  # created -> document_submitted -> face_submitted -> liveness_submitted -> decided
    document_valid: Optional[bool] = None
    face_match_score: Optional[float] = None
    liveness_passed: Optional[bool] = None
    decision: Optional[str] = None  # "approved" | "rejected"
    token: str = field(default_factory=lambda: uuid.uuid4().hex)
    used_nonces: List[str] = field(default_factory=list)


class SimulatorStore:
    """Thread-safe in-memory store. Reset between test runs via /admin/reset.
    This is a *test fixture*, not a production datastore - intentionally
    simple and fully resettable."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.sessions: Dict[str, VerificationSession] = {}
        self.submission_log: List[dict] = []  # for rate-limit / fraud checks
        self.audit_events: List[dict] = []

    def reset(self) -> None:
        with self._lock:
            self.sessions.clear()
            self.submission_log.clear()
            self.audit_events.clear()

    def create_session(self, identity_key: str, ttl_seconds: int) -> VerificationSession:
        now = dt.datetime.utcnow()
        sess = VerificationSession(
            id=uuid.uuid4().hex,
            identity_key=identity_key,
            created_at=now,
            expires_at=now + dt.timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self.sessions[sess.id] = sess
        self.log_event("session_created", sess.id, {"identity_key": identity_key})
        return sess

    def get(self, session_id: str) -> Optional[VerificationSession]:
        return self.sessions.get(session_id)

    def is_expired(self, sess: VerificationSession) -> bool:
        return dt.datetime.utcnow() > sess.expires_at

    def log_event(self, kind: str, session_id: str, data: dict) -> None:
        self.audit_events.append(
            {
                "ts": dt.datetime.utcnow().isoformat(),
                "kind": kind,
                "session_id": session_id,
                "data": data,
            }
        )

    def record_submission(self, identity_key: str) -> None:
        self.submission_log.append({"ts": dt.datetime.utcnow(), "identity_key": identity_key})

    def submissions_in_last_hour(self, identity_key: str) -> int:
        cutoff = dt.datetime.utcnow() - dt.timedelta(hours=1)
        return sum(1 for s in self.submission_log if s["identity_key"] == identity_key and s["ts"] >= cutoff)


store = SimulatorStore()

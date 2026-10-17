from __future__ import annotations

import datetime as dt
import hmac
import secrets
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
    # Server-issued liveness challenge (single-use). Never taken from the client.
    liveness_challenge: Optional[str] = None
    liveness_challenge_expires_at: Optional[dt.datetime] = None


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

    def issue_liveness_challenge(self, sess: VerificationSession, ttl_seconds: int) -> str:
        """Issue (or replace) the session's single-use liveness challenge."""
        nonce = "CHAL-" + secrets.token_hex(12)
        with self._lock:
            sess.liveness_challenge = nonce
            sess.liveness_challenge_expires_at = dt.datetime.utcnow() + dt.timedelta(seconds=ttl_seconds)
        return nonce

    def consume_liveness_challenge(self, sess: VerificationSession, response: str) -> str:
        """Atomically consume the session's challenge and grade `response`.
        Returns "ok" | "missing" | "expired" | "replayed" | "mismatch". The
        stored challenge is cleared on EVERY attempt, so each challenge can be
        answered at most once, right or wrong."""
        with self._lock:
            expected = sess.liveness_challenge
            expires = sess.liveness_challenge_expires_at
            sess.liveness_challenge = None
            sess.liveness_challenge_expires_at = None
            if expected is not None:
                sess.used_nonces.append(expected)
        if expected is None:
            return "replayed" if response in sess.used_nonces else "missing"
        if expires is None or dt.datetime.utcnow() > expires:
            return "expired"
        if not hmac.compare_digest(expected.encode(), str(response).encode()):
            return "mismatch"
        return "ok"

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

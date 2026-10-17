"""
Local-first KYC simulator.

This is the ONLY system this framework targets out of the box. It mimics
the shape of a real identity-verification backend (session -> document ->
face -> liveness -> decision) closely enough that Layers 5-7 tests exercise
realistic logic, while staying entirely synthetic and local.

VULNERABLE_MODE (default: on, for demo/eval purposes - toggle with
IDENTITYSHIELD_SIM_VULNERABLE=false) intentionally leaves in ONE class of
flaw per layer (for liveness: honoring a client-supplied
`client_asserts_live`; the challenge itself is server-issued, stored and
single-use in BOTH modes) so the framework's own tests have something real to find
and the project can demonstrate (not just claim) detection. This mirrors
how projects like OWASP Juice Shop / DVWA work: a deliberately-flawed local
target, never a third-party system.
"""
from __future__ import annotations

import os
import re
import time
from collections import deque
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from ..auth import require_admin
from .policies import DEFAULT_POLICY
from .store import store

router = APIRouter(prefix="/simulator", tags=["simulator"])

VULNERABLE_MODE = os.getenv("IDENTITYSHIELD_SIM_VULNERABLE", "true").lower() == "true"

# --- naive in-memory rate limiting (per process) ---------------------------
_rate_window: Dict[str, deque] = {}


def _rate_limited(key: str) -> bool:
    now = time.time()
    window = _rate_window.setdefault(key, deque())
    while window and now - window[0] > 60:
        window.popleft()
    window.append(now)
    return len(window) > DEFAULT_POLICY.rate_limit_per_minute


# --- schemas -----------------------------------------------------------------
class CreateSessionRequest(BaseModel):
    identity_key: str


class DocumentSubmission(BaseModel):
    session_id: str
    document_number: str
    document_type: str
    expiry_date: str  # YYYY-MM-DD


class FaceSubmission(BaseModel):
    session_id: str
    match_score: float  # [0,1] - synthetic matcher output, not a real image pipeline


class LivenessChallengeRequest(BaseModel):
    session_id: str


class LivenessSubmission(BaseModel):
    session_id: str
    challenge_response: str
    # DEPRECATED and IGNORED in both modes. The expected challenge is issued
    # and stored server-side (POST /simulator/liveness/challenge); a value the
    # client sends here is never compared against. Accepted only so older
    # clients don't get a 422, and so tests can prove it is ignored.
    expected_challenge: Optional[str] = None
    # VULNERABLE_MODE flaw lives here: client_asserts_live lets a caller try
    # to self-report liveness. A correctly-hardened target must ignore this
    # field server-side; our "hardened" (non-vulnerable) path does exactly
    # that, and the Layer 6 test below asserts it is ignored.
    client_asserts_live: Optional[bool] = None


class DecisionOverrideAttempt(BaseModel):
    session_id: str
    desired_decision: str  # what a malicious client would *try* to force


# --- document validation (Layer 1 target surface) --------------------------
_DOC_NUMBER_RE = re.compile(r"^[A-Z0-9]{6,12}$")


def _document_is_well_formed(doc: DocumentSubmission) -> bool:
    if not _DOC_NUMBER_RE.match(doc.document_number):
        return False
    if doc.document_type not in {"passport", "drivers_license", "national_id"}:
        return False
    try:
        import datetime as dt

        expiry = dt.date.fromisoformat(doc.expiry_date)
    except ValueError:
        return False
    import datetime as dt

    return expiry >= dt.date.today()


@router.post("/session")
def create_session(req: CreateSessionRequest):
    if _rate_limited(f"session:{req.identity_key}"):
        raise HTTPException(status_code=429, detail="rate limited")
    sess = store.create_session(req.identity_key, DEFAULT_POLICY.session_ttl_seconds)
    return {"session_id": sess.id, "token": sess.token, "expires_at": sess.expires_at.isoformat()}


def _authorize(session_id: str, authorization: Optional[str]):
    sess = store.get(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="unknown session")
    if store.is_expired(sess):
        raise HTTPException(status_code=410, detail="session expired")
    expected = f"Bearer {sess.token}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="invalid or missing session token")
    return sess


@router.post("/document")
def submit_document(payload: DocumentSubmission, authorization: Optional[str] = Header(default=None)):
    sess = _authorize(payload.session_id, authorization)
    if sess.state != "created":
        if not DEFAULT_POLICY.allow_duplicate_submission:
            raise HTTPException(status_code=409, detail="document already submitted for this session")

    valid = _document_is_well_formed(payload)
    if DEFAULT_POLICY.reject_malformed_documents and not valid:
        store.log_event("document_rejected", sess.id, {"reason": "malformed"})
        raise HTTPException(status_code=422, detail="document failed validation")

    if store.submissions_in_last_hour(sess.identity_key) >= DEFAULT_POLICY.max_submissions_per_identity_per_hour:
        store.log_event("submission_velocity_block", sess.id, {})
        raise HTTPException(status_code=429, detail="too many submissions for this identity")

    store.record_submission(sess.identity_key)
    sess.document_valid = valid
    sess.state = "document_submitted"
    store.log_event("document_submitted", sess.id, {"document_type": payload.document_type})
    return {"status": "document_submitted", "valid": valid}


@router.post("/face")
def submit_face(payload: FaceSubmission, authorization: Optional[str] = Header(default=None)):
    sess = _authorize(payload.session_id, authorization)
    if DEFAULT_POLICY.require_sequential_steps and sess.state != "document_submitted":
        raise HTTPException(status_code=409, detail="document must be submitted before face")

    score = max(0.0, min(1.0, payload.match_score))
    sess.face_match_score = score
    sess.state = "face_submitted"
    store.log_event("face_submitted", sess.id, {"score": score})
    return {"status": "face_submitted", "score": score, "threshold": DEFAULT_POLICY.min_face_match_score}


@router.post("/liveness/challenge")
def issue_liveness_challenge(payload: LivenessChallengeRequest, authorization: Optional[str] = Header(default=None)):
    """Issue a fresh, single-use liveness challenge for this session. The
    server keeps it; /liveness grades the response against the stored value
    only. Requesting a new challenge invalidates the previous one."""
    sess = _authorize(payload.session_id, authorization)
    if DEFAULT_POLICY.require_sequential_steps and sess.state != "face_submitted":
        raise HTTPException(status_code=409, detail="face must be submitted before requesting a liveness challenge")
    ttl = DEFAULT_POLICY.liveness_challenge_ttl_seconds
    challenge = store.issue_liveness_challenge(sess, ttl)
    store.log_event("liveness_challenge_issued", sess.id, {"ttl_seconds": ttl})  # value deliberately not logged
    return {"challenge": challenge, "expires_in": ttl}


@router.post("/liveness")
def submit_liveness(payload: LivenessSubmission, authorization: Optional[str] = Header(default=None)):
    sess = _authorize(payload.session_id, authorization)
    if DEFAULT_POLICY.require_sequential_steps and sess.state != "face_submitted":
        raise HTTPException(status_code=409, detail="face must be submitted before liveness")

    # Graded ONLY against the server-issued, stored challenge (both modes);
    # payload.expected_challenge is ignored. Consumed on every attempt.
    challenge_status = store.consume_liveness_challenge(sess, payload.challenge_response)
    challenge_ok = challenge_status == "ok"

    if VULNERABLE_MODE and payload.client_asserts_live is True:
        # Intentional flaw: trusts a client-supplied liveness assertion
        # instead of only the server-evaluated challenge. This exists so
        # Layer 6 (workflow/session security) tests have a real, local,
        # reproducible "client-controlled value changes a server decision"
        # bug to detect - never used against anything but this simulator.
        passed = True
    else:
        passed = challenge_ok

    sess.liveness_passed = passed
    sess.state = "liveness_submitted"
    store.log_event(
        "liveness_submitted",
        sess.id,
        {"passed": passed, "challenge_status": challenge_status, "vulnerable_mode": VULNERABLE_MODE},
    )
    return {"status": "liveness_submitted", "passed": passed, "challenge_status": challenge_status}


@router.post("/decision")
def get_decision(payload: DecisionOverrideAttempt, authorization: Optional[str] = Header(default=None)):
    sess = _authorize(payload.session_id, authorization)
    if sess.state != "liveness_submitted":
        raise HTTPException(status_code=409, detail="verification workflow incomplete")

    server_decision = (
        "approved"
        if (
            sess.document_valid
            and (sess.face_match_score or 0) >= DEFAULT_POLICY.min_face_match_score
            and sess.liveness_passed
        )
        else "rejected"
    )
    sess.decision = server_decision
    sess.state = "decided"
    store.log_event(
        "decision",
        sess.id,
        {"server_decision": server_decision, "client_requested": payload.desired_decision},
    )
    # NOTE: payload.desired_decision is intentionally logged and NEVER used
    # to compute server_decision. Layer 6 tests assert exactly this.
    return {"decision": server_decision}


@router.get("/audit/{session_id}")
def get_audit_trail(session_id: str):
    return {"events": [e for e in store.audit_events if e["session_id"] == session_id]}


# Admin-only control endpoint. The KYC flow routes above are deliberately
# left unauthenticated at this layer: they are lab targets.
@router.post("/admin/reset", dependencies=[Depends(require_admin)])
def admin_reset():
    store.reset()
    return {"status": "reset"}

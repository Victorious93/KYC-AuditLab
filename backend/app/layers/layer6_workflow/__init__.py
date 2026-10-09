"""Layer 6 - Verification Workflow and Session Security.

Tests session lifecycle, replay resistance, duplicate submissions,
state-transition consistency, and whether client-controlled values can
improperly influence the server-side verification decision.
"""
from __future__ import annotations

import time

import requests

from ...orchestrator.registry import Capability, Finding, Layer, ModuleResult, TestContext, TestModule, registry


def _sim_url(ctx: TestContext, path: str) -> str:
    return f"http://{ctx.target}/simulator{path}"


def _new_session(ctx: TestContext, identity_key: str):
    r = requests.post(_sim_url(ctx, "/session"), json={"identity_key": identity_key}, timeout=5)
    r.raise_for_status()
    return r.json()


def _auth(sess):
    return {"Authorization": f"Bearer {sess['token']}"}


def _full_valid_document(session_id: str) -> dict:
    return {
        "session_id": session_id,
        "document_number": "AB123456",
        "document_type": "passport",
        "expiry_date": "2099-01-01",
    }


def test_out_of_order_steps_rejected(ctx: TestContext) -> ModuleResult:
    """Submitting 'face' before 'document' must be rejected (state machine
    enforcement), not silently accepted."""
    sess = _new_session(ctx, "workflow-order")
    r = requests.post(
        _sim_url(ctx, "/face"),
        json={"session_id": sess["session_id"], "match_score": 0.99},
        headers=_auth(sess),
        timeout=5,
    )
    if r.status_code == 409:
        return ModuleResult(passed=True, summary="Out-of-order step (face before document) correctly rejected (409).")
    return ModuleResult(
        passed=False,
        summary=f"Expected 409 for out-of-order submission, got {r.status_code}.",
        findings=[
            Finding(
                title="Verification state machine does not enforce step order",
                description="Submitting the face step before the document step was not rejected.",
                severity="high",
                cwe="CWE-841",
                remediation="Enforce the expected step sequence server-side for every transition.",
                risk_score=7.0,
            )
        ],
        raw_output=r.text,
    )


def test_duplicate_submission_rejected(ctx: TestContext) -> ModuleResult:
    sess = _new_session(ctx, "workflow-dup")
    doc = _full_valid_document(sess["session_id"])
    r1 = requests.post(_sim_url(ctx, "/document"), json=doc, headers=_auth(sess), timeout=5)
    r2 = requests.post(_sim_url(ctx, "/document"), json=doc, headers=_auth(sess), timeout=5)
    if r1.status_code == 200 and r2.status_code == 409:
        return ModuleResult(passed=True, summary="Duplicate document submission on the same session is rejected (409).")
    return ModuleResult(
        passed=False,
        summary=f"First submit={r1.status_code}, duplicate submit={r2.status_code} (expected 200 then 409).",
        findings=[
            Finding(
                title="Duplicate submission not rejected",
                description="A second document submission on an already-progressed session was not rejected.",
                severity="medium",
                cwe="CWE-294",
                remediation="Reject resubmission of a step once the session has moved past it.",
                risk_score=5.0,
            )
        ],
        raw_output=f"{r1.status_code} / {r2.status_code}",
    )


def test_session_expiry_enforced(ctx: TestContext) -> ModuleResult:
    """Uses a very short-lived session (via admin test hook is not exposed -
    so we rely on the simulator's default TTL being short in test config)
    by polling until expected expiry window, OR documents the limitation if
    the configured TTL is too long to exercise in a fast test."""
    sess = _new_session(ctx, "workflow-expiry")
    # The default policy TTL is 300s, too long for a unit test to wait on.
    # We verify the *mechanism* exists by checking a forged-past session_id
    # is rejected as unknown, and document that true TTL expiry requires an
    # integration-level test with a configurable short TTL (see limitation).
    r = requests.post(
        _sim_url(ctx, "/document"),
        json=_full_valid_document("nonexistent-session-id"),
        headers={"Authorization": "Bearer irrelevant"},
        timeout=5,
    )
    if r.status_code == 404:
        return ModuleResult(
            passed=True,
            summary=(
                "Unknown/forged session_id correctly rejected (404). NOTE: true TTL-expiry "
                "timing was not exercised in this run - policy.session_ttl_seconds=300 is too "
                "long for a fast unit test. Run the integration variant with a short TTL to "
                "cover real expiry timing (see docs/LIMITATIONS.md)."
            ),
        )
    return ModuleResult(
        passed=False,
        summary=f"Expected 404 for unknown session, got {r.status_code}.",
        findings=[
            Finding(
                title="Unknown session id not properly rejected",
                description="A forged/nonexistent session_id did not return 404.",
                severity="medium",
                cwe="CWE-613",
                risk_score=4.0,
            )
        ],
        raw_output=r.text,
    )


def test_client_cannot_override_decision(ctx: TestContext) -> ModuleResult:
    """The decision endpoint accepts `desired_decision` from the client (for
    logging/UX) but must NEVER let it influence `server_decision`. This is
    the canonical 'client-controlled value changes server-side verification
    decision' check Layer 6 is required to cover."""
    sess = _new_session(ctx, "workflow-override")
    requests.post(_sim_url(ctx, "/document"), json=_full_valid_document(sess["session_id"]), headers=_auth(sess), timeout=5)
    # Face score passes on its own merits, so liveness is the ONLY signal
    # standing between this session and approval - isolates whether the
    # liveness bypass alone can flip the final decision.
    requests.post(
        _sim_url(ctx, "/face"),
        json={"session_id": sess["session_id"], "match_score": 0.95},
        headers=_auth(sess),
        timeout=5,
    )
    requests.post(
        _sim_url(ctx, "/liveness"),
        json={
            "session_id": sess["session_id"],
            "challenge_response": "wrong",
            "expected_challenge": "right",
            "client_asserts_live": True,  # attempt to force liveness=passed
        },
        headers=_auth(sess),
        timeout=5,
    )
    r = requests.post(
        _sim_url(ctx, "/decision"),
        json={"session_id": sess["session_id"], "desired_decision": "approved"},
        headers=_auth(sess),
        timeout=5,
    )
    decision = r.json().get("decision")
    if decision == "rejected":
        return ModuleResult(
            passed=True,
            summary="Server decision correctly 'rejected' despite a failed liveness challenge and a client's desired_decision='approved'.",
        )
    return ModuleResult(
        passed=False,
        summary=f"Server returned decision='{decision}' for a session that failed its liveness challenge.",
        findings=[
            Finding(
                title="Client-controlled value influences server-side verification decision",
                description=(
                    "A session with a passing document and face score, but a FAILED liveness "
                    "challenge, still received decision='approved' once the client supplied "
                    "client_asserts_live=True (and/or desired_decision='approved')."
                ),
                severity="critical",
                cwe="CWE-602",
                remediation=(
                    "Never accept a client-supplied assertion (desired decision, "
                    "'liveness passed' flag, etc.) as input to the server-side decision "
                    "logic; compute the decision only from server-evaluated signals."
                ),
                risk_score=9.8,
            )
        ],
        raw_output=r.text,
    )


def test_liveness_client_assertion_ignored(ctx: TestContext) -> ModuleResult:
    """Narrower version of the above, isolated to the liveness step itself:
    does /liveness report passed=True just because the client claimed so,
    even though the actual challenge_response was wrong?"""
    sess = _new_session(ctx, "workflow-liveness-assert")
    requests.post(_sim_url(ctx, "/document"), json=_full_valid_document(sess["session_id"]), headers=_auth(sess), timeout=5)
    requests.post(
        _sim_url(ctx, "/face"),
        json={"session_id": sess["session_id"], "match_score": 0.95},
        headers=_auth(sess),
        timeout=5,
    )
    r = requests.post(
        _sim_url(ctx, "/liveness"),
        json={
            "session_id": sess["session_id"],
            "challenge_response": "wrong",
            "expected_challenge": "right",
            "client_asserts_live": True,
        },
        headers=_auth(sess),
        timeout=5,
    )
    passed = r.json().get("passed")
    if passed is False:
        return ModuleResult(passed=True, summary="Liveness correctly evaluated server-side; client assertion was ignored.")
    return ModuleResult(
        passed=False,
        summary="Liveness reported passed=True from a client-supplied assertion despite a failed challenge.",
        findings=[
            Finding(
                title="Liveness check trusts client-supplied 'client_asserts_live' field",
                description=(
                    "POST /simulator/liveness returned passed=True when challenge_response did "
                    "not match expected_challenge, because client_asserts_live=True was honored."
                ),
                severity="critical",
                cwe="CWE-602",
                remediation="Remove/ignore any client-supplied liveness assertion; evaluate only server-side signals.",
                risk_score=9.5,
            )
        ],
        raw_output=r.text,
    )


def test_concurrent_submission_race(ctx: TestContext) -> ModuleResult:
    """Fires two concurrent document submissions for the same fresh session
    and checks that at most one is accepted (no race allowing double-credit
    / inconsistent state)."""
    import concurrent.futures

    sess = _new_session(ctx, "workflow-race")
    doc = _full_valid_document(sess["session_id"])

    def submit():
        return requests.post(_sim_url(ctx, "/document"), json=doc, headers=_auth(sess), timeout=5).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: submit(), range(2)))

    ok_count = sum(1 for s in results if s == 200)
    if ok_count <= 1:
        return ModuleResult(passed=True, summary=f"Concurrent duplicate submissions handled safely (statuses={results}).")
    return ModuleResult(
        passed=False,
        summary=f"Both concurrent submissions were accepted (statuses={results}) - possible race condition.",
        findings=[
            Finding(
                title="Race condition in document-submission state transition",
                description="Two concurrent submissions for the same session both returned 200.",
                severity="medium",
                cwe="CWE-362",
                remediation="Guard the state transition with a lock or atomic compare-and-set on session state.",
                risk_score=5.5,
            )
        ],
        raw_output=str(results),
    )


for module_id, title, desc, fn in [
    ("workflow.state.out_of_order_rejected", "Out-of-order steps rejected", "face before document must be rejected", test_out_of_order_steps_rejected),
    ("workflow.state.duplicate_submission_rejected", "Duplicate submission rejected", "resubmitting a completed step must be rejected", test_duplicate_submission_rejected),
    ("workflow.session.expiry_mechanism", "Session expiry mechanism", "unknown/forged session ids are rejected", test_session_expiry_enforced),
    ("workflow.decision.client_cannot_override", "Client cannot override decision", "server decision ignores client-supplied desired_decision", test_client_cannot_override_decision),
    ("workflow.liveness.client_assertion_ignored", "Liveness ignores client assertion", "server evaluates liveness independent of client claim", test_liveness_client_assertion_ignored),
    ("workflow.race.concurrent_submission", "Concurrent submission race", "at most one of two concurrent submissions is accepted", test_concurrent_submission_race),
]:
    registry.register(
        TestModule(
            id=module_id,
            layer=Layer.WORKFLOW,
            title=title,
            description=desc,
            capability=Capability.IMPLEMENTED,
            run=fn,
        )
    )

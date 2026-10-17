"""Layer 7 - Fraud Detection and Security Monitoring.

Drives synthetic anomaly scenarios (identity reuse, submission velocity,
device correlation via a synthetic device-id) through the simulator and
checks whether its configured monitoring signals (submission-velocity
blocking, audit trail completeness) correctly flag the suspicious pattern.
"""
from __future__ import annotations

import requests

from ...orchestrator.registry import Capability, Finding, Layer, ModuleResult, TestContext, TestModule, registry


def _sim_url(ctx: TestContext, path: str) -> str:
    # Built from the scope-validated host/port, never the raw target string.
    return ctx.url(f"/simulator{path}")


def test_identity_reuse_velocity_flagged(ctx: TestContext) -> ModuleResult:
    """Submits more document attempts for the SAME identity_key than the
    configured policy allows within an hour, and checks the simulator's
    velocity control actually trips (429) rather than silently allowing
    unlimited retries for one identity."""
    identity_key = "fraud-reuse-identity"
    statuses = []
    for i in range(6):  # policy default max is 3/hour
        r = requests.post(_sim_url(ctx, "/session"), json={"identity_key": identity_key}, timeout=5)
        sess = r.json()
        doc_r = requests.post(
            _sim_url(ctx, "/document"),
            json={
                "session_id": sess["session_id"],
                "document_number": "AB123456",
                "document_type": "passport",
                "expiry_date": "2099-01-01",
            },
            headers={"Authorization": f"Bearer {sess['token']}"},
            timeout=5,
        )
        statuses.append(doc_r.status_code)

    if 429 in statuses:
        return ModuleResult(
            passed=True,
            summary=f"Submission-velocity control for a reused identity tripped as expected (statuses={statuses}).",
        )
    return ModuleResult(
        passed=False,
        summary=f"No velocity block observed across 6 submissions for the same identity (statuses={statuses}).",
        findings=[
            Finding(
                title="Identity-reuse / submission-velocity monitoring did not trigger",
                description=(
                    f"6 document submissions for the same identity_key all proceeded past "
                    f"velocity checks (statuses={statuses}); expected a 429 once the "
                    f"configured per-identity hourly limit was exceeded."
                ),
                severity="medium",
                cwe="CWE-799",
                remediation="Verify the velocity-check policy threshold and that it is applied per-identity, not per-session.",
                risk_score=5.0,
            )
        ],
        raw_output=str(statuses),
    )


def test_audit_trail_completeness(ctx: TestContext) -> ModuleResult:
    """Runs a full session lifecycle and confirms every state transition
    produced an audit event - monitoring/forensics is only as good as the
    audit trail underneath it."""
    sess_r = requests.post(_sim_url(ctx, "/session"), json={"identity_key": "fraud-audit-check"}, timeout=5)
    sess = sess_r.json()
    auth = {"Authorization": f"Bearer {sess['token']}"}

    requests.post(
        _sim_url(ctx, "/document"),
        json={"session_id": sess["session_id"], "document_number": "AB123456", "document_type": "passport", "expiry_date": "2099-01-01"},
        headers=auth,
        timeout=5,
    )
    requests.post(_sim_url(ctx, "/face"), json={"session_id": sess["session_id"], "match_score": 0.9}, headers=auth, timeout=5)
    requests.post(
        _sim_url(ctx, "/liveness"),
        json={"session_id": sess["session_id"], "challenge_response": "x", "expected_challenge": "x"},
        headers=auth,
        timeout=5,
    )
    requests.post(_sim_url(ctx, "/decision"), json={"session_id": sess["session_id"], "desired_decision": "approved"}, headers=auth, timeout=5)

    audit = requests.get(_sim_url(ctx, f"/audit/{sess['session_id']}"), timeout=5).json()
    kinds = {e["kind"] for e in audit["events"]}
    expected = {"session_created", "document_submitted", "face_submitted", "liveness_submitted", "decision"}
    missing = expected - kinds

    if not missing:
        return ModuleResult(passed=True, summary=f"All {len(expected)} expected lifecycle events present in the audit trail.")
    return ModuleResult(
        passed=False,
        summary=f"Audit trail missing event kinds: {missing}",
        findings=[
            Finding(
                title="Incomplete audit trail for verification lifecycle",
                description=f"Expected event kinds {expected}, missing {missing}.",
                severity="medium",
                cwe="CWE-778",
                remediation="Ensure every state-changing action emits a durable audit event before returning a response.",
                risk_score=4.5,
            )
        ],
        raw_output=str(audit),
    )


registry.register(
    TestModule(
        id="fraud.velocity.identity_reuse_flagged",
        layer=Layer.FRAUD,
        title="Identity-reuse velocity is flagged",
        description="Repeats submissions for one identity beyond policy limits and checks for a block.",
        capability=Capability.IMPLEMENTED,
        run=test_identity_reuse_velocity_flagged,
    )
)
registry.register(
    TestModule(
        id="fraud.monitoring.audit_trail_completeness",
        layer=Layer.FRAUD,
        title="Audit trail completeness",
        description="Runs a full verification lifecycle and checks every transition is audit-logged.",
        capability=Capability.IMPLEMENTED,
        run=test_audit_trail_completeness,
    )
)

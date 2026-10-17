"""Layer 5 - Network and API Security.

Implemented against the local simulator: authentication/authorization,
transport-assumption checks, input validation, error-handling leakage, and
rate limiting.
"""
from __future__ import annotations

import requests

from ...orchestrator.registry import Capability, Finding, Layer, ModuleResult, TestContext, TestModule, registry


def _sim_url(ctx: TestContext, path: str) -> str:
    # Built from the scope-validated host/port, never the raw target string.
    return ctx.url(f"/simulator{path}")


def _new_session(ctx: TestContext, identity_key: str = "api-test-identity"):
    r = requests.post(_sim_url(ctx, "/session"), json={"identity_key": identity_key}, timeout=5)
    r.raise_for_status()
    return r.json()


def test_missing_auth_rejected(ctx: TestContext) -> ModuleResult:
    sess = _new_session(ctx)
    r = requests.post(
        _sim_url(ctx, "/document"),
        json={
            "session_id": sess["session_id"],
            "document_number": "AB123456",
            "document_type": "passport",
            "expiry_date": "2099-01-01",
        },
        timeout=5,
        # deliberately no Authorization header
    )
    if r.status_code == 401:
        return ModuleResult(passed=True, summary="Endpoint correctly rejects requests with no auth token (401).")
    return ModuleResult(
        passed=False,
        summary=f"Expected 401 for missing auth, got {r.status_code}.",
        findings=[
            Finding(
                title="Missing authentication not enforced",
                description=(
                    f"POST /simulator/document returned {r.status_code} instead of 401 when no "
                    "Authorization header was sent, indicating the endpoint may not consistently "
                    "require a valid session token."
                ),
                severity="high",
                cwe="CWE-306",
                remediation="Require and validate a bearer session token on every state-mutating endpoint.",
                risk_score=7.5,
            )
        ],
        raw_output=r.text,
    )


def test_invalid_token_rejected(ctx: TestContext) -> ModuleResult:
    sess = _new_session(ctx)
    r = requests.post(
        _sim_url(ctx, "/document"),
        json={
            "session_id": sess["session_id"],
            "document_number": "AB123456",
            "document_type": "passport",
            "expiry_date": "2099-01-01",
        },
        headers={"Authorization": "Bearer not-the-real-token"},
        timeout=5,
    )
    if r.status_code == 401:
        return ModuleResult(passed=True, summary="Endpoint correctly rejects an invalid bearer token.")
    return ModuleResult(
        passed=False,
        summary=f"Expected 401 for invalid token, got {r.status_code}.",
        findings=[
            Finding(
                title="Invalid session token accepted",
                description="An incorrect bearer token was not rejected with 401.",
                severity="critical",
                cwe="CWE-287",
                remediation="Validate the session token against the server-issued value for every request.",
                risk_score=9.0,
            )
        ],
        raw_output=r.text,
    )


def test_cross_session_token_isolation(ctx: TestContext) -> ModuleResult:
    """A token issued for session A must not grant access to session B."""
    sess_a = _new_session(ctx, identity_key="victim")
    sess_b = _new_session(ctx, identity_key="attacker")
    r = requests.post(
        _sim_url(ctx, "/document"),
        json={
            "session_id": sess_a["session_id"],
            "document_number": "AB123456",
            "document_type": "passport",
            "expiry_date": "2099-01-01",
        },
        headers={"Authorization": f"Bearer {sess_b['token']}"},
        timeout=5,
    )
    if r.status_code == 401:
        return ModuleResult(passed=True, summary="Tokens are correctly bound to their issuing session.")
    return ModuleResult(
        passed=False,
        summary=f"Session B's token was accepted for session A (status {r.status_code}).",
        findings=[
            Finding(
                title="Session token not bound to session (broken object-level authorization)",
                description=(
                    "A valid token from one verification session was accepted when presented "
                    "against a different session_id, allowing cross-session access."
                ),
                severity="critical",
                cwe="CWE-863",
                remediation="Bind tokens 1:1 to session_id server-side and reject any mismatch.",
                risk_score=9.3,
            )
        ],
        raw_output=r.text,
    )


def test_malformed_input_handling(ctx: TestContext) -> ModuleResult:
    """Fuzz-lite: send structurally invalid JSON/field types and confirm the
    API fails closed (4xx) rather than 500ing or leaking a stack trace."""
    sess = _new_session(ctx)
    bad_payloads = [
        {"session_id": sess["session_id"], "document_number": None, "document_type": "passport", "expiry_date": "2099-01-01"},
        {"session_id": sess["session_id"], "document_number": "A" * 5000, "document_type": "passport", "expiry_date": "2099-01-01"},
        {"session_id": 12345, "document_number": "AB123456", "document_type": "passport", "expiry_date": "not-a-date"},
    ]
    leaks = []
    for payload in bad_payloads:
        r = requests.post(
            _sim_url(ctx, "/document"),
            json=payload,
            headers={"Authorization": f"Bearer {sess['token']}"},
            timeout=5,
        )
        if r.status_code >= 500 or "Traceback" in r.text:
            leaks.append({"payload": payload, "status": r.status_code, "body": r.text[:300]})

    if not leaks:
        return ModuleResult(passed=True, summary="All malformed-input cases failed closed with 4xx, no stack traces.")
    return ModuleResult(
        passed=False,
        summary=f"{len(leaks)} malformed-input case(s) caused a 5xx or leaked internals.",
        findings=[
            Finding(
                title="Malformed input causes server error / information disclosure",
                description=f"Payloads causing 5xx or traceback leakage: {leaks}",
                severity="medium",
                cwe="CWE-20",
                remediation="Validate input types/lengths at the API boundary; return generic 4xx errors; disable debug tracebacks.",
                risk_score=5.5,
            )
        ],
        raw_output=str(leaks),
    )


def test_rate_limiting_enforced(ctx: TestContext) -> ModuleResult:
    """Bursts session-creation requests for the SAME identity to confirm
    the configured per-identity rate limit actually trips."""
    statuses = []
    for _ in range(40):
        r = requests.post(_sim_url(ctx, "/session"), json={"identity_key": "rate-limit-burst"}, timeout=5)
        statuses.append(r.status_code)
    if 429 in statuses:
        return ModuleResult(passed=True, summary="Rate limiting kicked in during a same-identity burst of 40 requests in <60s.")
    return ModuleResult(
        passed=False,
        summary="No 429 observed after 40 rapid requests for one identity; rate limiting may be absent or too permissive.",
        findings=[
            Finding(
                title="No rate limiting observed on session creation",
                description="40 rapid session-creation requests for the same identity all succeeded without a 429.",
                severity="medium",
                cwe="CWE-770",
                remediation="Enforce per-identity and per-IP rate limits on session/document creation endpoints.",
                risk_score=4.5,
            )
        ],
        raw_output=str(statuses),
    )


def test_rate_limit_bypass_via_identity_rotation(ctx: TestContext) -> ModuleResult:
    """Real finding, not a tuning artifact: the simulator's rate limiter is
    keyed purely by client-supplied identity_key, so rotating that value on
    every request bypasses it entirely. This mirrors a common real-world
    API flaw where throttling keys on a client-controlled field instead of
    a server-trusted one (authenticated user id, IP, device fingerprint)."""
    statuses = []
    for i in range(40):
        r = requests.post(_sim_url(ctx, "/session"), json={"identity_key": f"rotated-{i}"}, timeout=5)
        statuses.append(r.status_code)
    if 429 in statuses:
        return ModuleResult(passed=True, summary="Rate limiting still triggered despite identity rotation.")
    return ModuleResult(
        passed=False,
        summary="Rate limiting was fully bypassed by rotating identity_key on every request.",
        findings=[
            Finding(
                title="Rate limit keyed on client-controlled field, bypassable by rotation",
                description=(
                    "40 session-creation requests, each with a distinct client-supplied "
                    "identity_key, all succeeded with no 429 - the limiter is scoped per-key, "
                    "so an attacker trivially bypasses it by varying the key."
                ),
                severity="medium",
                cwe="CWE-770",
                remediation="Add a limiter keyed on a server-trusted dimension (source IP, device fingerprint, or authenticated caller) in addition to per-identity limits.",
                risk_score=5.0,
            )
        ],
        raw_output=str(statuses),
    )


registry.register(
    TestModule(
        id="api.auth.missing_token_rejected",
        layer=Layer.API,
        title="Missing auth token is rejected",
        description="Confirms state-mutating endpoints reject requests with no Authorization header.",
        capability=Capability.IMPLEMENTED,
        run=test_missing_auth_rejected,
    )
)
registry.register(
    TestModule(
        id="api.auth.invalid_token_rejected",
        layer=Layer.API,
        title="Invalid auth token is rejected",
        description="Confirms an incorrect bearer token is rejected.",
        capability=Capability.IMPLEMENTED,
        run=test_invalid_token_rejected,
    )
)
registry.register(
    TestModule(
        id="api.authz.cross_session_isolation",
        layer=Layer.API,
        title="Session tokens are not cross-usable",
        description="Confirms a token from session A cannot act on session B (BOLA/IDOR check).",
        capability=Capability.IMPLEMENTED,
        run=test_cross_session_token_isolation,
    )
)
registry.register(
    TestModule(
        id="api.input_validation.malformed_payloads",
        layer=Layer.API,
        title="Malformed input fails closed",
        description="Sends structurally invalid payloads and checks for 5xx/stack-trace leakage.",
        capability=Capability.IMPLEMENTED,
        run=test_malformed_input_handling,
    )
)
registry.register(
    TestModule(
        id="api.rate_limit.session_creation",
        layer=Layer.API,
        title="Rate limiting on session creation",
        description="Bursts session-creation requests for one identity and checks for 429 responses.",
        capability=Capability.IMPLEMENTED,
        run=test_rate_limiting_enforced,
    )
)
registry.register(
    TestModule(
        id="api.rate_limit.identity_rotation_bypass",
        layer=Layer.API,
        title="Rate limit bypass via identity rotation",
        description="Checks whether rotating the client-supplied identity_key bypasses rate limiting.",
        capability=Capability.IMPLEMENTED,
        run=test_rate_limit_bypass_via_identity_rotation,
    )
)

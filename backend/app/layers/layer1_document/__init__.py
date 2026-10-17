"""Layer 1 - Identity Document Security.

Exercises the simulator's document-validation surface with clearly-marked
SYNTHETIC test fixtures: malformed numbers, expired dates, wrong types,
oversized fields, and inconsistent metadata. This module never generates
counterfeit credentials - every fixture is a structurally-invalid or
synthetic placeholder value, not an attempt to produce a convincing fake
document.
"""
from __future__ import annotations

import requests

from ...orchestrator.registry import Capability, Finding, Layer, ModuleResult, TestContext, TestModule, registry

# Clearly-synthetic fixtures. None of these resemble a real document number
# format closely enough to be mistaken for an attempt at forgery - they are
# inputs designed to probe validation logic (bad length, bad charset, bad
# dates, type confusion).
SYNTHETIC_MALFORMED_DOCUMENTS = [
    {"document_number": "", "document_type": "passport", "expiry_date": "2099-01-01", "case": "empty_number"},
    {"document_number": "short", "document_type": "passport", "expiry_date": "2099-01-01", "case": "too_short"},
    {"document_number": "has-dashes-$$", "document_type": "passport", "expiry_date": "2099-01-01", "case": "bad_charset"},
    {"document_number": "VALID12345", "document_type": "passport", "expiry_date": "2000-01-01", "case": "expired"},
    {"document_number": "VALID12345", "document_type": "fake_type", "expiry_date": "2099-01-01", "case": "invalid_type"},
    {"document_number": "VALID12345", "document_type": "passport", "expiry_date": "not-a-date", "case": "malformed_date"},
]


def _sim_url(ctx: TestContext, path: str) -> str:
    # Built from the scope-validated host/port, never the raw target string.
    return ctx.url(f"/simulator{path}")


def _new_session(ctx: TestContext, identity_key: str):
    r = requests.post(_sim_url(ctx, "/session"), json={"identity_key": identity_key}, timeout=5)
    r.raise_for_status()
    return r.json()


def test_malformed_documents_rejected(ctx: TestContext) -> ModuleResult:
    accepted_bad = []
    for i, fixture in enumerate(SYNTHETIC_MALFORMED_DOCUMENTS):
        sess = _new_session(ctx, f"doc-fixture-{i}")
        r = requests.post(
            _sim_url(ctx, "/document"),
            json={
                "session_id": sess["session_id"],
                "document_number": fixture["document_number"],
                "document_type": fixture["document_type"],
                "expiry_date": fixture["expiry_date"],
            },
            headers={"Authorization": f"Bearer {sess['token']}"},
            timeout=5,
        )
        if r.status_code == 200 and r.json().get("valid") is True:
            accepted_bad.append({"case": fixture["case"], "status": r.status_code})

    if not accepted_bad:
        return ModuleResult(
            passed=True,
            summary=f"All {len(SYNTHETIC_MALFORMED_DOCUMENTS)} synthetic malformed-document fixtures were correctly rejected or flagged invalid.",
        )
    return ModuleResult(
        passed=False,
        summary=f"{len(accepted_bad)} malformed document fixture(s) were incorrectly accepted as valid.",
        findings=[
            Finding(
                title="Document validation accepts structurally invalid documents",
                description=f"Fixtures incorrectly marked valid: {accepted_bad}",
                severity="high",
                cwe="CWE-20",
                remediation="Tighten document-number, type, and expiry validation; reject on any format/consistency failure.",
                risk_score=7.0,
            )
        ],
        raw_output=str(accepted_bad),
    )


def test_consistent_rejection_reason_not_leaked(ctx: TestContext) -> ModuleResult:
    """Error responses for invalid documents must not leak internal
    validation internals (e.g. regex patterns, stack traces) that would
    help an attacker iterate toward a format that passes validation."""
    sess = _new_session(ctx, "doc-leak-check")
    r = requests.post(
        _sim_url(ctx, "/document"),
        json={"session_id": sess["session_id"], "document_number": "bad!!", "document_type": "passport", "expiry_date": "2099-01-01"},
        headers={"Authorization": f"Bearer {sess['token']}"},
        timeout=5,
    )
    body = r.text.lower()
    leaky_markers = ["traceback", "regex", "re.compile", "_doc_number_re"]
    found = [m for m in leaky_markers if m in body]
    if not found:
        return ModuleResult(passed=True, summary="Validation error response does not leak internal implementation details.")
    return ModuleResult(
        passed=False,
        summary=f"Error response leaked internal markers: {found}",
        findings=[
            Finding(
                title="Validation error response leaks implementation details",
                description=f"Response body contained: {found}",
                severity="low",
                cwe="CWE-209",
                remediation="Return generic validation error messages; never expose internal patterns/stack traces.",
                risk_score=3.0,
            )
        ],
        raw_output=r.text,
    )


registry.register(
    TestModule(
        id="document.validation.malformed_fixtures_rejected",
        layer=Layer.DOCUMENT,
        title="Malformed synthetic documents are rejected",
        description="Submits clearly-synthetic malformed document fixtures and confirms rejection.",
        capability=Capability.IMPLEMENTED,
        run=test_malformed_documents_rejected,
    )
)
registry.register(
    TestModule(
        id="document.validation.error_no_leak",
        layer=Layer.DOCUMENT,
        title="Validation errors do not leak internals",
        description="Confirms document-validation error responses do not expose implementation details.",
        capability=Capability.IMPLEMENTED,
        run=test_consistent_rejection_reason_not_leaked,
    )
)

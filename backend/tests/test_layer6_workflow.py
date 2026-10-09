import os

import pytest

from .helpers import run_module


def test_out_of_order_rejected(live_server):
    r = run_module(live_server, "workflow.state.out_of_order_rejected")
    assert r.status == "pass", r.summary


def test_duplicate_submission_rejected(live_server):
    r = run_module(live_server, "workflow.state.duplicate_submission_rejected")
    assert r.status == "pass", r.summary


def test_session_expiry_mechanism(live_server):
    r = run_module(live_server, "workflow.session.expiry_mechanism")
    assert r.status == "pass", r.summary


def test_concurrent_submission_race(live_server):
    r = run_module(live_server, "workflow.race.concurrent_submission")
    assert r.status == "pass", r.summary


def test_vulnerable_mode_is_detected(live_server):
    """Demonstrates the framework actually DETECTS the intentional flaw when
    the simulator runs in its default vulnerable mode (IDENTITYSHIELD_SIM_
    VULNERABLE=true), rather than merely asserting everything passes. This
    is the "run available tests and report real results" proof for Layer 6."""
    r = run_module(live_server, "workflow.liveness.client_assertion_ignored")
    if os.getenv("IDENTITYSHIELD_SIM_VULNERABLE", "true").lower() == "true":
        assert r.status == "fail", r.summary
        assert r.finding_severities == ["critical"]
    else:
        assert r.status == "pass", r.summary


def test_client_cannot_override_decision_matches_mode(live_server):
    r = run_module(live_server, "workflow.decision.client_cannot_override")
    if os.getenv("IDENTITYSHIELD_SIM_VULNERABLE", "true").lower() == "true":
        assert r.status == "fail", r.summary
    else:
        assert r.status == "pass", r.summary

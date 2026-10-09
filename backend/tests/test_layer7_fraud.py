from .helpers import run_module


def test_identity_reuse_velocity_flagged(live_server):
    r = run_module(live_server, "fraud.velocity.identity_reuse_flagged")
    assert r.status == "pass", r.summary


def test_audit_trail_completeness(live_server):
    r = run_module(live_server, "fraud.monitoring.audit_trail_completeness")
    assert r.status == "pass", r.summary

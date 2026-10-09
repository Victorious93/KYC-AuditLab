from .helpers import run_module


def test_missing_token_rejected(live_server):
    r = run_module(live_server, "api.auth.missing_token_rejected")
    assert r.status == "pass", r.summary


def test_invalid_token_rejected(live_server):
    r = run_module(live_server, "api.auth.invalid_token_rejected")
    assert r.status == "pass", r.summary


def test_cross_session_isolation(live_server):
    r = run_module(live_server, "api.authz.cross_session_isolation")
    assert r.status == "pass", r.summary


def test_malformed_input_handling(live_server):
    r = run_module(live_server, "api.input_validation.malformed_payloads")
    assert r.status == "pass", r.summary


def test_rate_limiting(live_server):
    r = run_module(live_server, "api.rate_limit.session_creation")
    assert r.status == "pass", r.summary


def test_rate_limit_identity_rotation_bypass_is_detected(live_server):
    """The simulator's limiter IS keyed per-identity by design, so rotating
    identity_key really does bypass it - this is a genuine, reproducible
    finding the framework should surface, not a bug to paper over."""
    r = run_module(live_server, "api.rate_limit.identity_rotation_bypass")
    assert r.status == "fail", r.summary
    assert r.finding_severities == ["medium"]

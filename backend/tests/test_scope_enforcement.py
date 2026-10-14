from .helpers import ADMIN_HEADERS, run_module


def test_unscoped_target_is_blocked(live_server):
    """A target that is on the server-side hostname allowlist but has no
    ScopeEntry authorizing it must still be refused."""
    import requests

    requests.delete(f"http://{live_server}/scope/127.0.0.1", headers=ADMIN_HEADERS, timeout=5)
    r = run_module(live_server, "api.auth.missing_token_rejected")
    assert r.status == "blocked_scope", r.summary
    assert "ScopeEntry" in r.summary

    requests.post(
        f"http://{live_server}/scope",
        json={"target": "127.0.0.1", "note": "restore for later tests"},
        headers=ADMIN_HEADERS,
        timeout=5,
    )


def test_non_allowlisted_host_is_blocked(live_server):
    """A target outside the hard, server-side hostname allowlist must be
    refused even with a ScopeEntry, since enforce_local_only is on."""
    import requests

    requests.post(
        f"http://{live_server}/scope",
        json={"target": "evil.example.com", },
        headers=ADMIN_HEADERS,
        timeout=5,
    )
    r = run_module("evil.example.com:8000", "api.auth.missing_token_rejected")
    assert r.status == "blocked_scope", r.summary
    assert "allowlist" in r.summary

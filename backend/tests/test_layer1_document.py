from .helpers import run_module


def test_malformed_documents_rejected(live_server):
    r = run_module(live_server, "document.validation.malformed_fixtures_rejected")
    assert r.status == "pass", r.summary


def test_validation_error_no_leak(live_server):
    r = run_module(live_server, "document.validation.error_no_leak")
    assert r.status == "pass", r.summary

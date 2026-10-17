"""Regression tests for the scope-check vs. request-URL parser differential
(audit F1). Before the fix, `127.0.0.2:18080\\@localhost` passed scope as
`localhost` (urlsplit takes the host after the last '@') while requests /
urllib3 treat '\\' as the end of the authority and connected to
127.0.0.2:18080. Scope now uses ONE strict parser for both the decision and
the URL that is actually requested."""
from __future__ import annotations

import socket
import threading

import pytest
import requests
from urllib3.util import parse_url

from app.orchestrator import scope
from app.orchestrator.registry import TestContext
from app.orchestrator.scope import ParsedTarget, ScopeViolation, parse_target, target_url

from .helpers import ADMIN_HEADERS, run_module

BYPASS_TARGETS = [
    "127.0.0.2:18080\\@localhost",
    "evil.com:80\\@localhost",
    "a\\@localhost",
    "a:80\\@localhost",
    "a\\\\@localhost",
    "a@localhost",
    "user:pw@localhost",
    "http://127.0.0.2:18080\\@localhost/",
    "http://user:pw@localhost:9/",
    "localhost\\",
    "127.0.0.2\\.localhost",
]

MALFORMED_TARGETS = [
    "localhost:99999",
    "localhost:0",
    "localhost:-1",
    "localhost:80:81",
    "local host",
    " localhost",
    "localhost ",
    "localhost\t",
    "localhost\n",
    "localhost\r\nHost: evil",
    "local\x00host",
    "localhost\x7f",
    "lоcalhost",  # Cyrillic 'о'
    "localhost/path",
    "localhost/../x",
    "localhost?x=1",
    "localhost#frag",
    "localhost%2f",
    "localhost;rm",
    "[::1]extra",
    "[fe80::1%25eth0]",
    "127.1",
    "0x7f000001",
    "2130706433",
    "127.0.0.01",
    "ftp://localhost",
    "javascript://localhost",
    "-bad-.example",
    "a..b",
]


@pytest.mark.parametrize("target", BYPASS_TARGETS)
def test_userinfo_and_backslash_targets_rejected(target):
    with pytest.raises(ScopeViolation):
        parse_target(target)


@pytest.mark.parametrize("target", MALFORMED_TARGETS)
def test_malformed_targets_rejected(target):
    with pytest.raises(ScopeViolation):
        parse_target(target)


@pytest.mark.parametrize("target", BYPASS_TARGETS + MALFORMED_TARGETS)
def test_rejected_targets_are_never_allowlisted(target, monkeypatch):
    monkeypatch.setattr(scope.settings, "allowed_targets", ["localhost", "127.0.0.1"])
    assert not scope.is_host_allowlisted(target)


@pytest.mark.parametrize(
    "target,url",
    [
        ("localhost", "http://localhost/simulator/session"),
        ("localhost:8000", "http://localhost:8000/simulator/session"),
        ("LOCALHOST.:8000", "http://localhost:8000/simulator/session"),
        ("127.0.0.1:8000", "http://127.0.0.1:8000/simulator/session"),
        ("[::1]:8000", "http://[::1]:8000/simulator/session"),
        ("::1", "http://[::1]/simulator/session"),
        ("http://127.0.0.1:8000/", "http://127.0.0.1:8000/simulator/session"),
        ("https://example.com", "https://example.com/simulator/session"),
    ],
)
def test_request_url_built_from_parsed_host_port(target, url):
    built = target_url(target, "/simulator/session")
    assert built == url
    # The HTTP client's own parser must agree with the scope parser.
    parsed = parse_target(target)
    u = parse_url(built)
    assert u.auth is None
    assert u.host.strip("[]") == parsed.host
    assert u.port == parsed.port


def test_url_builder_backstop_refuses_mismatch():
    # A ParsedTarget that somehow carries smuggled authority characters must
    # be caught by the urllib3 re-parse before any request is sent.
    with pytest.raises(ScopeViolation):
        ParsedTarget(host="127.0.0.2:18080\\@localhost").url("/x")
    with pytest.raises(ScopeViolation):
        ParsedTarget(host="localhost").url("\\@evil/x")


def test_context_url_uses_scoped_target_not_raw_string():
    ctx = TestContext(
        target="127.0.0.2:18080\\@localhost", db=None, evidence_dir="/tmp", scoped=parse_target("localhost:1")
    )
    assert ctx.url("/simulator/session") == "http://localhost:1/simulator/session"
    raw_ctx = TestContext(target="127.0.0.2:18080\\@localhost", db=None, evidence_dir="/tmp")
    with pytest.raises(ScopeViolation):
        raw_ctx.url("/simulator/session")


@pytest.fixture
def canary():
    """A listener on a NON-allowlisted loopback address. Any connection
    means the scope bypass reached the network."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.2", 0))
    except OSError:
        pytest.skip("127.0.0.2 not bindable on this host")
    srv.listen(5)
    srv.settimeout(0.2)
    hits: list[bytes] = []
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                conn.settimeout(1)
                try:
                    hits.append(conn.recv(4096))
                except OSError:
                    hits.append(b"")

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    yield srv.getsockname()[1], hits
    stop.set()
    t.join(timeout=2)
    srv.close()


def test_end_to_end_bypass_is_blocked_and_never_connects(live_server, canary):
    """Reproduces the audit PoC: allowlist localhost/127.0.0.1, ScopeEntry for
    localhost, then run an HTTP module against `127.0.0.2:<port>\\@localhost`.
    Pre-fix this passed scope and POSTed to the 127.0.0.2 listener."""
    port, hits = canary
    requests.post(
        f"http://{live_server}/scope", json={"target": "localhost", "note": "F1 regression"},
        headers=ADMIN_HEADERS, timeout=5,
    )
    for target in (f"127.0.0.2:{port}\\@localhost", f"127.0.0.2:{port}\\\\@localhost", f"127.0.0.2:{port}@localhost"):
        r = run_module(target, "api.auth.missing_token_rejected")
        assert r.status == "blocked_scope", (target, r.status, r.summary)
    # Control: the plain non-allowlisted address is blocked too.
    r = run_module(f"127.0.0.2:{port}", "api.auth.missing_token_rejected")
    assert r.status == "blocked_scope", r.summary
    assert hits == [], f"scope bypass reached the non-allowlisted listener: {hits!r}"


def test_scope_api_rejects_userinfo_and_backslash(live_server):
    for bad in ("127.0.0.2:18080\\@localhost", "a@localhost"):
        r = requests.post(f"http://{live_server}/scope", json={"target": bad}, headers=ADMIN_HEADERS, timeout=5)
        assert r.status_code == 422, (bad, r.status_code, r.text)

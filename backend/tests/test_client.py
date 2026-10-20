"""Tests for app.client (session-token client for controllers / host tools).

Run only against the in-process app (FastAPI TestClient) or the in-process
uvicorn ``live_server`` on 127.0.0.1 - never a remote host."""
from __future__ import annotations

import json
import logging

import pytest
import requests
from fastapi.testclient import TestClient

from app import auth
from app.auth import hash_key
from app.client import (
    AuthError,
    ClientError,
    ConfigError,
    IdentityShieldClient,
    RateLimited,
    is_loopback_url,
)
from app.client.__main__ import main as cli_main
from app.main import app

from .helpers import ADMIN_KEY, BOTH_KEY, OPERATOR_KEY

TEST_SECRET = "test-session-secret-not-a-real-secret-0123456789"
WRONG = "definitely-not-a-configured-key"
BASE = "http://127.0.0.1"  # TestClient accepts absolute URLs; never leaves the process


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS", ",".join(
        f"{i}:{r}:{hash_key(k)}" for i, r, k in [
            ("test-admin", "admin", ADMIN_KEY),
            ("test-operator", "operator", OPERATOR_KEY),
            ("test-both", "admin+operator", BOTH_KEY)]))
    monkeypatch.delenv("IDENTITYSHIELD_DEV_API_KEYS", raising=False)
    monkeypatch.setenv("IDENTITYSHIELD_SESSION_SECRET", TEST_SECRET)
    monkeypatch.setenv("IDENTITYSHIELD_SESSION_TTL_SECONDS", "600")
    monkeypatch.setenv("IDENTITYSHIELD_AUTH_RATE_LIMIT_MAX", "3")
    monkeypatch.setenv("IDENTITYSHIELD_AUTH_RATE_LIMIT_WINDOW_SECONDS", "60")
    for v in ("IDENTITYSHIELD_API_KEY", "IDENTITYSHIELD_API_URL", "IDENTITYSHIELD_CLIENT_ALLOW_NON_LOOPBACK"):
        monkeypatch.delenv(v, raising=False)


class Clock:
    def __init__(self, t=1_900_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(auth.time, "time", c)  # server side (same process)
    return c


class InProcess:
    """FastAPI TestClient as a requests-style transport (drops ``timeout``,
    which TestClient does not support)."""

    def __init__(self):
        self.tc = TestClient(app)

    def request(self, method, url, headers=None, json=None, timeout=None):
        return self.tc.request(method, url, headers=headers, json=json)


class Recorder:
    """Wraps a transport and records (method, path, headers) of each call."""

    def __init__(self, inner):
        self.inner = inner
        self.calls = []

    def request(self, method, url, headers=None, json=None, timeout=None):
        self.calls.append((method, url.split("://", 1)[1].split("/", 1)[1], dict(headers or {})))
        return self.inner.request(method, url, headers=headers, json=json, timeout=timeout)

    def paths(self):
        return [f"{m} /{p}" for m, p, _ in self.calls]


def _client(key=BOTH_KEY, clock=None, sleep=None, **kw):
    rec = Recorder(InProcess())
    extra = {}
    if clock is not None:
        extra["clock"] = clock
    if sleep is not None:
        extra["sleep"] = sleep
    return IdentityShieldClient(BASE, key, session=rec, **extra, **kw), rec


# --- token exchange & caching -------------------------------------------------

def test_sign_in_returns_identity_and_roles_but_not_token():
    c, _ = _client()
    info = c.sign_in()
    assert info["identity"] == "test-both"
    assert info["roles"] == ["admin", "operator"]
    assert info["token_type"] == "Bearer"
    assert "token" not in info
    assert c.identity == "test-both" and c.roles == ("admin", "operator")
    assert c.token_expires_at is not None


def test_key_only_sent_to_auth_session_and_bearer_everywhere_else():
    c, rec = _client()
    assert len(c.list_modules()) > 0
    c.list_runs()
    c.close()
    assert rec.paths() == ["POST /auth/session", "GET /tests/modules", "GET /results/runs", "POST /auth/logout"]
    for method, path, headers in rec.calls:
        if path == "auth/session":
            assert headers == {"X-API-Key": BOTH_KEY}
        else:
            assert "X-API-Key" not in headers
            assert headers["Authorization"].startswith("Bearer iss1.")


def test_token_is_cached_in_memory():
    c, rec = _client()
    for _ in range(5):
        c.list_modules()
    assert c.sign_in_count == 1
    assert rec.paths().count("POST /auth/session") == 1


def test_refreshes_before_expiry(clock):
    c, rec = _client(clock=clock, refresh_skew_seconds=30)
    c.list_modules()
    clock.t += 600 - 31  # still fresh
    c.list_modules()
    assert c.sign_in_count == 1
    clock.t += 2  # inside the skew window -> proactive refresh
    c.list_modules()
    assert c.sign_in_count == 2
    assert rec.paths().count("POST /auth/session") == 2


def test_reauths_once_on_401_after_server_side_revocation():
    c, rec = _client()
    c.list_modules()
    old = c._token
    # Revoke the token out of band (as if another process signed it out).
    assert TestClient(app).post("/auth/logout", headers={"Authorization": f"Bearer {old}"}).status_code == 200
    assert len(c.list_modules()) > 0
    assert c.sign_in_count == 2 and c._token != old
    assert rec.paths()[-3:] == ["GET /tests/modules", "POST /auth/session", "GET /tests/modules"]


def test_reauth_after_expired_token_server_side(clock):
    # Client thinks the token is fresh (its clock lags) but the server says 401.
    client_clock = Clock(clock.t)
    c, _ = _client(clock=client_clock)
    c.list_modules()
    clock.t += 601  # server: expired
    client_clock.t = clock.t - 1000  # client: still fresh
    assert len(c.list_modules()) > 0
    assert c.sign_in_count == 2


def test_key_rotated_away_raises_auth_error_without_looping(monkeypatch):
    c, rec = _client()
    c.list_modules()
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS", f"test-admin:admin:{hash_key(ADMIN_KEY)}")
    with pytest.raises(AuthError) as ei:
        c.list_modules()
    assert ei.value.status == 401
    assert rec.paths()[-2:] == ["GET /tests/modules", "POST /auth/session"]
    assert rec.paths().count("POST /auth/session") == 2


# --- logout ---------------------------------------------------------------------

def test_close_revokes_token_server_side():
    c, _ = _client()
    c.list_modules()
    token = c._token
    c.close()
    assert c._token is None
    r = TestClient(app).get("/tests/modules", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_context_manager_logs_out_and_close_without_token_is_noop():
    with _client()[0] as c:
        c.list_modules()
        token = c._token
    assert TestClient(app).get("/tests/modules", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    c2, rec = _client()
    c2.close()
    assert rec.calls == []


# --- errors -----------------------------------------------------------------------

def test_wrong_key_raises_auth_error_single_attempt():
    c, rec = _client(key=WRONG)
    with pytest.raises(AuthError) as ei:
        c.list_modules()
    assert ei.value.status == 401
    assert rec.paths() == ["POST /auth/session"]


def test_missing_role_is_403_auth_error_not_reauth():
    c, rec = _client(key=OPERATOR_KEY)
    with pytest.raises(AuthError) as ei:
        c.list_scope()  # admin only
    assert ei.value.status == 403
    assert rec.paths().count("POST /auth/session") == 1


def test_other_http_errors_raise_client_error_with_detail():
    c, _ = _client()
    with pytest.raises(ClientError) as ei:
        c.run_module("no.such.module", "127.0.0.1")
    assert ei.value.status == 404
    assert "no.such.module" in str(ei.value.detail)


def test_sign_in_429_raises_rate_limited_when_retry_after_exceeds_budget(clock):
    for _ in range(3):
        with pytest.raises(AuthError):
            _client(key=WRONG, clock=clock)[0].sign_in()
    slept = []
    c, rec = _client(clock=clock, sleep=slept.append, max_retry_after_seconds=30)
    with pytest.raises(RateLimited) as ei:
        c.sign_in()
    assert ei.value.status == 429 and ei.value.retry_after == 60
    assert slept == [] and rec.paths() == ["POST /auth/session"]


def test_sign_in_429_waits_retry_after_then_succeeds(clock):
    for _ in range(3):
        with pytest.raises(AuthError):
            _client(key=WRONG, clock=clock)[0].sign_in()
    slept = []

    def sleep(s):
        slept.append(s)
        clock.t += s

    c, rec = _client(clock=clock, sleep=sleep, max_retry_after_seconds=120)
    assert len(c.list_modules()) > 0
    assert slept == [60.0]
    assert rec.paths() == ["POST /auth/session", "POST /auth/session", "GET /tests/modules"]


class _Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.content = b"" if body is None else json.dumps(body).encode()

    def json(self):
        return self._body


class _Scripted:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, json=None, timeout=None):
        self.calls.append((method, url, dict(headers or {})))
        return self.responses.pop(0)


def _session_body():
    return {"token": "iss1.x.y", "token_type": "Bearer", "expires_at": "2099-01-01T00:00:00+00:00",
            "identity": "t", "roles": ["operator"]}


def test_request_429_retry_after_honoured_once_then_raises():
    slept = []
    s = _Scripted([_Resp(200, _session_body()), _Resp(429, {"detail": "slow"}, {"Retry-After": "2"}),
                   _Resp(200, [1]), _Resp(429, {}, {"Retry-After": "2"}), _Resp(429, {}, {"Retry-After": "2"})])
    c = IdentityShieldClient(BASE, "k", session=s, sleep=slept.append)
    assert c.get("/x") == [1]
    assert slept == [2.0]
    with pytest.raises(RateLimited):
        c.get("/x")
    assert slept == [2.0, 2.0]


def test_429_without_retry_after_raises_immediately():
    s = _Scripted([_Resp(429, {"detail": "slow"})])
    c = IdentityShieldClient(BASE, "k", session=s, sleep=lambda _: pytest.fail("should not sleep"))
    with pytest.raises(RateLimited) as ei:
        c.sign_in()
    assert ei.value.retry_after is None


def test_transport_error_is_client_error_without_key():
    class Boom:
        def request(self, *a, **k):
            raise requests.ConnectionError(f"boom {k['headers']}")

    c = IdentityShieldClient(BASE, "transport-test-key-not-a-secret", session=Boom())
    with pytest.raises(ClientError) as ei:
        c.sign_in()
    assert "transport-test-key-not-a-secret" not in str(ei.value)
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


# --- configuration / secrecy -----------------------------------------------------

def test_key_from_env_and_missing_key(monkeypatch):
    with pytest.raises(ConfigError):
        IdentityShieldClient(BASE, session=InProcess())
    monkeypatch.setenv("IDENTITYSHIELD_API_KEY", OPERATOR_KEY)
    c = IdentityShieldClient(BASE, session=InProcess())
    assert c.sign_in()["identity"] == "test-operator"
    c.close()


@pytest.mark.parametrize("url,ok", [
    ("http://127.0.0.1:8000", True), ("http://localhost:8000", True), ("http://[::1]:8000", True),
    ("http://127.0.0.5", True), ("http://10.0.0.5:8000", False), ("https://example.com", False),
    ("http://backend:8000", False), ("http://127.0.0.1.example.com", False),
])
def test_loopback_only_by_default(url, ok):
    assert is_loopback_url(url) is ok
    if ok:
        IdentityShieldClient(url, "k", session=object())
    else:
        with pytest.raises(ConfigError):
            IdentityShieldClient(url, "k", session=object())


def test_non_loopback_requires_explicit_opt_in(monkeypatch):
    IdentityShieldClient("http://backend:8000", "k", session=object(), allow_non_loopback=True)
    monkeypatch.setenv("IDENTITYSHIELD_CLIENT_ALLOW_NON_LOOPBACK", "1")
    IdentityShieldClient("http://backend:8000", "k", session=object())
    with pytest.raises(ConfigError):
        IdentityShieldClient("ftp://127.0.0.1", "k", session=object())


def test_key_and_token_never_in_repr_or_logs(caplog):
    caplog.set_level(logging.DEBUG)
    c, _ = _client()
    c.list_modules()
    token = c._token
    text = repr(c) + str(c)
    c.close()
    with pytest.raises(AuthError):
        _client(key=WRONG)[0].sign_in()
    logged = caplog.text + text
    assert BOTH_KEY not in logged and WRONG not in logged and token not in logged
    assert "test-both" in logged  # identity is fine to log


# --- against the in-process uvicorn server over real HTTP (127.0.0.1) ----------

def test_end_to_end_over_http_live_server(live_server):
    with IdentityShieldClient(f"http://{live_server}", BOTH_KEY) as c:
        res = c.run_module("api.auth.missing_token_rejected", live_server)
        assert res["status"] == "passed"
        run = c.get_run(res["run_id"])
        assert run["module_id"] == "api.auth.missing_token_rejected"
        token = c._token
    assert requests.get(f"http://{live_server}/tests/modules",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5).status_code == 401


def test_cli_whoami_and_modules(live_server, monkeypatch, capsys):
    monkeypatch.setenv("IDENTITYSHIELD_API_KEY", BOTH_KEY)
    assert cli_main(["--base-url", f"http://{live_server}", "whoami"]) == 0
    out = capsys.readouterr().out
    body = json.loads(out)
    assert body["identity"] == "test-both" and "token" not in body
    assert BOTH_KEY not in out and "iss1." not in out
    assert cli_main(["--base-url", f"http://{live_server}", "modules"]) == 0
    assert any(m["id"] == "api.auth.missing_token_rejected" for m in json.loads(capsys.readouterr().out))


def test_cli_error_exit_codes(live_server, monkeypatch, capsys):
    base = ["--base-url", f"http://{live_server}"]
    assert cli_main(base + ["whoami"]) == 2  # no key in env
    monkeypatch.setenv("IDENTITYSHIELD_API_KEY", WRONG)
    assert cli_main(base + ["whoami"]) == 3
    monkeypatch.setenv("IDENTITYSHIELD_API_KEY", OPERATOR_KEY)
    assert cli_main(base + ["scope"]) == 3  # 403, admin only
    assert cli_main(base + ["run-get", "no-such-run"]) == 1
    assert cli_main(["--base-url", "http://10.1.2.3:8000", "whoami"]) == 2
    err = capsys.readouterr().err
    assert WRONG not in err and OPERATOR_KEY not in err

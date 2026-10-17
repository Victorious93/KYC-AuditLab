"""Follow-ups to POST /auth/session: failed-attempt rate limiting per client
IP, server-side revocation via POST /auth/logout, and the startup warning for
a missing session secret outside local env."""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app import auth
from app.auth import hash_key
from app.main import app

from .helpers import ADMIN_KEY, BOTH_KEY, OPERATOR_KEY

client = TestClient(app)
TEST_SECRET = "test-session-secret-not-a-real-secret-0123456789"
WRONG = "definitely-not-a-configured-key"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS", ",".join(
        f"{i}:{r}:{hash_key(k)}" for i, r, k in [
            ("test-admin", "admin", ADMIN_KEY),
            ("test-operator", "operator", OPERATOR_KEY),
            ("test-both", "admin+operator", BOTH_KEY)]))
    monkeypatch.delenv("IDENTITYSHIELD_DEV_API_KEYS", raising=False)
    monkeypatch.setenv("IDENTITYSHIELD_SESSION_SECRET", TEST_SECRET)
    monkeypatch.setenv("IDENTITYSHIELD_AUTH_RATE_LIMIT_MAX", "3")
    monkeypatch.setenv("IDENTITYSHIELD_AUTH_RATE_LIMIT_WINDOW_SECONDS", "60")


class Clock:
    def __init__(self, t=1_900_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(auth.time, "time", c)
    return c


def _login(key, c=client):
    return c.post("/auth/session", headers={"X-API-Key": key})


def _token(key=BOTH_KEY):
    r = _login(key)
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _bearer(t):
    return {"Authorization": f"Bearer {t}"}


# --- rate limiting -------------------------------------------------------------

def test_failed_attempts_are_limited_with_429_and_retry_after(clock):
    for _ in range(3):
        assert _login(WRONG).status_code == 401
    r = _login(WRONG)
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "60"
    # Even the correct key is refused while locked out (no oracle).
    assert _login(BOTH_KEY).status_code == 429


def test_missing_key_counts_as_failure(clock):
    for _ in range(3):
        assert client.post("/auth/session").status_code == 401
    assert client.post("/auth/session").status_code == 429


def test_lockout_is_a_sliding_window(clock):
    for i in range(3):
        assert _login(WRONG).status_code == 401
        clock.t += 10  # failures at t0, t0+10, t0+20
    # now t0+30: oldest failure ages out at t0+60
    r = _login(BOTH_KEY)
    assert r.status_code == 429 and r.headers["Retry-After"] == "30"
    clock.t += 30
    assert _login(BOTH_KEY).status_code == 200
    # Only one failure has aged out; one more failure locks again.
    assert _login(WRONG).status_code == 401
    assert _login(WRONG).status_code == 429


def test_successful_logins_are_not_counted(clock):
    for _ in range(10):
        assert _login(BOTH_KEY).status_code == 200
    assert _login(WRONG).status_code == 401


def test_limit_is_per_client_ip(clock):
    other = TestClient(app, client=("10.9.8.7", 50000))
    for _ in range(3):
        _login(WRONG)
    assert _login(WRONG).status_code == 429
    assert _login(BOTH_KEY, other).status_code == 200


def test_x_forwarded_for_is_not_trusted(clock):
    for i in range(3):
        client.post("/auth/session", headers={"X-API-Key": WRONG, "X-Forwarded-For": f"203.0.113.{i}"})
    r = client.post("/auth/session", headers={"X-API-Key": BOTH_KEY, "X-Forwarded-For": "203.0.113.99"})
    assert r.status_code == 429


def test_rate_limit_can_be_disabled(monkeypatch, clock):
    monkeypatch.setenv("IDENTITYSHIELD_AUTH_RATE_LIMIT_MAX", "0")
    for _ in range(20):
        assert _login(WRONG).status_code == 401
    assert _login(BOTH_KEY).status_code == 200


@pytest.mark.parametrize("raw_max,raw_win,exp_max,exp_win", [
    (None, None, 10, 300), ("abc", "xyz", 10, 300), ("-5", "0", 0, 1), ("25", "900", 25, 900),
])
def test_rate_limit_config_parsing(monkeypatch, raw_max, raw_win, exp_max, exp_win):
    for name, raw in [("IDENTITYSHIELD_AUTH_RATE_LIMIT_MAX", raw_max),
                      ("IDENTITYSHIELD_AUTH_RATE_LIMIT_WINDOW_SECONDS", raw_win)]:
        if raw is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, raw)
    assert auth.rate_limit_max() == exp_max
    assert auth.rate_limit_window() == exp_win


def test_unconfigured_server_503_is_not_counted(monkeypatch, clock):
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS", "")
    for _ in range(5):
        assert _login(WRONG).status_code == 503
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS", f"x:admin:{hash_key(BOTH_KEY)}")
    assert _login(BOTH_KEY).status_code == 200


def test_rate_limit_does_not_affect_other_routes(clock):
    t = _token()
    for _ in range(4):
        _login(WRONG)
    assert client.get("/tests/modules", headers=_bearer(t)).status_code == 200
    assert client.get("/tests/modules", headers={"X-API-Key": BOTH_KEY}).status_code == 200


# --- logout / revocation -------------------------------------------------------

def test_logout_revokes_token():
    t = _token()
    assert client.get("/tests/modules", headers=_bearer(t)).status_code == 200
    r = client.post("/auth/logout", headers=_bearer(t))
    assert r.status_code == 200 and r.json() == {"revoked": True}
    assert client.get("/tests/modules", headers=_bearer(t)).status_code == 401
    # A revoked token can't log out again either.
    assert client.post("/auth/logout", headers=_bearer(t)).status_code == 401


def test_logout_only_revokes_that_token():
    t1, t2 = _token(), _token()
    assert t1 != t2
    client.post("/auth/logout", headers=_bearer(t1))
    assert client.get("/tests/modules", headers=_bearer(t2)).status_code == 200
    assert client.get("/tests/modules", headers={"X-API-Key": BOTH_KEY}).status_code == 200


def test_tokens_carry_unique_jti():
    import base64, json
    jtis = set()
    for _ in range(5):
        body = _token().split(".")[1]
        jtis.add(json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))["jti"])
    assert len(jtis) == 5


@pytest.mark.parametrize("headers", [
    {}, {"Authorization": "Bearer garbage"}, {"Authorization": "Bearer "},
    {"X-API-Key": BOTH_KEY},
])
def test_logout_requires_valid_bearer_token(headers):
    assert client.post("/auth/logout", headers=headers).status_code == 401


def test_logout_with_expired_token_is_401():
    entry = auth.load_keys()[0]
    import time
    t, _ = auth.issue_session_token(entry, auth.session_secret(), now=time.time() - 7200)
    assert client.post("/auth/logout", headers=_bearer(t)).status_code == 401


def test_denylist_entries_are_dropped_after_expiry(clock):
    t = _token()
    client.post("/auth/logout", headers=_bearer(t))
    assert auth.revoked_count() == 1
    clock.t += 3600
    assert auth.revoked_count() == 0
    assert client.get("/tests/modules", headers=_bearer(t)).status_code == 401  # expired anyway


def test_token_without_jti_is_rejected():
    import base64, hashlib, hmac, json, time
    entry = [e for e in auth.load_keys() if e.identity == "test-both"][0]
    secret = auth.session_secret()
    p = {"sub": entry.identity, "kfp": auth._key_fingerprint(secret, entry),
         "iat": int(time.time()), "exp": int(time.time()) + 600}
    body = base64.urlsafe_b64encode(json.dumps(p).encode()).rstrip(b"=").decode()
    si = f"iss1.{body}"
    sig = base64.urlsafe_b64encode(hmac.new(secret, si.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert client.get("/tests/modules", headers=_bearer(f"{si}.{sig}")).status_code == 401


def test_cors_preflight_allows_logout():
    r = client.options("/auth/logout", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization"})
    assert r.status_code == 200


# --- startup warning -----------------------------------------------------------

def test_warns_when_secret_unset_outside_local(monkeypatch, caplog):
    monkeypatch.delenv("IDENTITYSHIELD_SESSION_SECRET", raising=False)
    monkeypatch.setenv("IDENTITYSHIELD_ENV", "staging")
    with caplog.at_level(logging.WARNING, logger="app.auth"):
        w = auth.check_session_config()
    assert len(w) == 1 and "IDENTITYSHIELD_SESSION_SECRET is unset" in w[0]
    assert "IDENTITYSHIELD_SESSION_SECRET is unset" in caplog.text


def test_no_warning_in_local_env_without_secret(monkeypatch):
    monkeypatch.delenv("IDENTITYSHIELD_SESSION_SECRET", raising=False)
    monkeypatch.setenv("IDENTITYSHIELD_ENV", "local")
    assert auth.check_session_config() == []


def test_no_warning_with_good_secret_outside_local(monkeypatch):
    monkeypatch.setenv("IDENTITYSHIELD_ENV", "production")
    assert auth.check_session_config() == []


def test_warns_on_short_secret(monkeypatch):
    monkeypatch.setenv("IDENTITYSHIELD_SESSION_SECRET", "short")
    w = auth.check_session_config()
    assert len(w) == 1 and "disabled" in w[0]


def test_startup_runs_the_check(monkeypatch, caplog):
    monkeypatch.delenv("IDENTITYSHIELD_SESSION_SECRET", raising=False)
    monkeypatch.setenv("IDENTITYSHIELD_ENV", "staging")
    with caplog.at_level(logging.WARNING, logger="app.auth"):
        with TestClient(app):
            pass
    assert "IDENTITYSHIELD_SESSION_SECRET is unset" in caplog.text

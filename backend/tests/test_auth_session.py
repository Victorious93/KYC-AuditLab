"""POST /auth/session and Authorization: Bearer session tokens.

The dashboard no longer has an API key baked into its bundle: the operator
types a key at runtime, the dashboard exchanges it here for a short-lived
token and only keeps the token. These tests pin the token's security
properties: signed, expiring, bound to a still-configured key, roles taken
from current config, and unable to mint further tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest
import requests
from fastapi.testclient import TestClient

from app import auth
from app.auth import hash_key
from app.main import app

from .helpers import ADMIN_KEY, BOTH_KEY, OPERATOR_KEY

client = TestClient(app)
TEST_SECRET = "test-session-secret-not-a-real-secret-0123456789"


def _keys_env(*entries):
    return ",".join(f"{i}:{r}:{hash_key(k)}" for i, r, k in entries)


DEFAULT_KEYS = [
    ("test-admin", "admin", ADMIN_KEY),
    ("test-operator", "operator", OPERATOR_KEY),
    ("test-both", "admin+operator", BOTH_KEY),
]


@pytest.fixture(autouse=True)
def _session_env(monkeypatch):
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS", _keys_env(*DEFAULT_KEYS))
    monkeypatch.delenv("IDENTITYSHIELD_DEV_API_KEYS", raising=False)
    monkeypatch.setenv("IDENTITYSHIELD_SESSION_SECRET", TEST_SECRET)
    monkeypatch.delenv("IDENTITYSHIELD_SESSION_TTL_SECONDS", raising=False)


def _login(key):
    return client.post("/auth/session", headers={"X-API-Key": key})


def _token(key=BOTH_KEY):
    r = _login(key)
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _forge(payload, secret=TEST_SECRET, prefix="iss1"):
    body = _b64e(json.dumps(payload).encode())
    si = f"{prefix}.{body}"
    sig = _b64e(hmac.new(secret.encode(), si.encode(), hashlib.sha256).digest())
    return f"{si}.{sig}"


def _payload(token):
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


# --- issuing -----------------------------------------------------------------

def test_exchange_returns_bearer_token_with_identity_roles_and_expiry():
    before = time.time()
    r = _login(BOTH_KEY)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert body["identity"] == "test-both"
    assert body["roles"] == ["admin", "operator"]
    assert body["token"].startswith("iss1.")
    p = _payload(body["token"])
    assert p["sub"] == "test-both"
    assert before - 1 <= p["iat"] <= time.time() + 1
    assert p["exp"] - p["iat"] == 3600


def test_token_does_not_contain_the_key_or_its_hash():
    token = _token(BOTH_KEY)
    decoded = json.dumps(_payload(token))
    for needle in (BOTH_KEY, hash_key(BOTH_KEY)):
        assert needle not in token
        assert needle not in decoded


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "definitely-wrong"}, {"X-API-Key": ""}])
def test_exchange_requires_a_valid_api_key(headers):
    r = client.post("/auth/session", headers=headers)
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == "X-API-Key"


def test_token_cannot_mint_another_token():
    r = client.post("/auth/session", headers=_bearer(_token()))
    assert r.status_code == 401


def test_exchange_fails_closed_without_configured_keys(monkeypatch):
    monkeypatch.delenv("IDENTITYSHIELD_API_KEYS", raising=False)
    assert _login(BOTH_KEY).status_code == 503


# --- using tokens --------------------------------------------------------------

def test_both_role_token_reaches_admin_and_operator_routes():
    h = _bearer(_token(BOTH_KEY))
    assert client.get("/scope", headers=h).status_code == 200
    assert client.get("/results/runs", headers=h).status_code == 200
    assert client.get("/tests/modules", headers=h).status_code == 200


def test_token_roles_are_not_hierarchical():
    admin = _bearer(_token(ADMIN_KEY))
    op = _bearer(_token(OPERATOR_KEY))
    assert client.get("/scope", headers=admin).status_code == 200
    assert client.get("/results/runs", headers=admin).status_code == 403
    assert client.get("/results/runs", headers=op).status_code == 200
    assert client.get("/scope", headers=op).status_code == 403


def test_scope_authorized_by_comes_from_token_identity():
    r = client.post("/scope", json={"target": "token-authz.local", "authorized_by": "spoof"},
                    headers=_bearer(_token(ADMIN_KEY)))
    assert r.status_code == 200, r.text
    assert r.json()["authorized_by"] == "test-admin"


def test_x_api_key_takes_precedence_over_bearer():
    good = _token(BOTH_KEY)
    r = client.get("/scope", headers={**_bearer(good), "X-API-Key": "definitely-wrong"})
    assert r.status_code == 401


@pytest.mark.parametrize("authz", ["Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Token abc", "bearer-ish"])
def test_non_bearer_or_empty_authorization_is_401(authz):
    assert client.get("/scope", headers={"Authorization": authz}).status_code == 401


def test_raw_api_key_as_bearer_is_rejected():
    # Bearer only accepts session tokens; keys go in X-API-Key.
    assert client.get("/scope", headers=_bearer(BOTH_KEY)).status_code == 401


# --- tampering ------------------------------------------------------------------

def _tamper_cases(token):
    prefix, body, sig = token.split(".")
    p = _payload(token)
    flipped = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
    return {
        "bad-signature": f"{prefix}.{body}.{flipped}",
        "no-signature": f"{prefix}.{body}.",
        "two-parts": f"{prefix}.{body}",
        "four-parts": f"{token}.x",
        "wrong-prefix": f"iss2.{body}.{sig}",
        "sub-swapped": f"{prefix}.{_b64e(json.dumps({**p, 'sub': 'test-admin'}).encode())}.{sig}",
        "exp-extended": f"{prefix}.{_b64e(json.dumps({**p, 'exp': p['exp'] + 10**6}).encode())}.{sig}",
        "garbage": "not-a-token",
        "empty-segments": "..",
    }


TAMPER_CASES = ["bad-signature", "no-signature", "two-parts", "four-parts", "wrong-prefix",
                "sub-swapped", "exp-extended", "garbage", "empty-segments"]


def test_tamper_case_list_is_complete():
    assert sorted(_tamper_cases(_token(BOTH_KEY))) == sorted(TAMPER_CASES)


@pytest.mark.parametrize("case", TAMPER_CASES)
def test_tampered_tokens_are_rejected(case):
    token = _tamper_cases(_token(BOTH_KEY))[case]
    assert client.get("/scope", headers=_bearer(token)).status_code == 401


def test_token_signed_with_another_secret_is_rejected(monkeypatch):
    token = _token(BOTH_KEY)
    monkeypatch.setenv("IDENTITYSHIELD_SESSION_SECRET", "a-completely-different-secret-value-xyz-123")
    assert client.get("/scope", headers=_bearer(token)).status_code == 401


def test_forged_token_with_right_secret_but_unknown_fingerprint_is_rejected():
    token = _forge({"sub": "test-both", "kfp": "AAAAAAAAAAAAAAAAAAAAAA", "iat": 0, "exp": int(time.time()) + 600})
    assert client.get("/scope", headers=_bearer(token)).status_code == 401


@pytest.mark.parametrize("bad", [
    {"exp": "9999999999"},
    {"exp": True},
    {"exp": 1.5e10},
    {"exp": None},
])
def test_malformed_claims_are_rejected(bad):
    p = _payload(_token(BOTH_KEY))
    p.update(bad)
    assert client.get("/scope", headers=_bearer(_forge(p))).status_code == 401


@pytest.mark.parametrize("drop", ["sub", "kfp", "exp"])
def test_missing_claims_are_rejected(drop):
    p = _payload(_token(BOTH_KEY))
    p.pop(drop)
    assert client.get("/scope", headers=_bearer(_forge(p))).status_code == 401


def test_non_json_body_with_valid_signature_is_rejected():
    si = "iss1." + _b64e(b"\xff\xfenot json")
    sig = _b64e(hmac.new(TEST_SECRET.encode(), si.encode(), hashlib.sha256).digest())
    assert client.get("/scope", headers=_bearer(f"{si}.{sig}")).status_code == 401


def test_correctly_re_signed_payload_is_accepted():
    # Sanity check for the forging helper: an untampered payload re-signed
    # with the real secret is valid, so the rejections above are meaningful.
    p = _payload(_token(BOTH_KEY))
    assert client.get("/scope", headers=_bearer(_forge(p))).status_code == 200


# --- expiry, revocation, config changes ----------------------------------------

def test_expired_token_is_rejected():
    entry = next(e for e in auth.load_keys() if e.identity == "test-both")
    token, exp = auth.issue_session_token(entry, auth.session_secret(), now=time.time() - 7200)
    assert exp < time.time()
    assert client.get("/scope", headers=_bearer(token)).status_code == 401


def test_token_expires_after_ttl(monkeypatch):
    token = _token(BOTH_KEY)
    exp = _payload(token)["exp"]
    real = time.time
    monkeypatch.setattr(auth.time, "time", lambda: exp - 1)
    assert client.get("/scope", headers=_bearer(token)).status_code == 200
    monkeypatch.setattr(auth.time, "time", lambda: exp)
    assert client.get("/scope", headers=_bearer(token)).status_code == 401
    monkeypatch.setattr(auth.time, "time", real)


def test_removing_the_key_revokes_its_tokens(monkeypatch):
    token = _token(BOTH_KEY)
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS", _keys_env(*DEFAULT_KEYS[:2]))
    assert client.get("/scope", headers=_bearer(token)).status_code == 401


def test_rotating_the_key_revokes_its_tokens(monkeypatch):
    token = _token(BOTH_KEY)
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS",
                       _keys_env(*DEFAULT_KEYS[:2], ("test-both", "admin+operator", "rotated-key-not-a-secret")))
    assert client.get("/scope", headers=_bearer(token)).status_code == 401


def test_renaming_the_identity_revokes_its_tokens(monkeypatch):
    token = _token(BOTH_KEY)
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS",
                       _keys_env(*DEFAULT_KEYS[:2], ("someone-else", "admin+operator", BOTH_KEY)))
    assert client.get("/scope", headers=_bearer(token)).status_code == 401


def test_roles_come_from_current_config_not_the_token(monkeypatch):
    token = _token(BOTH_KEY)
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS",
                       _keys_env(*DEFAULT_KEYS[:2], ("test-both", "operator", BOTH_KEY)))
    h = _bearer(token)
    assert client.get("/results/runs", headers=h).status_code == 200
    assert client.get("/scope", headers=h).status_code == 403


def test_no_keys_configured_fails_closed_for_tokens(monkeypatch):
    token = _token(BOTH_KEY)
    monkeypatch.delenv("IDENTITYSHIELD_API_KEYS", raising=False)
    assert client.get("/scope", headers=_bearer(token)).status_code == 503


def test_dev_key_tokens_die_outside_local_env(monkeypatch):
    monkeypatch.setenv("IDENTITYSHIELD_DEV_API_KEYS", "dev:admin:devkey-for-this-test")
    monkeypatch.setenv("IDENTITYSHIELD_ENV", "local")
    token = _token("devkey-for-this-test")
    assert client.get("/scope", headers=_bearer(token)).status_code == 200
    monkeypatch.setenv("IDENTITYSHIELD_ENV", "production")
    assert client.get("/scope", headers=_bearer(token)).status_code == 401


# --- secret / TTL configuration --------------------------------------------------

def test_short_secret_disables_session_tokens(monkeypatch):
    token = _token(BOTH_KEY)
    monkeypatch.setenv("IDENTITYSHIELD_SESSION_SECRET", "too-short")
    assert _login(BOTH_KEY).status_code == 503
    assert client.get("/scope", headers=_bearer(token)).status_code == 401
    # Plain API keys keep working.
    assert client.get("/scope", headers={"X-API-Key": BOTH_KEY}).status_code == 200


def test_unset_secret_uses_random_per_process_secret(monkeypatch):
    monkeypatch.delenv("IDENTITYSHIELD_SESSION_SECRET", raising=False)
    assert auth.session_secret() == auth._PROCESS_SESSION_SECRET
    assert len(auth._PROCESS_SESSION_SECRET) == 32
    token = _token(BOTH_KEY)
    assert client.get("/scope", headers=_bearer(token)).status_code == 200
    # A token from the configured-secret mode does not validate here.
    monkeypatch.setenv("IDENTITYSHIELD_SESSION_SECRET", TEST_SECRET)
    assert client.get("/scope", headers=_bearer(token)).status_code == 401


@pytest.mark.parametrize("raw,expected", [
    (None, 3600), ("900", 900), ("1", 60), ("0", 60), ("-5", 60),
    ("999999", 43200), ("abc", 3600), ("", 3600),
])
def test_ttl_is_configurable_and_clamped(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("IDENTITYSHIELD_SESSION_TTL_SECONDS", raising=False)
    else:
        monkeypatch.setenv("IDENTITYSHIELD_SESSION_TTL_SECONDS", raw)
    assert auth.session_ttl_seconds() == expected
    p = _payload(_token(BOTH_KEY))
    assert p["exp"] - p["iat"] == expected


# --- over real HTTP, from the dashboard origin -------------------------------------

def test_live_server_dashboard_flow(live_server):
    base = f"http://{live_server}"
    origin = {"Origin": "http://localhost:5173"}
    pre = requests.options(f"{base}/auth/session", headers={
        **origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "x-api-key"}, timeout=5)
    assert pre.status_code == 200
    r = requests.post(f"{base}/auth/session", headers={**origin, "X-API-Key": OPERATOR_KEY}, timeout=5)
    assert r.status_code == 200, r.text
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"
    token = r.json()["token"]
    pre = requests.options(f"{base}/results/runs", headers={
        **origin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"}, timeout=5)
    assert pre.status_code == 200
    assert "authorization" in pre.headers["access-control-allow-headers"].lower()
    g = requests.get(f"{base}/results/runs", headers={**origin, **_bearer(token)}, timeout=5)
    assert g.status_code == 200
    assert requests.get(f"{base}/results/runs", headers=origin, timeout=5).status_code == 401

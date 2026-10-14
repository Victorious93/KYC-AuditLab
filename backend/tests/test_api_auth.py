"""Authentication / authorization tests for the control-plane API."""
from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_key
from app.db import SessionLocal
from app.main import app
from app.models import ScopeEntry

from .helpers import ADMIN_HEADERS, ADMIN_KEY, BOTH_KEY, OPERATOR_HEADERS

client = TestClient(app)
BAD_HEADERS = {"X-API-Key": "definitely-wrong"}

# (method, path, json, required role)
ADMIN_ROUTES = [
    ("post", "/scope", {"target": "auth-test.local", "note": "x"}),
    ("get", "/scope", None),
    ("delete", "/scope/auth-test.local", None),
    ("post", "/simulator/admin/reset", None),
]
OPERATOR_ROUTES = [
    ("get", "/tests/modules", None),
    ("post", "/tests/run", {"module_id": "no.such.module", "target": "127.0.0.1"}),
    ("post", "/tests/run-layer", {"layer": "no_such_layer", "target": "127.0.0.1"}),
    ("get", "/results/runs", None),
    ("get", "/results/runs/does-not-exist", None),
]
ALL_ROUTES = ADMIN_ROUTES + OPERATOR_ROUTES


def _call(method, path, body, headers=None):
    kw = {"headers": headers or {}}
    if body is not None:
        kw["json"] = body
    return getattr(client, method)(path, **kw)


@pytest.mark.parametrize("method,path,body", ALL_ROUTES)
def test_missing_key_is_401(method, path, body):
    r = _call(method, path, body)
    assert r.status_code == 401, r.text
    assert r.headers.get("WWW-Authenticate") == "X-API-Key"


@pytest.mark.parametrize("method,path,body", ALL_ROUTES)
def test_wrong_key_is_401(method, path, body):
    assert _call(method, path, body, BAD_HEADERS).status_code == 401


@pytest.mark.parametrize("method,path,body", ADMIN_ROUTES)
def test_admin_routes_reject_operator_with_403(method, path, body):
    assert _call(method, path, body, OPERATOR_HEADERS).status_code == 403


@pytest.mark.parametrize("method,path,body", OPERATOR_ROUTES)
def test_operator_routes_reject_admin_only_key_with_403(method, path, body):
    assert _call(method, path, body, ADMIN_HEADERS).status_code == 403


@pytest.mark.parametrize("method,path,body", ADMIN_ROUTES)
def test_admin_routes_succeed_with_admin_key(method, path, body):
    assert _call(method, path, body, ADMIN_HEADERS).status_code == 200


@pytest.mark.parametrize(
    "method,path,body,expected",
    [
        ("get", "/tests/modules", None, 200),
        ("get", "/results/runs", None, 200),
        # Authenticated + authorized; these then hit normal 404 handling.
        ("post", "/tests/run", {"module_id": "no.such.module", "target": "127.0.0.1"}, 404),
        ("post", "/tests/run-layer", {"layer": "no_such_layer", "target": "127.0.0.1"}, 404),
        ("get", "/results/runs/does-not-exist", None, 404),
    ],
)
def test_operator_routes_succeed_with_operator_key(method, path, body, expected):
    assert _call(method, path, body, OPERATOR_HEADERS).status_code == expected


def test_multi_role_key_reaches_both_groups():
    h = {"X-API-Key": BOTH_KEY}
    assert client.get("/scope", headers=h).status_code == 200
    assert client.get("/results/runs", headers=h).status_code == 200


def test_authorized_by_comes_from_key_identity_not_client():
    r = client.post(
        "/scope",
        json={"target": "authz-by.local", "authorized_by": "mallory-spoof"},
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 200, r.text
    assert r.json()["authorized_by"] == "test-admin"
    db = SessionLocal()
    try:
        entry = db.query(ScopeEntry).filter(ScopeEntry.target == "authz-by.local").one()
        assert entry.authorized_by == "test-admin"
    finally:
        db.close()

    # Re-authorizing (upsert path) by another identity also overwrites from the key.
    r = client.post("/scope", json={"target": "authz-by.local", "authorized_by": "x"},
                    headers={"X-API-Key": BOTH_KEY})
    assert r.json()["authorized_by"] == "test-both"


def test_simulator_kyc_flow_routes_remain_open():
    r = client.post("/simulator/session", json={"identity_key": "auth-open-check"})
    assert r.status_code == 200
    assert client.get("/health").status_code == 200


def test_fail_closed_when_no_keys_configured(monkeypatch):
    monkeypatch.delenv("IDENTITYSHIELD_API_KEYS", raising=False)
    monkeypatch.delenv("IDENTITYSHIELD_DEV_API_KEYS", raising=False)
    assert client.get("/scope", headers=ADMIN_HEADERS).status_code == 503
    assert client.get("/results/runs", headers=OPERATOR_HEADERS).status_code == 503


def test_malformed_config_entries_fail_closed(monkeypatch):
    monkeypatch.setenv("IDENTITYSHIELD_API_KEYS", "nope,a:superuser:" + hash_key("k") + ",b:admin:nothex")
    monkeypatch.delenv("IDENTITYSHIELD_DEV_API_KEYS", raising=False)
    assert client.get("/scope", headers={"X-API-Key": "k"}).status_code == 503


def test_dev_plaintext_keys_only_in_local_env(monkeypatch):
    monkeypatch.delenv("IDENTITYSHIELD_API_KEYS", raising=False)
    monkeypatch.setenv("IDENTITYSHIELD_DEV_API_KEYS", "dev:admin:devkey")
    monkeypatch.setenv("IDENTITYSHIELD_ENV", "local")
    assert client.get("/scope", headers={"X-API-Key": "devkey"}).status_code == 200
    monkeypatch.setenv("IDENTITYSHIELD_ENV", "production")
    assert client.get("/scope", headers={"X-API-Key": "devkey"}).status_code == 503


def test_hash_helper_matches_sha256():
    assert hash_key(ADMIN_KEY) == hashlib.sha256(ADMIN_KEY.encode()).hexdigest()

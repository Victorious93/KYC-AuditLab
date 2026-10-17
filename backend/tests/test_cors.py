"""Audit F6: the backend had no CORS middleware, so a browser preflight from
the dashboard origin got a 405 and the dashboard could not call the API with
its X-API-Key header. CORS is now an explicit origin allowlist."""
import pytest
import requests

from app.config import DEFAULT_CORS_ORIGINS, get_settings, parse_cors_origins

from .helpers import OPERATOR_HEADERS


def _preflight(live_server, origin, path="/tests/modules", method="GET", headers="x-api-key"):
    return requests.options(
        f"http://{live_server}{path}",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": headers,
        },
        timeout=5,
    )


def test_default_origins_are_the_dashboard_dev_server():
    assert DEFAULT_CORS_ORIGINS == ("http://localhost:5173", "http://127.0.0.1:5173")
    assert get_settings().cors_origins == list(DEFAULT_CORS_ORIGINS)


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5173"])
def test_preflight_from_dashboard_allows_x_api_key(live_server, origin):
    r = _preflight(live_server, origin)
    assert r.status_code == 200, r.text  # was 405 before CORS was configured
    assert r.headers["access-control-allow-origin"] == origin
    assert "x-api-key" in r.headers["access-control-allow-headers"].lower()
    assert "access-control-allow-credentials" not in r.headers


def test_post_preflight_for_run(live_server):
    r = _preflight(live_server, "http://localhost:5173", path="/tests/run", method="POST", headers="x-api-key, content-type")
    assert r.status_code == 200
    assert "POST" in r.headers["access-control-allow-methods"]


def test_actual_request_from_dashboard_origin_gets_acao(live_server):
    r = requests.get(
        f"http://{live_server}/tests/modules",
        headers={**OPERATOR_HEADERS, "Origin": "http://localhost:5173"},
        timeout=5,
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"


@pytest.mark.parametrize("origin", ["http://evil.example", "http://localhost:5174", "null", "http://192.168.1.20:5173"])
def test_other_origins_not_allowed(live_server, origin):
    r = _preflight(live_server, origin)
    assert r.status_code == 400
    assert "access-control-allow-origin" not in r.headers
    g = requests.get(f"http://{live_server}/health", headers={"Origin": origin}, timeout=5)
    assert "access-control-allow-origin" not in g.headers


def test_cors_does_not_bypass_auth(live_server):
    r = requests.get(f"http://{live_server}/tests/modules", headers={"Origin": "http://localhost:5173"}, timeout=5)
    assert r.status_code == 401


@pytest.mark.parametrize("raw", ["*", "http://localhost:5173,*", "https://*.example.com"])
def test_wildcard_origins_refused(raw):
    with pytest.raises(ValueError):
        parse_cors_origins(raw)


@pytest.mark.parametrize("raw", ["localhost:5173", "http://localhost:5173/path", "ftp://x"])
def test_malformed_origins_refused(raw):
    with pytest.raises(ValueError):
        parse_cors_origins(raw)


def test_origin_list_parsing():
    assert parse_cors_origins(" http://a:1 , https://b/ ,,") == ["http://a:1", "https://b"]
    assert parse_cors_origins("") == []

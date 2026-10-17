"""Session-token client for the IdentityShield API (see package docstring).

Key handling rules (enforced here, relied on by docs/CONTROLLER_INTEGRATION.md):

* The API key comes from the caller or ``IDENTITYSHIELD_API_KEY`` at runtime.
  It is kept in memory only (needed to re-authenticate), sent only in the
  ``X-API-Key`` header of ``POST /auth/session``, never written to disk and
  never logged; ``repr()`` masks it.
* The session token is kept in memory only and is never logged.
* Only loopback base URLs (127.0.0.0/8, ::1, ``localhost``) are accepted
  unless the caller explicitly opts in with ``allow_non_loopback=True`` or
  ``IDENTITYSHIELD_CLIENT_ALLOW_NON_LOOPBACK=1`` (e.g. the compose service
  name ``backend``). This is a local lab; do not point it at shared hosts.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlsplit

import requests

log = logging.getLogger(__name__)

ENV_API_KEY = "IDENTITYSHIELD_API_KEY"
ENV_API_URL = "IDENTITYSHIELD_API_URL"
ENV_ALLOW_NON_LOOPBACK = "IDENTITYSHIELD_CLIENT_ALLOW_NON_LOOPBACK"
DEFAULT_API_URL = "http://127.0.0.1:8000"


class ClientError(Exception):
    """An API call failed. ``status`` is the HTTP status (if any)."""

    def __init__(self, message: str, status: Optional[int] = None, detail: Any = None):
        super().__init__(message)
        self.status = status
        self.detail = detail


class ConfigError(ClientError):
    """Missing key, bad base URL, or a non-loopback URL without opt-in."""


class AuthError(ClientError):
    """The API key was rejected (401) or a request was forbidden (403)."""


class RateLimited(ClientError):
    """429 that we did not (or could no longer) wait out. ``retry_after`` is
    the server's Retry-After in seconds (None if absent/unparseable)."""

    def __init__(self, message: str, retry_after: Optional[float]):
        super().__init__(message, status=429)
        self.retry_after = retry_after


def is_loopback_url(url: str) -> bool:
    host = (urlsplit(url).hostname or "").strip().lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _truthy(v: Optional[str]) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None  # HTTP-date form is not used by this server


def _parse_expires_at(value: Any) -> Optional[float]:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()


class IdentityShieldClient:
    """Token-based client. Use as a context manager so the token is revoked::

        with IdentityShieldClient() as c:          # key from IDENTITYSHIELD_API_KEY
            c.list_modules()

    ``session`` may be any object with a ``requests``-style
    ``request(method, url, headers=, json=, timeout=)`` (tests pass a fake).
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        session: Any = None,
        timeout: float = 30.0,
        refresh_skew_seconds: float = 30.0,
        max_retry_after_seconds: float = 30.0,
        allow_non_loopback: Optional[bool] = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        base = (base_url or os.getenv(ENV_API_URL) or DEFAULT_API_URL).rstrip("/")
        parts = urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConfigError(f"invalid base URL {base!r} (expected http(s)://host:port)")
        if allow_non_loopback is None:
            allow_non_loopback = _truthy(os.getenv(ENV_ALLOW_NON_LOOPBACK))
        if not allow_non_loopback and not is_loopback_url(base):
            raise ConfigError(
                f"refusing non-loopback base URL {base!r}: IdentityShield is a local lab. "
                f"Set {ENV_ALLOW_NON_LOOPBACK}=1 only for a trusted local network (e.g. compose)."
            )
        key = api_key if api_key is not None else os.getenv(ENV_API_KEY, "")
        if not key or not key.strip():
            raise ConfigError(f"no API key: pass api_key= or set {ENV_API_KEY} at runtime")

        self.base_url = base
        self.__api_key = key.strip()  # name-mangled; never logged or persisted
        self._session = session if session is not None else requests.Session()
        self._owns_session = session is None
        self._timeout = timeout
        self._skew = refresh_skew_seconds
        self._max_wait = max_retry_after_seconds
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.RLock()
        self._token: Optional[str] = None
        self._expires_at: Optional[float] = None
        self.identity: Optional[str] = None
        self.roles: tuple = ()
        self.sign_in_count = 0  # observability for callers/tests (no secrets)

    def __repr__(self) -> str:  # never include the key or token
        return (f"IdentityShieldClient(base_url={self.base_url!r}, identity={self.identity!r}, "
                f"roles={list(self.roles)!r}, signed_in={self._token is not None})")

    __str__ = __repr__

    # --- context management -------------------------------------------------

    def __enter__(self) -> "IdentityShieldClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        """Revoke the current token server-side (best effort), then forget it."""
        try:
            self.logout()
        finally:
            if self._owns_session:
                try:
                    self._session.close()
                except Exception:  # pragma: no cover - defensive
                    pass

    # --- token lifecycle ----------------------------------------------------

    @property
    def token_expires_at(self) -> Optional[float]:
        return self._expires_at

    def _token_fresh(self) -> bool:
        if not self._token:
            return False
        if self._expires_at is None:
            return True
        return self._clock() < self._expires_at - self._skew

    def _send(self, method: str, path: str, headers: Dict[str, str], json: Any = None):
        try:
            return self._session.request(method, f"{self.base_url}{path}", headers=headers,
                                         json=json, timeout=self._timeout)
        except requests.RequestException as exc:
            # str(exc) may include the URL but never our headers.
            raise ClientError(f"{method} {path} failed: {exc.__class__.__name__}") from None

    def _wait_or_raise(self, resp, what: str, attempts_left: int) -> None:
        wait = _parse_retry_after(resp.headers.get("Retry-After"))
        if attempts_left <= 0 or wait is None or wait > self._max_wait:
            raise RateLimited(f"{what}: rate limited (429), Retry-After={wait}", wait)
        log.info("%s: 429, waiting %.0fs (Retry-After)", what, wait)
        self._sleep(wait)

    def sign_in(self) -> Dict[str, Any]:
        """Exchange the API key for a session token. Returns the response
        body minus the token (identity, roles, expires_at, token_type)."""
        with self._lock:
            attempts = 1  # at most one Retry-After wait
            while True:
                resp = self._send("POST", "/auth/session", {"X-API-Key": self.__api_key})
                if resp.status_code == 429:
                    self._wait_or_raise(resp, "sign-in", attempts)
                    attempts -= 1
                    continue
                break
            if resp.status_code == 401:
                raise AuthError("API key rejected by POST /auth/session", status=401)
            if resp.status_code >= 400:
                raise ClientError(f"POST /auth/session -> {resp.status_code}", status=resp.status_code,
                                  detail=_detail(resp))
            body = resp.json()
            token = body.get("token")
            if not token or str(body.get("token_type", "Bearer")).lower() != "bearer":
                raise ClientError("POST /auth/session returned no Bearer token")
            self._token = token
            self._expires_at = _parse_expires_at(body.get("expires_at"))
            self.identity = body.get("identity")
            self.roles = tuple(body.get("roles") or ())
            self.sign_in_count += 1
            log.info("signed in to %s as %s roles=%s", self.base_url, self.identity, list(self.roles))
            return {k: v for k, v in body.items() if k != "token"}

    def _ensure_token(self) -> str:
        with self._lock:
            if not self._token_fresh():
                self.sign_in()
            assert self._token
            return self._token

    def logout(self) -> bool:
        """POST /auth/logout with the current token; always forgets it locally.
        Returns True if the server confirmed revocation."""
        with self._lock:
            token, self._token, self._expires_at = self._token, None, None
        if not token:
            return False
        try:
            resp = self._send("POST", "/auth/logout", {"Authorization": f"Bearer {token}"})
        except ClientError:
            return False
        return resp.status_code == 200

    # --- requests -----------------------------------------------------------

    def request(self, method: str, path: str, json: Any = None) -> Any:
        """Authenticated call. Re-authenticates once on 401, waits out one 429
        Retry-After (bounded), raises ClientError subclasses otherwise."""
        if not path.startswith("/"):
            path = "/" + path
        reauthed = False
        waits = 1
        while True:
            token = self._ensure_token()
            resp = self._send(method, path, {"Authorization": f"Bearer {token}"}, json=json)
            if resp.status_code == 401 and not reauthed:
                # Expired, revoked, server restarted (random secret) or key rotated.
                with self._lock:
                    if self._token == token:
                        self._token, self._expires_at = None, None
                reauthed = True
                continue
            if resp.status_code == 429:
                self._wait_or_raise(resp, f"{method} {path}", waits)
                waits -= 1
                continue
            break
        if resp.status_code in (401, 403):
            raise AuthError(f"{method} {path} -> {resp.status_code}", status=resp.status_code,
                            detail=_detail(resp))
        if resp.status_code >= 400:
            raise ClientError(f"{method} {path} -> {resp.status_code}", status=resp.status_code,
                              detail=_detail(resp))
        if not resp.content:
            return None
        return resp.json()

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, json: Any = None) -> Any:
        return self.request("POST", path, json=json)

    # --- convenience wrappers (roles: operator for tests/results, admin for scope)

    def list_modules(self) -> Any:
        return self.get("/tests/modules")

    def run_module(self, module_id: str, target: str, params: Optional[dict] = None) -> Any:
        return self.post("/tests/run", {"module_id": module_id, "target": target, "params": params})

    def run_layer(self, layer: str, target: str) -> Any:
        return self.post("/tests/run-layer", {"layer": layer, "target": target})

    def list_runs(self) -> Any:
        return self.get("/results/runs")

    def get_run(self, run_id: str) -> Any:
        return self.get(f"/results/runs/{run_id}")

    def list_scope(self) -> Any:
        return self.get("/scope")

    def authorize_scope(self, target: str, note: Optional[str] = None) -> Any:
        return self.post("/scope", {"target": target, "note": note})


def _detail(resp) -> Any:
    try:
        body = resp.json()
    except Exception:
        return None
    return body.get("detail") if isinstance(body, dict) else body


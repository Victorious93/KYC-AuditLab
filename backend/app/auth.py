"""
API-key authentication and role-based authorization for the IdentityShield
control-plane API (/scope, /tests, /results, /simulator/admin/*).

Keys are presented in the ``X-API-Key`` header. They are configured only via
server-side environment variables - never hard-coded - and are stored as
SHA-256 hashes:

    IDENTITYSHIELD_API_KEYS="alice:admin:<sha256hex>,ci-bot:operator:<sha256hex>"

Each entry is ``identity:roles:sha256hex`` where ``roles`` is one or more of
``admin`` / ``operator`` joined with ``+`` (e.g. ``alice:admin+operator:...``).
Roles are NOT hierarchical: an ``admin``-only key cannot run tests, and an
``operator``-only key cannot manage scope. Give a key both roles if needed.

Generate a hash with:  python -m app.auth hash <your-key>

Local-dev escape hatch: ``IDENTITYSHIELD_DEV_API_KEYS`` accepts the same
format but with the *plaintext* key in the last field. It is honoured ONLY
when ``IDENTITYSHIELD_ENV=local`` (the default) and is ignored otherwise.

Fail closed: if no valid keys are configured, every protected route returns
503 and nothing is reachable.

Comparisons are constant time: the presented key is hashed and compared to
every configured hash with ``hmac.compare_digest`` (no early exit).

Short-lived session tokens (``POST /auth/session``): a client that holds an
API key can exchange it for a signed token and then send
``Authorization: Bearer <token>`` instead of the key. Browser and device
clients (the dashboard, future controllers/APKs) then never need to keep the
long-lived key. Tokens are stateless HMAC-SHA256 over
``{sub, kfp, iat, exp}`` where ``kfp`` is a keyed fingerprint of the API key
that issued it. On every request the token is re-bound to the *currently
configured* key: removing or rotating that key revokes all of its tokens
immediately, and the roles come from the current key config, not the token.

    IDENTITYSHIELD_SESSION_SECRET       signing secret, >= 32 chars. If unset,
                                        a random per-process secret is used
                                        (tokens die on restart; fine for one
                                        local uvicorn process). If set but too
                                        short, session tokens are disabled.
    IDENTITYSHIELD_SESSION_TTL_SECONDS  token lifetime, default 3600, clamped
                                        to [60, 43200].

A token cannot be used to mint another token (``/auth/session`` requires the
API key itself), so a stolen token dies at its expiry at the latest.

Each token carries a random ``jti``. ``POST /auth/logout`` (Bearer) adds that
jti to an in-memory denylist kept until the token's own expiry, so a signed
out token is rejected server-side even before it expires.

Failed ``POST /auth/session`` attempts are rate-limited per client IP with an
in-memory sliding window (429 + Retry-After):

    IDENTITYSHIELD_AUTH_RATE_LIMIT_MAX             failures allowed per window,
                                                   default 10, 0 disables
    IDENTITYSHIELD_AUTH_RATE_LIMIT_WINDOW_SECONDS  window length, default 300

Single-process limitation: the denylist, the rate limiter and the random
fallback secret all live in process memory. With several uvicorn/gunicorn
workers (or replicas) set the same IDENTITYSHIELD_SESSION_SECRET everywhere,
and be aware that revocations and rate-limit counters are per worker and are
lost on restart. A shared store (e.g. Redis/DB) would be needed for that.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import threading
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, FrozenSet, List, Optional, Tuple

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

log = logging.getLogger(__name__)

API_KEY_HEADER = "X-API-Key"
ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
VALID_ROLES = frozenset({ROLE_ADMIN, ROLE_OPERATOR})

_api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)
_bearer = HTTPBearer(auto_error=False)

SESSION_TOKEN_PREFIX = "iss1"
SESSION_SECRET_MIN_LEN = 32
SESSION_TTL_DEFAULT = 3600
SESSION_TTL_MIN = 60
SESSION_TTL_MAX = 12 * 3600
# Used only when IDENTITYSHIELD_SESSION_SECRET is unset.
_PROCESS_SESSION_SECRET = secrets.token_bytes(32)


@dataclass(frozen=True)
class Principal:
    identity: str
    roles: FrozenSet[str]


@dataclass(frozen=True)
class _KeyEntry:
    identity: str
    roles: FrozenSet[str]
    digest: bytes


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _parse(raw: str, hashed: bool) -> List[_KeyEntry]:
    entries: List[_KeyEntry] = []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":", 2)
        if len(parts) != 3 or not all(p.strip() for p in parts):
            log.warning("Ignoring malformed API key entry (expected identity:roles:key)")
            continue
        identity, roles_s, secret = (p.strip() for p in parts)
        roles = frozenset(r.strip() for r in roles_s.split("+") if r.strip())
        if not roles or not roles <= VALID_ROLES:
            log.warning("Ignoring API key entry for %r: invalid roles %r", identity, roles_s)
            continue
        if hashed:
            try:
                digest = bytes.fromhex(secret)
            except ValueError:
                digest = b""
            if len(digest) != 32:
                log.warning("Ignoring API key entry for %r: not a sha256 hex digest", identity)
                continue
        else:
            digest = hashlib.sha256(secret.encode("utf-8")).digest()
        entries.append(_KeyEntry(identity, roles, digest))
    return entries


def load_keys() -> List[_KeyEntry]:
    """Read key config from the environment on every call so rotation or
    revocation via env takes effect without code changes (and tests can
    monkeypatch)."""
    entries = _parse(os.getenv("IDENTITYSHIELD_API_KEYS", ""), hashed=True)
    dev_raw = os.getenv("IDENTITYSHIELD_DEV_API_KEYS", "")
    if dev_raw:
        if os.getenv("IDENTITYSHIELD_ENV", "local") == "local":
            entries += _parse(dev_raw, hashed=False)
        else:
            log.warning("IDENTITYSHIELD_DEV_API_KEYS ignored: IDENTITYSHIELD_ENV is not 'local'")
    return entries


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing or invalid API key",
        headers={"WWW-Authenticate": API_KEY_HEADER},
    )


def _loaded_keys_or_503() -> List[_KeyEntry]:
    entries = load_keys()
    if not entries:
        # Fail closed: an unconfigured server exposes nothing.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured on the server",
        )
    return entries


def _match_api_key(api_key: str, entries: List[_KeyEntry]) -> Optional[_KeyEntry]:
    presented = hashlib.sha256(api_key.encode("utf-8")).digest()
    match: Optional[_KeyEntry] = None
    for entry in entries:  # no early exit: constant work per configured key
        if hmac.compare_digest(presented, entry.digest) and match is None:
            match = entry
    return match


# --- session tokens ---------------------------------------------------------

def session_secret() -> Optional[bytes]:
    """The token signing secret, or None if session tokens are disabled
    (IDENTITYSHIELD_SESSION_SECRET set but shorter than 32 chars)."""
    raw = os.getenv("IDENTITYSHIELD_SESSION_SECRET", "")
    if not raw:
        return _PROCESS_SESSION_SECRET
    if len(raw) < SESSION_SECRET_MIN_LEN:
        log.warning("IDENTITYSHIELD_SESSION_SECRET is shorter than %d chars: session tokens disabled",
                    SESSION_SECRET_MIN_LEN)
        return None
    return raw.encode("utf-8")


def session_ttl_seconds() -> int:
    try:
        ttl = int(os.getenv("IDENTITYSHIELD_SESSION_TTL_SECONDS", str(SESSION_TTL_DEFAULT)))
    except ValueError:
        log.warning("Invalid IDENTITYSHIELD_SESSION_TTL_SECONDS; using %d", SESSION_TTL_DEFAULT)
        ttl = SESSION_TTL_DEFAULT
    return max(SESSION_TTL_MIN, min(SESSION_TTL_MAX, ttl))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key_fingerprint(secret: bytes, entry: _KeyEntry) -> str:
    # Keyed, so the (client-readable) token payload does not reveal anything
    # an attacker could brute-force offline back to the API key.
    return _b64e(hmac.new(secret, b"kfp:" + entry.digest, hashlib.sha256).digest()[:16])


def _sign(secret: bytes, signing_input: str) -> str:
    return _b64e(hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest())


def issue_session_token(entry: _KeyEntry, secret: bytes, now: Optional[float] = None) -> Tuple[str, int]:
    iat = int(time.time() if now is None else now)
    exp = iat + session_ttl_seconds()
    payload = {"sub": entry.identity, "kfp": _key_fingerprint(secret, entry), "iat": iat, "exp": exp,
               "jti": secrets.token_urlsafe(16)}
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{SESSION_TOKEN_PREFIX}.{body}"
    return f"{signing_input}.{_sign(secret, signing_input)}", exp


@dataclass(frozen=True)
class SessionClaims:
    entry: _KeyEntry
    jti: str
    exp: int


def verify_session_token(token: str, entries: List[_KeyEntry]) -> Optional[_KeyEntry]:
    """Return the currently configured key entry the token is bound to, or
    None if the token is malformed, forged, expired, revoked, or its key is
    gone."""
    claims = verify_session_claims(token, entries)
    return claims.entry if claims else None


def verify_session_claims(token: str, entries: List[_KeyEntry]) -> Optional[SessionClaims]:
    secret = session_secret()
    if secret is None:
        return None
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != SESSION_TOKEN_PREFIX:
        return None
    signing_input = f"{parts[0]}.{parts[1]}"
    if not hmac.compare_digest(_sign(secret, signing_input), parts[2]):
        return None
    try:
        payload = json.loads(_b64d(parts[1]))
        sub, kfp, exp, jti = payload["sub"], payload["kfp"], payload["exp"], payload["jti"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(exp, int) or isinstance(exp, bool) or exp <= time.time():
        return None
    if not isinstance(jti, str) or not jti or is_revoked(jti):
        return None
    match: Optional[_KeyEntry] = None
    for entry in entries:  # bind to a key that is still configured
        if (hmac.compare_digest(_key_fingerprint(secret, entry), str(kfp))
                and entry.identity == sub and match is None):
            match = entry
    return SessionClaims(match, jti, exp) if match else None


# --- revocation (jti denylist) -------------------------------------------------

_revoked: Dict[str, int] = {}
_revoked_lock = threading.Lock()


def _purge_revoked(now: float) -> None:
    for jti in [j for j, exp in _revoked.items() if exp <= now]:
        del _revoked[jti]


def revoke_jti(jti: str, exp: int) -> None:
    """Deny this token id until its expiry (after which the signature check
    rejects it anyway, so the entry can be dropped)."""
    with _revoked_lock:
        _purge_revoked(time.time())
        _revoked[jti] = exp


def is_revoked(jti: str) -> bool:
    with _revoked_lock:
        _purge_revoked(time.time())
        return jti in _revoked


def revoked_count() -> int:
    with _revoked_lock:
        _purge_revoked(time.time())
        return len(_revoked)


# --- /auth/session failed-attempt rate limit ----------------------------------

RATE_LIMIT_MAX_DEFAULT = 10
RATE_LIMIT_WINDOW_DEFAULT = 300


def _env_int(name: str, default: int, lo: int) -> int:
    try:
        v = int(os.getenv(name, str(default)))
    except ValueError:
        log.warning("Invalid %s; using %d", name, default)
        return default
    return max(lo, v)


def rate_limit_max() -> int:
    return _env_int("IDENTITYSHIELD_AUTH_RATE_LIMIT_MAX", RATE_LIMIT_MAX_DEFAULT, 0)


def rate_limit_window() -> int:
    return _env_int("IDENTITYSHIELD_AUTH_RATE_LIMIT_WINDOW_SECONDS", RATE_LIMIT_WINDOW_DEFAULT, 1)


class FailedAttemptLimiter:
    """Sliding-window counter of failed attempts per client key (IP).
    In-memory and per process; see module docstring."""

    def __init__(self) -> None:
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, client: str, now: float, window: int) -> Deque[float]:
        q = self._hits.get(client)
        if q is None:
            return deque()
        while q and q[0] <= now - window:
            q.popleft()
        if not q:
            del self._hits[client]
        return q

    def retry_after(self, client: str) -> int:
        """Seconds until another attempt is allowed; 0 if allowed now."""
        limit, window = rate_limit_max(), rate_limit_window()
        if limit <= 0:
            return 0
        now = time.time()
        with self._lock:
            q = self._prune(client, now, window)
            if len(q) < limit:
                return 0
            # Oldest failure that must age out to get back under the limit.
            return max(1, int(q[len(q) - limit] + window - now + 0.999))

    def record_failure(self, client: str) -> None:
        if rate_limit_max() <= 0:
            return
        now = time.time()
        with self._lock:
            self._prune(client, now, rate_limit_window())
            self._hits.setdefault(client, deque()).append(now)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


session_rate_limiter = FailedAttemptLimiter()


def reset_auth_state() -> None:
    """Test helper: clear the denylist and rate-limit counters."""
    session_rate_limiter.reset()
    with _revoked_lock:
        _revoked.clear()


def check_session_config() -> List[str]:
    """Startup sanity check; logs and returns warnings."""
    warnings: List[str] = []
    env = os.getenv("IDENTITYSHIELD_ENV", "local")
    raw = os.getenv("IDENTITYSHIELD_SESSION_SECRET", "")
    if not raw and env != "local":
        warnings.append(
            f"IDENTITYSHIELD_SESSION_SECRET is unset (IDENTITYSHIELD_ENV={env!r}): using a random "
            "per-process secret. Session tokens die on restart and are NOT valid across workers/"
            "replicas. Set a shared secret of >= 32 chars.")
    elif raw and len(raw) < SESSION_SECRET_MIN_LEN:
        warnings.append(
            f"IDENTITYSHIELD_SESSION_SECRET is shorter than {SESSION_SECRET_MIN_LEN} chars: "
            "session tokens are disabled.")
    for w in warnings:
        log.warning(w)
    return warnings


# --- FastAPI dependencies ----------------------------------------------------

def authenticated_key_entry(api_key: Optional[str] = Security(_api_key_header)) -> _KeyEntry:
    """X-API-Key only (no session tokens). Used by POST /auth/session so a
    token can never be used to mint a fresh one."""
    entries = _loaded_keys_or_503()
    match = _match_api_key(api_key, entries) if api_key else None
    if match is None:
        raise _unauthorized()
    return match


def authenticate(
    api_key: Optional[str] = Security(_api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(_bearer),
) -> Principal:
    """X-API-Key, or ``Authorization: Bearer <session token>``. If an
    X-API-Key header is present it is what gets checked."""
    entries = _loaded_keys_or_503()
    if api_key:
        match = _match_api_key(api_key, entries)
    elif bearer is not None and bearer.credentials:
        match = verify_session_token(bearer.credentials, entries)
    else:
        match = None
    if match is None:
        raise _unauthorized()
    return Principal(identity=match.identity, roles=match.roles)


def require_role(role: str):
    assert role in VALID_ROLES

    def _dep(principal: Principal = Depends(authenticate)) -> Principal:
        if role not in principal.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key lacks required role '{role}'",
            )
        return principal

    return _dep


require_admin = require_role(ROLE_ADMIN)
require_operator = require_role(ROLE_OPERATOR)


if __name__ == "__main__":  # pragma: no cover
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "hash":
        print(hash_key(sys.argv[2]))
    else:
        print("usage: python -m app.auth hash <key>")
        sys.exit(2)

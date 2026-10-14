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
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from typing import FrozenSet, List, Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

log = logging.getLogger(__name__)

API_KEY_HEADER = "X-API-Key"
ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
VALID_ROLES = frozenset({ROLE_ADMIN, ROLE_OPERATOR})

_api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)


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


def authenticate(api_key: Optional[str] = Security(_api_key_header)) -> Principal:
    entries = load_keys()
    if not entries:
        # Fail closed: an unconfigured server exposes nothing.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured on the server",
        )
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing or invalid API key",
        headers={"WWW-Authenticate": API_KEY_HEADER},
    )
    if not api_key:
        raise unauthorized
    presented = hashlib.sha256(api_key.encode("utf-8")).digest()
    match: Optional[_KeyEntry] = None
    for entry in entries:  # no early exit: constant work per configured key
        if hmac.compare_digest(presented, entry.digest) and match is None:
            match = entry
    if match is None:
        raise unauthorized
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

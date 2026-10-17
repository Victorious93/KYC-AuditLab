"""POST /auth/session: exchange an API key for a short-lived session token.
POST /auth/logout: revoke the presented session token server-side.

The dashboard (and future device/controller clients) call /auth/session once
with the operator's API key in X-API-Key and then send ``Authorization:
Bearer <token>``, so the long-lived key is never stored by the client. Token
format, lifetime, revocation and the failed-attempt rate limit are described
in app/auth.py.
"""
from __future__ import annotations

import datetime as dt
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials

from ..auth import (
    _api_key_header,
    _bearer,
    _loaded_keys_or_503,
    _match_api_key,
    _unauthorized,
    issue_session_token,
    revoke_jti,
    session_rate_limiter,
    session_secret,
    verify_session_claims,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    # The direct peer address only. X-Forwarded-For is deliberately NOT
    # trusted (it is client-controlled); behind a reverse proxy all clients
    # share the proxy's IP - see docs/LIMITATIONS.md.
    return request.client.host if request.client else "unknown"


@router.post("/session")
def create_session(request: Request, api_key: Optional[str] = Security(_api_key_header)):
    client = _client_ip(request)
    wait = session_rate_limiter.retry_after(client)
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many failed sign-in attempts; try again later",
            headers={"Retry-After": str(wait)},
        )
    entries = _loaded_keys_or_503()  # 503 (unconfigured) is not counted
    entry = _match_api_key(api_key, entries) if api_key else None
    if entry is None:
        session_rate_limiter.record_failure(client)
        raise _unauthorized()
    secret = session_secret()
    if secret is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="session tokens are disabled (IDENTITYSHIELD_SESSION_SECRET is too short)",
        )
    token, exp = issue_session_token(entry, secret)
    return {
        "token": token,
        "token_type": "Bearer",
        "expires_at": dt.datetime.fromtimestamp(exp, tz=dt.timezone.utc).isoformat(),
        "identity": entry.identity,
        "roles": sorted(entry.roles),
    }


@router.post("/logout")
def logout(bearer: Optional[HTTPAuthorizationCredentials] = Security(_bearer)):
    """Revoke the Bearer session token used for this request. API keys can't
    be "logged out" (rotate them in config instead)."""
    entries = _loaded_keys_or_503()
    claims = verify_session_claims(bearer.credentials, entries) if bearer and bearer.credentials else None
    if claims is None:
        raise _unauthorized()
    revoke_jti(claims.jti, claims.exp)
    return {"revoked": True}

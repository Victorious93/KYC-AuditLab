"""POST /auth/session: exchange an API key for a short-lived session token.

The dashboard (and future device/controller clients) call this once with the
operator's API key in X-API-Key and then send ``Authorization: Bearer
<token>``, so the long-lived key is never stored by the client. Token format,
lifetime and revocation are described in app/auth.py.
"""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import _KeyEntry, authenticated_key_entry, issue_session_token, session_secret

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/session")
def create_session(entry: _KeyEntry = Depends(authenticated_key_entry)):
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

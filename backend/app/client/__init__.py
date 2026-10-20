"""Small reusable Python client for the IdentityShield control-plane API.

Exchanges an API key for a short-lived session token (``POST /auth/session``),
sends ``Authorization: Bearer <token>`` on every call, refreshes the token
before expiry or after a 401, honours ``Retry-After`` on 429 and revokes the
token (``POST /auth/logout``) on close. See ``docs/CONTROLLER_INTEGRATION.md``.

Depends only on ``requests`` and the standard library so an external
controller (e.g. Droidcommand-AI) can vendor this package as-is.
"""
from .session import (
    AuthError,
    ClientError,
    ConfigError,
    IdentityShieldClient,
    RateLimited,
    is_loopback_url,
)

__all__ = [
    "AuthError",
    "ClientError",
    "ConfigError",
    "IdentityShieldClient",
    "RateLimited",
    "is_loopback_url",
]

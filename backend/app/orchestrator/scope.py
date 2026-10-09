"""
Scope authorization and execution-safety controls.

Every test module MUST call `assert_in_scope(target)` before sending a single
byte to a target. This is enforced in `runner.py` as well, so a module that
forgets to call it is still blocked centrally - but modules should call it
too, defensively, since some (e.g. Android, biometric) run outside the
central HTTP runner.

Design:
- `Settings.allowed_targets` (server-side env/config, NOT settable via API)
  is the hard ceiling: nothing outside it can ever be tested from this
  deployment.
- `ScopeEntry` rows in the DB are the soft/explicit layer: who authorized
  testing this target and when. A target must satisfy BOTH checks.
- Default-deny: an empty or missing scope entry means "not authorized",
  never "assume yes".
"""
from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import ScopeEntry

settings = get_settings()


class ScopeViolation(Exception):
    """Raised when a test target is not authorized. Must abort the run."""


def _hostname(target: str) -> str:
    if "//" in target:
        return urlparse(target).hostname or target
    return target.split(":")[0]


def is_host_allowlisted(target: str) -> bool:
    host = _hostname(target)
    return host in settings.allowed_targets


def is_explicitly_authorized(db: Session, target: str) -> bool:
    host = _hostname(target)
    entry = (
        db.query(ScopeEntry)
        .filter(ScopeEntry.target == host, ScopeEntry.revoked == "false")
        .first()
    )
    return entry is not None


def assert_in_scope(db: Session, target: str) -> None:
    """Raise ScopeViolation unless `target` passes both the hard allowlist
    and has an explicit, non-revoked ScopeEntry. Call this before any
    network, filesystem-outside-evidence, or device action."""
    if settings.enforce_local_only and not is_host_allowlisted(target):
        raise ScopeViolation(
            f"Target '{target}' is not in the server-side allowlist "
            f"({settings.allowed_targets}). Refusing to execute."
        )
    if not is_explicitly_authorized(db, target):
        raise ScopeViolation(
            f"Target '{target}' has no active ScopeEntry authorizing testing. "
            "Create one via POST /scope before running any module against it."
        )

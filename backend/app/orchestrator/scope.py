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

One canonical parser (`parse_target`) is used BOTH for the scope decision
and for building every outbound request URL (`target_url` /
`TestContext.url`). Modules must never interpolate the raw target string
into a URL: a parser differential between the scope check and the HTTP
client (e.g. `127.0.0.2:18080\\@localhost`, which urlsplit() reads as host
`localhost` but requests/urllib3 send to 127.0.0.2:18080) would otherwise
bypass the allowlist.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import ScopeEntry

settings = get_settings()


class ScopeViolation(Exception):
    """Raised when a test target is not authorized. Must abort the run."""


# Strict target grammar:
#   [ ("http" | "https") "://" ] host [ ":" port ] [ "/" ]
#   host = DNS hostname | IPv4 dotted-quad | "[" IPv6 "]"   (bare IPv6 without port also accepted)
# Rejected outright: userinfo ("@"), backslashes, whitespace, control and
# non-ASCII characters, paths beyond a single trailing "/", query, fragment,
# percent-encoding, IPv6 zone ids, and numeric-looking hosts that are not a
# canonical dotted-quad (e.g. "127.1", "0x7f000001", "2130706433").
_SCHEME_RE = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://")
_BRACKETED_RE = re.compile(r"^\[(?P<host>[0-9A-Fa-f:.]+)\](?::(?P<port>[0-9]{1,5}))?$")
_HOSTPORT_RE = re.compile(r"^(?P<host>[A-Za-z0-9._-]+)(?::(?P<port>[0-9]{1,5}))?$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
_NUMERICISH_RE = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$", re.IGNORECASE)
_ALLOWED_SCHEMES = {"http", "https"}


@dataclass(frozen=True)
class ParsedTarget:
    """Canonical, validated target. `host` is lower-case with no trailing
    dot; IPv6 is compressed and stored WITHOUT brackets."""

    host: str
    port: Optional[int] = None
    scheme: str = "http"

    @property
    def is_ipv6(self) -> bool:
        return ":" in self.host

    @property
    def netloc(self) -> str:
        h = f"[{self.host}]" if self.is_ipv6 else self.host
        return f"{h}:{self.port}" if self.port is not None else h

    def url(self, path: str = "") -> str:
        """Build a request URL from the parsed host/port only, then re-parse
        it with the HTTP client's own parser (urllib3) as a backstop and
        refuse if the client would connect anywhere else."""
        if path and not path.startswith("/"):
            raise ScopeViolation(f"Request path must start with '/': {path!r}")
        if "\\" in path or any(ord(c) < 0x21 or ord(c) == 0x7F for c in path):
            raise ScopeViolation(f"Refusing request path with backslash/whitespace/control chars: {path!r}")
        url = f"{self.scheme}://{self.netloc}{path}"
        _assert_url_targets(url, self)
        return url


def _assert_url_targets(url: str, expected: ParsedTarget) -> None:
    from urllib3.util import parse_url

    try:
        u = parse_url(url)
    except Exception as exc:  # noqa: BLE001
        raise ScopeViolation(f"Built URL {url!r} is not parseable: {exc}") from exc
    host = (u.host or "").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    if u.auth is not None or host != expected.host or u.port != expected.port:
        raise ScopeViolation(
            f"Built URL {url!r} resolves to host={u.host!r} port={u.port!r}, "
            f"not the scoped {expected.netloc!r}. Refusing to send."
        )
    split = urlsplit(url)
    if split.username is not None or (split.hostname or "") != expected.host:
        raise ScopeViolation(f"Built URL {url!r} does not round-trip to the scoped host. Refusing to send.")


def _validate_port(raw: Optional[str], target: str) -> Optional[int]:
    if raw is None:
        return None
    port = int(raw)
    if not 1 <= port <= 65535:
        raise ScopeViolation(f"Port out of range in target {target!r}.")
    return port


def _validate_dns_host(host: str, target: str) -> str:
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253:
        raise ScopeViolation(f"Invalid hostname length in target {target!r}.")
    labels = host.split(".")
    if not all(_LABEL_RE.match(lbl) for lbl in labels):
        raise ScopeViolation(f"Invalid hostname in target {target!r}.")
    # WHATWG/inet_aton treat a numeric final label as an IPv4 literal
    # ("127.1", "0x7f.1", "2130706433"). Only canonical dotted-quads are allowed.
    if _NUMERICISH_RE.match(labels[-1]):
        try:
            return ipaddress.IPv4Address(host).compressed
        except ValueError:
            raise ScopeViolation(
                f"Ambiguous numeric host in target {target!r}; use a canonical dotted-quad IPv4 address."
            ) from None
    return host


def parse_target(target: str) -> ParsedTarget:
    """The ONE canonical target parser. Raises ScopeViolation on anything
    outside the strict grammar above."""
    if not isinstance(target, str) or not target:
        raise ScopeViolation("Empty target.")
    for ch in target:
        o = ord(ch)
        if o > 0x7E or o < 0x21:
            raise ScopeViolation(
                f"Target {target!r} contains whitespace, control or non-ASCII characters; refusing."
            )
    if "@" in target:
        raise ScopeViolation(f"Target {target!r} contains '@' (userinfo is not allowed); refusing.")
    if "\\" in target:
        raise ScopeViolation(f"Target {target!r} contains a backslash; refusing.")

    rest = target
    scheme = "http"
    m = _SCHEME_RE.match(rest)
    if m:
        scheme = m.group("scheme").lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise ScopeViolation(f"Unsupported scheme {scheme!r} in target {target!r}.")
        rest = rest[m.end():]
    if rest.endswith("/"):
        rest = rest[:-1]
    if any(c in rest for c in "/?#%;"):
        raise ScopeViolation(
            f"Target {target!r} must be host[:port] (no path, query, fragment or percent-encoding)."
        )
    if not rest:
        raise ScopeViolation(f"Could not parse a hostname from target {target!r}.")

    # Bare IPv6 literal without brackets (e.g. "::1"); cannot carry a port.
    if rest.count(":") >= 2 and not rest.startswith("["):
        try:
            return ParsedTarget(ipaddress.IPv6Address(rest).compressed, None, scheme)
        except ValueError:
            raise ScopeViolation(f"Invalid IPv6 literal in target {target!r}.") from None

    m = _BRACKETED_RE.match(rest)
    if m:
        try:
            host = ipaddress.IPv6Address(m.group("host")).compressed
        except ValueError:
            raise ScopeViolation(f"Invalid IPv6 literal in target {target!r}.") from None
        return ParsedTarget(host, _validate_port(m.group("port"), target), scheme)

    m = _HOSTPORT_RE.match(rest)
    if not m:
        raise ScopeViolation(f"Could not parse a hostname from target {target!r}.")
    host = _validate_dns_host(m.group("host"), target)
    return ParsedTarget(host, _validate_port(m.group("port"), target), scheme)


def target_url(target: "str | ParsedTarget", path: str = "") -> str:
    """Build an outbound request URL for `target` from its canonical parse.
    Modules must use this (or TestContext.url) instead of f"http://{target}...".
    """
    parsed = target if isinstance(target, ParsedTarget) else parse_target(target)
    return parsed.url(path)


def _normalize_host(host: str) -> str:
    """Lower-case, strip whitespace/brackets/trailing dot; canonicalize IPs.
    Used for allowlist entries (server-side config), not for targets."""
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return host


def _hostname(target: str) -> str:
    """Canonical host of `target` (see parse_target). Kept for callers that
    only need the host, e.g. ScopeEntry storage."""
    return parse_target(target).host


def _allowlist() -> set[str]:
    return {_normalize_host(h) for h in settings.allowed_targets if h and h.strip()}


def is_host_allowlisted(target: str) -> bool:
    try:
        host = _hostname(target)
    except ScopeViolation:
        return False
    return bool(host) and host in _allowlist()


def is_explicitly_authorized(db: Session, target: str) -> bool:
    try:
        host = _hostname(target)
    except ScopeViolation:
        return False
    entry = (
        db.query(ScopeEntry)
        .filter(ScopeEntry.target == host, ScopeEntry.revoked == "false")
        .first()
    )
    return entry is not None


def assert_in_scope(db: Session, target: str) -> ParsedTarget:
    """Raise ScopeViolation unless `target` parses under the strict grammar,
    passes the hard allowlist and has an explicit, non-revoked ScopeEntry.
    Returns the canonical ParsedTarget that callers MUST use to build any
    request URL. Call this before any network, filesystem-outside-evidence,
    or device action."""
    parsed = parse_target(target)  # raises ScopeViolation on malformed/ambiguous input
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
    return parsed

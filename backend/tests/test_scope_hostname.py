"""Unit tests for target-host parsing/normalization in orchestrator.scope."""
import pytest

from app.orchestrator import scope
from app.orchestrator.scope import ScopeViolation, _hostname, is_host_allowlisted


@pytest.mark.parametrize(
    "target,expected",
    [
        ("localhost", "localhost"),
        ("localhost:8000", "localhost"),
        ("LocalHost:8000", "localhost"),
        ("127.0.0.1", "127.0.0.1"),
        ("127.0.0.1:8000", "127.0.0.1"),
        ("http://127.0.0.1:8000", "127.0.0.1"),
        ("http://127.0.0.1:8000/", "127.0.0.1"),
        ("HTTP://Example.COM.", "example.com"),
        ("::1", "::1"),
        ("[::1]", "::1"),
        ("[::1]:8000", "::1"),
        ("http://[::1]:8000/", "::1"),
        ("[0:0:0:0:0:0:0:1]:8000", "::1"),
        ("2001:DB8::1", "2001:db8::1"),
        ("https://host.local:9", "host.local"),
    ],
)
def test_hostname_parsing(target, expected):
    assert _hostname(target) == expected


def test_ipv6_is_not_split_on_colon():
    # Regression: the old split(":")[0] turned "[::1]:8000" into "[".
    assert _hostname("[::1]:8000") != "["
    assert _hostname("::1") != ""


@pytest.mark.parametrize("bad", ["http://", "[::1", "", "  LocalHost:8000 "])
def test_unparseable_raises(bad):
    with pytest.raises(ScopeViolation):
        _hostname(bad)


@pytest.fixture
def allowlist(monkeypatch):
    def _set(entries):
        monkeypatch.setattr(scope.settings, "allowed_targets", entries)
    return _set


def test_allowlist_entries_trimmed_and_case_normalized(allowlist):
    allowlist([" LocalHost ", " 127.0.0.1", "[::1] ", ""])
    assert is_host_allowlisted("localhost:8000")
    assert is_host_allowlisted("http://LOCALHOST/")
    assert is_host_allowlisted("127.0.0.1:1")
    assert is_host_allowlisted("[::1]:8000")
    assert is_host_allowlisted("::1")
    assert is_host_allowlisted("[0:0:0:0:0:0:0:1]")


def test_allowlist_denies_lookalikes(allowlist):
    allowlist(["localhost", "127.0.0.1", "::1"])
    assert not is_host_allowlisted("localhost.evil.com")
    assert not is_host_allowlisted("http://127.0.0.1.evil.com/")
    assert not is_host_allowlisted("[::2]:8000")
    assert not is_host_allowlisted("")
    assert not is_host_allowlisted("[::1")
    # Empty allowlist entries must not make "" allowlisted.
    allowlist(["", " "])
    assert not is_host_allowlisted("")

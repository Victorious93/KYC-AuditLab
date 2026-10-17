"""Audit F4: /simulator/liveness used to compare two CLIENT-supplied values
(challenge_response == expected_challenge), so sending the same value twice
passed in both modes. The challenge is now issued and stored server-side per
session, graded only against the stored value, and single-use."""
from __future__ import annotations

import pytest
import requests

from app.simulator import app as sim
from app.simulator.policies import DEFAULT_POLICY
from app.simulator.store import store


def _session_at_liveness(base, ident):
    s = requests.post(f"{base}/session", json={"identity_key": ident}, timeout=5).json()
    h = {"Authorization": f"Bearer {s['token']}"}
    sid = s["session_id"]
    doc = {"session_id": sid, "document_number": "SPECIMEN01", "document_type": "passport", "expiry_date": "2099-01-01"}
    assert requests.post(f"{base}/document", json=doc, headers=h, timeout=5).status_code == 200
    assert requests.post(f"{base}/face", json={"session_id": sid, "match_score": 0.95}, headers=h, timeout=5).status_code == 200
    return sid, h


def _challenge(base, sid, h):
    r = requests.post(f"{base}/liveness/challenge", json={"session_id": sid}, headers=h, timeout=5)
    assert r.status_code == 200, r.text
    return r.json()["challenge"]


def _liveness(base, sid, h, **body):
    return requests.post(f"{base}/liveness", json={"session_id": sid, **body}, headers=h, timeout=5)


@pytest.fixture(params=[True, False], ids=["vulnerable_mode", "hardened_mode"])
def mode(request, monkeypatch):
    monkeypatch.setattr(sim, "VULNERABLE_MODE", request.param)
    return request.param


@pytest.fixture
def base(live_server):
    return f"http://{live_server}/simulator"


def test_self_consistent_forgery_rejected_in_both_modes(base, mode):
    sid, h = _session_at_liveness(base, "f4-forgery")
    _challenge(base, sid, h)
    r = _liveness(base, sid, h, challenge_response="X", expected_challenge="X")
    assert r.status_code == 200
    assert r.json()["passed"] is False
    assert r.json()["challenge_status"] == "mismatch"


def test_forgery_without_any_issued_challenge_rejected(base, mode):
    sid, h = _session_at_liveness(base, "f4-nochal")
    r = _liveness(base, sid, h, challenge_response="X", expected_challenge="X")
    assert r.json()["passed"] is False
    assert r.json()["challenge_status"] == "missing"


def test_correct_server_challenge_passes_and_approves(base, mode):
    sid, h = _session_at_liveness(base, "f4-genuine")
    chal = _challenge(base, sid, h)
    assert chal.startswith("CHAL-") and len(chal) > 20
    r = _liveness(base, sid, h, challenge_response=chal)
    assert r.json() == {"status": "liveness_submitted", "passed": True, "challenge_status": "ok"}
    d = requests.post(f"{base}/decision", json={"session_id": sid, "desired_decision": "approved"}, headers=h, timeout=5)
    assert d.json()["decision"] == "approved"


def test_client_expected_challenge_is_ignored(base, mode):
    """A correct response passes even if the client claims a different
    expected value; the client's claim is never used."""
    sid, h = _session_at_liveness(base, "f4-ignored")
    chal = _challenge(base, sid, h)
    r = _liveness(base, sid, h, challenge_response=chal, expected_challenge="something-else")
    assert r.json()["passed"] is True


def test_challenge_is_single_use(base, mode, monkeypatch):
    # Allow resubmission at the workflow level so only the nonce rule applies.
    monkeypatch.setattr(DEFAULT_POLICY, "require_sequential_steps", False)
    sid, h = _session_at_liveness(base, "f4-single-use")
    chal = _challenge(base, sid, h)
    assert _liveness(base, sid, h, challenge_response=chal).json()["passed"] is True
    second = _liveness(base, sid, h, challenge_response=chal).json()
    assert second["passed"] is False and second["challenge_status"] == "replayed"


def test_wrong_answer_burns_the_challenge(base, mode, monkeypatch):
    monkeypatch.setattr(DEFAULT_POLICY, "require_sequential_steps", False)
    sid, h = _session_at_liveness(base, "f4-burn")
    chal = _challenge(base, sid, h)
    assert _liveness(base, sid, h, challenge_response="guess").json()["challenge_status"] == "mismatch"
    late = _liveness(base, sid, h, challenge_response=chal).json()
    assert late["passed"] is False and late["challenge_status"] == "replayed"


def test_new_challenge_invalidates_previous(base, mode, monkeypatch):
    sid, h = _session_at_liveness(base, "f4-reissue")
    old = _challenge(base, sid, h)
    _challenge(base, sid, h)
    r = _liveness(base, sid, h, challenge_response=old).json()
    assert r["passed"] is False and r["challenge_status"] == "mismatch"


def test_challenge_from_another_session_rejected(base, mode):
    sid_a, h_a = _session_at_liveness(base, "f4-cross-a")
    sid_b, h_b = _session_at_liveness(base, "f4-cross-b")
    chal_a = _challenge(base, sid_a, h_a)
    _challenge(base, sid_b, h_b)
    r = _liveness(base, sid_b, h_b, challenge_response=chal_a).json()
    assert r["passed"] is False


def test_expired_challenge_rejected(base, mode):
    sid, h = _session_at_liveness(base, "f4-expired")
    chal = _challenge(base, sid, h)
    import datetime as dt

    store.get(sid).liveness_challenge_expires_at = dt.datetime.utcnow() - dt.timedelta(seconds=1)
    r = _liveness(base, sid, h, challenge_response=chal).json()
    assert r["passed"] is False and r["challenge_status"] == "expired"


def test_challenge_endpoint_requires_token_and_order(base):
    s = requests.post(f"{base}/session", json={"identity_key": "f4-order"}, timeout=5).json()
    sid = s["session_id"]
    assert requests.post(f"{base}/liveness/challenge", json={"session_id": sid}, timeout=5).status_code == 401
    h = {"Authorization": f"Bearer {s['token']}"}
    assert requests.post(f"{base}/liveness/challenge", json={"session_id": sid}, headers=h, timeout=5).status_code == 409


def test_challenge_value_not_written_to_audit_log(base):
    sid, h = _session_at_liveness(base, "f4-audit")
    chal = _challenge(base, sid, h)
    events = requests.get(f"{base}/audit/{sid}", timeout=5).json()["events"]
    assert any(e["kind"] == "liveness_challenge_issued" for e in events)
    assert chal not in str(events)


def test_planted_flaw_kept_only_in_vulnerable_mode(base, mode):
    """VULNERABLE_MODE's intentional flaw (honoring client_asserts_live)
    is preserved; hardened mode ignores it."""
    sid, h = _session_at_liveness(base, "f4-planted")
    _challenge(base, sid, h)
    r = _liveness(base, sid, h, challenge_response="wrong", client_asserts_live=True).json()
    assert r["passed"] is mode

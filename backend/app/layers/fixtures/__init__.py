"""SYNTHETIC fixtures for Layers 2/3 plus a small driver that pushes one
sample through the bundled simulator's full KYC flow. See docs/DATASETS.md."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import requests

FIXTURE_DIR = Path(__file__).resolve().parent
LAYER2_SCORES_CSV = FIXTURE_DIR / "layer2_match_scores.csv"
LAYER3_PAD_CSV = FIXTURE_DIR / "layer3_pad_cases.csv"


def simulator_flow(target: str, identity_key: str, match_score: float, expected_challenge: str,
                   challenge_response: str, client_asserts_live: Optional[bool] = None) -> dict:
    """session -> valid synthetic document -> face score -> liveness -> decision.
    Returns {"liveness_passed": bool, "decision": str}."""
    base = f"http://{target}/simulator"
    s = requests.post(f"{base}/session", json={"identity_key": identity_key}, timeout=5)
    s.raise_for_status()
    sess = s.json()
    h = {"Authorization": f"Bearer {sess['token']}"}
    sid = sess["session_id"]

    def post(path, body):
        r = requests.post(f"{base}{path}", json={"session_id": sid, **body}, headers=h, timeout=5)
        r.raise_for_status()
        return r.json()

    post("/document", {"document_number": "SPECIMEN01", "document_type": "passport", "expiry_date": "2099-01-01"})
    post("/face", {"match_score": match_score})
    body = {"challenge_response": challenge_response, "expected_challenge": expected_challenge}
    if client_asserts_live is not None:
        body["client_asserts_live"] = client_asserts_live
    live = post("/liveness", body)
    dec = post("/decision", {"desired_decision": "approved"})
    return {"liveness_passed": bool(live["passed"]), "decision": dec["decision"]}

"""Regenerate the SYNTHETIC Layer 2/3 fixtures (deterministic, seeded).

No images, faces, documents or biometric data of any kind are produced:
Layer 2 rows are (pair_id, score, label, scenario) floats standing in for a
matcher's output; Layer 3 rows are labelled liveness-challenge submissions
(text challenge tokens) that are replayed against the bundled simulator.

    python scripts/gen_layers23_fixtures.py   # from backend/
"""
from __future__ import annotations

import csv
import random
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "app" / "layers" / "fixtures"

# (scenario, label, n, mean, sd) - impostor scenarios model harder cases
# (e.g. look-alike / same-demographic pairs) with a higher score mean.
L2_SCENARIOS = [
    ("genuine_good_capture", "genuine", 60, 0.90, 0.05),
    ("genuine_poor_capture", "genuine", 40, 0.80, 0.08),
    ("impostor_random", "impostor", 60, 0.30, 0.12),
    ("impostor_lookalike", "impostor", 40, 0.68, 0.10),
]

# Layer 3 attack types map to how the submission is made to /simulator/liveness.
L3_TYPES = [
    ("genuine", False, 60),
    ("wrong_challenge_response", True, 20),   # e.g. pre-recorded replay: answers a different prompt
    ("stale_challenge_replay", True, 20),     # replays a previous session's token
    ("client_asserts_live", True, 20),        # wrong response + client-side "live" flag
]


def main() -> None:
    rng = random.Random(20261015)
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "layer2_match_scores.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pair_id", "score", "label", "scenario"])
        for scen, label, n, mu, sd in L2_SCENARIOS:
            for i in range(n):
                w.writerow([f"{scen}-{i}", f"{min(1.0, max(0.0, rng.gauss(mu, sd))):.4f}", label, scen])
    with open(OUT / "layer3_pad_cases.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "is_attack", "attack_type", "expected_challenge", "challenge_response", "client_asserts_live"])
        for kind, attack, n in L3_TYPES:
            for i in range(n):
                exp = f"SPECIMEN-CHAL-{rng.randrange(16**6):06x}"
                if kind == "genuine":
                    resp, flag = exp, ""
                elif kind == "wrong_challenge_response":
                    resp, flag = f"SPECIMEN-CHAL-{rng.randrange(16**6):06x}", ""
                elif kind == "stale_challenge_replay":
                    resp, flag = "SPECIMEN-CHAL-000000", ""
                else:
                    resp, flag = "", "true"
                w.writerow([f"{kind}-{i}", int(attack), kind, exp, resp, flag])


if __name__ == "__main__":
    main()

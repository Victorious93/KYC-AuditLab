"""Layer 3 - Liveness Detection Security.

Evaluates a presentation-attack-detection (PAD) decision function against a
labeled set of (sample_metadata, is_attack) cases and reports standard PAD
metrics (APCER, BPCER, ACER). The evaluation harness is fully implemented.

No attack media (photos, video replays, deepfakes, masks, etc.) is
generated or bundled here, by design - see docs/LIMITATIONS.md. The bundled
default dataset below is SYNTHETIC METADATA ONLY (labels + a numeric mock
"detector confidence" field), not imagery or video, and is used solely to
exercise the metrics engine deterministically. A real evaluation requires
the operator to supply a labeled dataset (metadata + their detector's
output, or a callable implementing PADDetector) from an approved source.
"""
from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from typing import Callable, List, Optional

from ...orchestrator.registry import Capability, Finding, Layer, ModuleResult, TestContext, TestModule, registry


@dataclass
class PADCase:
    case_id: str
    is_attack: bool          # ground truth: True = presentation attack, False = genuine live sample
    mock_confidence: float    # placeholder "liveness confidence" in [0,1], synthetic


PADDetector = Callable[[PADCase], bool]  # returns True if detector says "live"


def default_detector(case: PADCase) -> bool:
    """Reference mock detector: calls it live iff mock_confidence >= 0.5.
    Stands in for a real detector's decision function during harness
    development; swap in your real detector via params['detector']."""
    return case.mock_confidence >= 0.5


def _bundled_synthetic_cases(n: int = 500, seed: int = 7) -> List[PADCase]:
    rng = random.Random(seed)
    cases = []
    for i in range(n // 2):
        cases.append(PADCase(f"genuine-{i}", is_attack=False, mock_confidence=min(1.0, max(0.0, rng.gauss(0.85, 0.12)))))
    for i in range(n // 2):
        cases.append(PADCase(f"attack-{i}", is_attack=True, mock_confidence=min(1.0, max(0.0, rng.gauss(0.25, 0.12)))))
    return cases


def evaluate_detector(cases: List[PADCase], detector: PADDetector) -> dict:
    attacks = [c for c in cases if c.is_attack]
    genuine = [c for c in cases if not c.is_attack]

    # APCER: proportion of attack presentations incorrectly classified as live.
    apcer = sum(1 for c in attacks if detector(c) is True) / len(attacks) if attacks else 0.0
    # BPCER: proportion of genuine presentations incorrectly classified as attack.
    bpcer = sum(1 for c in genuine if detector(c) is False) / len(genuine) if genuine else 0.0
    acer = (apcer + bpcer) / 2
    return {"apcer": apcer, "bpcer": bpcer, "acer": acer, "n_attacks": len(attacks), "n_genuine": len(genuine)}


def load_challenge_cases(path: str) -> List[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def simulator_detector(target: str) -> Callable[[dict], bool]:
    """Wraps the target's /liveness endpoint as a PAD decision function."""
    from ..fixtures import simulator_flow

    def detect(row: dict) -> bool:
        flag = row.get("client_asserts_live", "").strip().lower() == "true"
        out = simulator_flow(target, f"l3-{row['case_id']}", 0.95, row["expected_challenge"],
                             row["challenge_response"], True if flag else None)
        return out["liveness_passed"]

    return detect


def run_pad_evaluation(ctx: TestContext) -> ModuleResult:
    from ..fixtures import LAYER3_PAD_CSV

    detector: Optional[PADDetector] = ctx.params.get("detector")
    cases_override: Optional[List[PADCase]] = ctx.params.get("cases")
    using_synthetic = cases_override is None
    per_type = {}

    if cases_override is not None:
        metrics = evaluate_detector(cases_override, detector or default_detector)
        label = "provided"
    else:
        rows = load_challenge_cases(ctx.params.get("cases_csv_path") or str(LAYER3_PAD_CSV))
        det = detector or simulator_detector(ctx.target)
        verdicts = {r["case_id"]: det(r) for r in rows}
        cases = [PADCase(r["case_id"], r["is_attack"] == "1", 1.0 if verdicts[r["case_id"]] else 0.0) for r in rows]
        metrics = evaluate_detector(cases, lambda c: verdicts[c.case_id])
        for r in rows:
            t = per_type.setdefault(r["attack_type"], [0, 0])
            t[0] += 1
            t[1] += verdicts[r["case_id"]]
        metrics["accepted_as_live_by_type"] = {k: f"{v[1]}/{v[0]}" for k, v in per_type.items()}
        label = "SYNTHETIC challenge-replay fixture (layer3_pad_cases.csv), scored by target /liveness"
    summary = (
        f"{label}, "
        f"n_attacks={metrics['n_attacks']}, n_genuine={metrics['n_genuine']}. "
        f"APCER={metrics['apcer']:.4f}, BPCER={metrics['bpcer']:.4f}, ACER={metrics['acer']:.4f}."
        + (f" Accepted-as-live by type: {metrics['accepted_as_live_by_type']}." if per_type else "")
    )

    findings = []
    if using_synthetic:
        findings.append(
            Finding(
                title="PAD evaluation ran against synthetic placeholder metadata, not real attack data",
                description=(
                    "No real PAD dataset (attack media) was supplied. Results are the target's "
                    "real decisions on synthetic challenge-response protocol cases (replays, "
                    "wrong responses, client-asserted liveness); they measure the liveness "
                    "protocol, not an image-based PAD model."
                ),
                severity="info",
                remediation="Supply params['cases'] (real labeled dataset) and params['detector'] (your real PAD decision function).",
                risk_score=0.0,
            )
        )
    if metrics["apcer"] > 0.05:
        findings.append(
            Finding(
                title="Attack Presentation Classification Error Rate exceeds 5%",
                description=f"APCER={metrics['apcer']:.4f}: too many attack presentations classified as live.",
                severity="high" if metrics["apcer"] > 0.10 else "medium",
                remediation="Tighten the liveness decision threshold or retrain the PAD model; this is the metric attackers exploit directly.",
                risk_score=min(10.0, metrics["apcer"] * 60),
            )
        )

    return ModuleResult(passed=metrics["apcer"] <= 0.05, summary=summary, findings=findings, raw_output=str(metrics))


registry.register(
    TestModule(
        id="liveness.pad.apcer_bpcer_evaluation",
        layer=Layer.LIVENESS,
        title="PAD evaluation (APCER/BPCER/ACER)",
        description=(
            "Evaluates a presentation-attack-detection decision function against a labeled "
            "dataset and reports APCER/BPCER/ACER. By default replays a synthetic challenge-response "
            "fixture against the target's /liveness endpoint unless a real dataset/detector is supplied via params."
        ),
        capability=Capability.EVALUATION_ONLY,
        run=run_pad_evaluation,
        limitation=(
            "No real presentation-attack dataset or attack media is bundled or generated by "
            "this project, by design. The metrics engine (APCER/BPCER/ACER) is fully "
            "implemented; plugging in a real detector and an approved research dataset is "
            "left to the operator."
        ),
    )
)

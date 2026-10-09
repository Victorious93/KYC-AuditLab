"""Layer 2 - Facial Biometric Security.

Offline benchmarking harness for a matcher's genuine/impostor score
distributions. The harness itself (FAR/FRR/EER computation at configurable
thresholds) is fully implemented and real. What it is run against, by
default, is a bundled SYNTHETIC score distribution (clearly labeled, no
imagery, no real or simulated faces) - NOT a consented biometric dataset,
because none is available in this environment.

To use with a real evaluation: supply a CSV of (score, label) pairs from a
consented/approved dataset via TestContext.params["scores_csv_path"] and
this module will benchmark that instead. No impersonation or spoofing
generator is implemented or planned here - see docs/LIMITATIONS.md.
"""
from __future__ import annotations

import csv
import os
import random
from dataclasses import dataclass
from typing import List, Tuple

from ...orchestrator.registry import Capability, Finding, Layer, ModuleResult, TestContext, TestModule, registry


@dataclass
class ScoreSample:
    score: float   # matcher similarity score, [0, 1]
    genuine: bool  # True = same-identity pair, False = different-identity pair


def _bundled_synthetic_scores(n: int = 2000, seed: int = 42) -> List[ScoreSample]:
    """Generates a SYNTHETIC score distribution shaped like a plausible
    matcher output (genuine pairs cluster high, impostor pairs cluster low,
    with overlap) purely so the harness below has something deterministic
    to compute against in the absence of a real dataset. This is NOT a
    biometric dataset and contains no facial data of any kind - just two
    overlapping Gaussian distributions of floats."""
    rng = random.Random(seed)
    samples: List[ScoreSample] = []
    for _ in range(n // 2):
        samples.append(ScoreSample(score=min(1.0, max(0.0, rng.gauss(0.85, 0.10))), genuine=True))
    for _ in range(n // 2):
        samples.append(ScoreSample(score=min(1.0, max(0.0, rng.gauss(0.35, 0.15))), genuine=False))
    return samples


def _load_scores_csv(path: str) -> List[ScoreSample]:
    samples = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            samples.append(ScoreSample(score=float(row["score"]), genuine=row["label"].strip().lower() in ("1", "true", "genuine")))
    return samples


def compute_far_frr(samples: List[ScoreSample], threshold: float) -> Tuple[float, float]:
    """FAR = impostor pairs scoring >= threshold (incorrectly accepted).
    FRR = genuine pairs scoring < threshold (incorrectly rejected)."""
    impostors = [s for s in samples if not s.genuine]
    genuines = [s for s in samples if s.genuine]
    far = sum(1 for s in impostors if s.score >= threshold) / len(impostors) if impostors else 0.0
    frr = sum(1 for s in genuines if s.score < threshold) / len(genuines) if genuines else 0.0
    return far, frr


def estimate_eer(samples: List[ScoreSample], steps: int = 200) -> Tuple[float, float]:
    """Returns (eer, threshold_at_eer) by scanning thresholds 0..1."""
    best_gap = None
    best = (1.0, 0.0)
    for i in range(steps + 1):
        t = i / steps
        far, frr = compute_far_frr(samples, t)
        gap = abs(far - frr)
        if best_gap is None or gap < best_gap:
            best_gap = gap
            best = ((far + frr) / 2, t)
    return best


def run_benchmark(ctx: TestContext) -> ModuleResult:
    scores_csv_path = ctx.params.get("scores_csv_path")
    using_synthetic = scores_csv_path is None
    samples = _load_scores_csv(scores_csv_path) if scores_csv_path else _bundled_synthetic_scores()

    policy_threshold = float(ctx.params.get("threshold", 0.80))
    far, frr = compute_far_frr(samples, policy_threshold)
    eer, eer_threshold = estimate_eer(samples)

    summary = (
        f"{'SYNTHETIC placeholder' if using_synthetic else 'provided'} dataset, n={len(samples)}. "
        f"At threshold={policy_threshold:.2f}: FAR={far:.4f}, FRR={frr:.4f}. "
        f"Estimated EER={eer:.4f} at threshold={eer_threshold:.2f}."
    )

    findings = []
    if using_synthetic:
        findings.append(
            Finding(
                title="Biometric benchmark ran against synthetic placeholder data, not a real dataset",
                description=(
                    "No consented/approved biometric dataset was supplied via "
                    "params['scores_csv_path']. Results above are computed on a synthetic "
                    "score distribution and do NOT represent this matcher's real-world "
                    "FAR/FRR. Supply a real dataset to get meaningful numbers."
                ),
                severity="info",
                remediation="Provide a CSV of (score,label) pairs from an approved dataset.",
                risk_score=0.0,
            )
        )
    if far > 0.05:
        findings.append(
            Finding(
                title="False Acceptance Rate exceeds common KYC guidance threshold (5%)",
                description=f"FAR={far:.4f} at configured threshold {policy_threshold}.",
                severity="high" if far > 0.10 else "medium",
                remediation="Raise the match threshold or retrain/recalibrate the matcher.",
                risk_score=min(10.0, far * 50),
            )
        )

    return ModuleResult(passed=far <= 0.05, summary=summary, findings=findings, raw_output=summary)


registry.register(
    TestModule(
        id="biometric.benchmark.far_frr",
        layer=Layer.BIOMETRIC,
        title="FAR/FRR benchmark at policy threshold",
        description=(
            "Computes False Acceptance/Rejection Rate and estimated EER from a score "
            "distribution. Uses a bundled synthetic placeholder dataset unless a real, "
            "approved dataset CSV is supplied via params['scores_csv_path']."
        ),
        capability=Capability.EVALUATION_ONLY,
        run=run_benchmark,
        limitation=(
            "No consented biometric dataset is bundled with this project. The FAR/FRR "
            "computation engine is fully implemented and tested; running it against real "
            "data requires the operator to supply an approved dataset. No facial-matching "
            "spoofing/impersonation generator is implemented, by design."
        ),
    )
)

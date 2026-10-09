"""Configurable verification policies for the KYC simulator.

These knobs let test modules exercise specific behaviors (e.g. "does the
simulator correctly reject a duplicate submission under this policy?")
without touching simulator internals.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SimulatorPolicy:
    session_ttl_seconds: int = 300
    allow_duplicate_submission: bool = False
    require_sequential_steps: bool = True
    max_submissions_per_identity_per_hour: int = 3
    reject_malformed_documents: bool = True
    min_face_match_score: float = 0.80  # [0,1], threshold for "verified"
    rate_limit_per_minute: int = 30


DEFAULT_POLICY = SimulatorPolicy()

"""The actual, current inventory of fixtures/datasets this project bundles,
validated against FixtureMetadataV1. This is the single place that answers
"what data does IdentityShield ship, and what is it classified as" - every
entry here must be classified SYNTHETIC, since this project builds no
consented/approved/preexisting_approved dataset of its own (see
docs/LIMITATIONS.md: real datasets are supplied by the operator at
run time via ctx.params, never bundled)."""
from __future__ import annotations

import datetime as dt
from typing import List

from .fixture_metadata import FixtureClassification, FixtureMetadataV1

BUNDLED_FIXTURES: List[FixtureMetadataV1] = [
    FixtureMetadataV1(
        fixture_id="layer1.malformed_documents.v1",
        classification=FixtureClassification.SYNTHETIC,
        description="Structurally-invalid document fixtures (bad length/charset, expired dates, wrong "
        "type) used by document.validation.malformed_fixtures_rejected.",
        source="generated in-repo: backend/app/layers/layer1_document/__init__.py::SYNTHETIC_MALFORMED_DOCUMENTS",
        contains_real_imagery_or_biometrics=False,
        created_at=dt.date(2026, 10, 9),
    ),
    FixtureMetadataV1(
        fixture_id="layer2.biometric_score_distribution.v1",
        classification=FixtureClassification.SYNTHETIC,
        description="Two overlapping Gaussian distributions of floats standing in for genuine/impostor "
        "matcher scores, used as the default input to the FAR/FRR/EER harness.",
        source="generated in-repo: backend/app/layers/layer2_biometric/__init__.py::_bundled_synthetic_scores",
        contains_real_imagery_or_biometrics=False,
        created_at=dt.date(2026, 10, 9),
    ),
    FixtureMetadataV1(
        fixture_id="layer3.pad_mock_confidence.v1",
        classification=FixtureClassification.SYNTHETIC,
        description="Labeled (is_attack, mock_confidence) cases - numeric metadata only, no imagery or "
        "video - used as the default input to the APCER/BPCER/ACER PAD evaluation harness.",
        source="generated in-repo: backend/app/layers/layer3_liveness/__init__.py::_bundled_synthetic_cases",
        contains_real_imagery_or_biometrics=False,
        created_at=dt.date(2026, 10, 9),
    ),
    FixtureMetadataV1(
        fixture_id="layer7.synthetic_event_streams.v1",
        classification=FixtureClassification.SYNTHETIC,
        description="Repeated submissions / identity-reuse / velocity test sequences driven through the "
        "live simulator by the Layer 7 test modules themselves (no static file - generated per-run).",
        source="generated at test time: backend/app/layers/layer7_fraud/__init__.py",
        contains_real_imagery_or_biometrics=False,
        created_at=dt.date(2026, 10, 9),
    ),
]

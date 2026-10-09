"""Versioned fixture/dataset metadata schema (M1 Task 4, M2 Task 3).

Per the release-gate checklist: "No fixture is accepted without explicit
synthetic, consented, approved, or preexisting-approved classification."
This model is that check, made structural rather than a comment in code.
"""
from __future__ import annotations

import datetime as dt
from enum import Enum

from pydantic import BaseModel, Field, model_validator

SCHEMA_VERSION = "1.0.0"


class FixtureClassification(str, Enum):
    SYNTHETIC = "synthetic"                      # generated data, no real-world subject
    CONSENTED = "consented"                      # real data, explicit subject consent on file
    APPROVED = "approved"                         # a named approver signed off on this specific dataset
    PREEXISTING_APPROVED = "preexisting_approved"  # from an established research dataset with its own approval/license


class FixtureMetadataV1(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION, frozen=True)

    fixture_id: str = Field(description="Stable identifier, e.g. 'layer1.malformed_documents.v1'.")
    classification: FixtureClassification
    description: str
    source: str = Field(
        description="Where this fixture came from: 'generated in-repo' for synthetic data, a dataset "
        "name + version for preexisting_approved, or an approval record reference otherwise."
    )
    contains_real_imagery_or_biometrics: bool = Field(
        description="Must be explicitly declared, not inferred. True requires classification to be "
        "CONSENTED, APPROVED, or PREEXISTING_APPROVED - never SYNTHETIC (see validator)."
    )
    created_at: dt.date

    @model_validator(mode="after")
    def synthetic_cannot_contain_real_data(self) -> "FixtureMetadataV1":
        if self.classification == FixtureClassification.SYNTHETIC and self.contains_real_imagery_or_biometrics:
            raise ValueError(
                f"Fixture '{self.fixture_id}' is classified SYNTHETIC but declares "
                "contains_real_imagery_or_biometrics=True - that combination is never valid. "
                "Synthetic fixtures must not contain real biometric/imagery data by definition."
            )
        return self

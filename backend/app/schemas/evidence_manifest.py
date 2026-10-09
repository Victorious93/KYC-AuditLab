"""Versioned evidence-manifest schema (M1 Task 6, M2 Task 1/6).

Matches the fields the delivery model's "Final evidence package" section
requires of manifest.json: release ID, commit, timestamps, tool versions,
configuration hash, fixture identifiers, artifact hashes, test statuses,
and approval references.
"""
from __future__ import annotations

import datetime as dt
from typing import Dict, List

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0.0"


class TestStatusEntry(BaseModel):
    requirement_id: str
    status: str = Field(
        description="One of the RunStatus/traceability vocabulary values: "
        "pending, running, pass, fail, blocked, unsupported, skipped, flaky, unavailable, not-run, error."
    )
    run_id: str | None = None


class EvidenceManifestV1(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION, frozen=True)

    release_id: str
    commit: str = Field(description="Full git commit SHA this evidence package was built from.")
    created_at: dt.datetime
    tool_versions: Dict[str, str] = Field(
        description="e.g. {'python': '3.13.x', 'pytest': '8.3.3', 'node': '20.x'}"
    )
    config_hash: str = Field(description="Hash of the ExecutionConfigV1 instance used for this run.")
    fixture_ids: List[str] = Field(default_factory=list, description="FixtureMetadataV1.fixture_id values used.")
    artifact_hashes: Dict[str, str] = Field(
        default_factory=dict, description="path -> sha256 for every file under this evidence package."
    )
    test_statuses: List[TestStatusEntry] = Field(default_factory=list)
    approval_references: List[str] = Field(
        default_factory=list,
        description="Paths to approval records, e.g. ['docs/phase1/decisions/0001-single-operator-process.md'].",
    )

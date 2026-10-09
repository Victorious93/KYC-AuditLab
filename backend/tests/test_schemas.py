"""M2 schema tests: every shared schema must validate a positive example
and reject representative negative examples (M2 acceptance criteria:
'Invalid schema instances are rejected with actionable errors.')."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas import ExecutionConfigV1, FixtureClassification, FixtureMetadataV1, EvidenceManifestV1
from app.schemas.fixtures_registry import BUNDLED_FIXTURES

SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "docs" / "phase1" / "schemas"


# --- ExecutionConfigV1 -------------------------------------------------------

def test_execution_config_valid():
    cfg = ExecutionConfigV1(
        environment="local",
        allowed_targets=["localhost", "127.0.0.1"],
        enforce_local_only=True,
        evidence_dir="./evidence",
    )
    assert cfg.schema_version == "1.0.0"


def test_execution_config_rejects_empty_allowlist():
    with pytest.raises(ValidationError):
        ExecutionConfigV1(environment="local", allowed_targets=[], evidence_dir="./evidence")


def test_execution_config_rejects_production_target():
    with pytest.raises(ValidationError):
        ExecutionConfigV1(
            environment="local", allowed_targets=["kyc-prod.example.com"], evidence_dir="./evidence"
        )


def test_execution_config_rejects_production_environment():
    with pytest.raises(ValidationError):
        ExecutionConfigV1(environment="production", allowed_targets=["localhost"], evidence_dir="./evidence")


# --- FixtureMetadataV1 --------------------------------------------------------

def test_fixture_metadata_valid_synthetic():
    f = FixtureMetadataV1(
        fixture_id="test.fixture.v1",
        classification=FixtureClassification.SYNTHETIC,
        description="test",
        source="generated in-repo",
        contains_real_imagery_or_biometrics=False,
        created_at=dt.date.today(),
    )
    assert f.classification == FixtureClassification.SYNTHETIC


def test_fixture_metadata_rejects_synthetic_claiming_real_data():
    with pytest.raises(ValidationError):
        FixtureMetadataV1(
            fixture_id="test.fixture.v2",
            classification=FixtureClassification.SYNTHETIC,
            description="test",
            source="generated in-repo",
            contains_real_imagery_or_biometrics=True,  # contradicts SYNTHETIC
            created_at=dt.date.today(),
        )


def test_fixture_metadata_rejects_unknown_classification():
    with pytest.raises(ValidationError):
        FixtureMetadataV1(
            fixture_id="test.fixture.v3",
            classification="made_up_category",  # not in FixtureClassification
            description="test",
            source="x",
            contains_real_imagery_or_biometrics=False,
            created_at=dt.date.today(),
        )


def test_all_bundled_fixtures_are_synthetic():
    """Every fixture actually shipped in this repo must validate and must
    be classified SYNTHETIC - this project bundles no real dataset."""
    assert len(BUNDLED_FIXTURES) >= 1
    for f in BUNDLED_FIXTURES:
        assert f.classification == FixtureClassification.SYNTHETIC
        assert f.contains_real_imagery_or_biometrics is False


# --- EvidenceManifestV1 -------------------------------------------------------

def test_evidence_manifest_valid():
    m = EvidenceManifestV1(
        release_id="phase1-rc1",
        commit="a2726e8" * 5 + "abcde",  # arbitrary 40-char-ish sha stand-in
        created_at=dt.datetime.utcnow(),
        tool_versions={"python": "3.13", "pytest": "8.3.3"},
        config_hash="deadbeef",
        fixture_ids=[f.fixture_id for f in BUNDLED_FIXTURES],
        test_statuses=[],
        approval_references=["docs/phase1/decisions/0001-single-operator-process.md"],
    )
    assert m.schema_version == "1.0.0"


def test_evidence_manifest_rejects_missing_required_field():
    with pytest.raises(ValidationError):
        EvidenceManifestV1(release_id="phase1-rc1")  # missing commit, created_at, tool_versions, config_hash


# --- Exported JSON Schema files stay in sync ---------------------------------

@pytest.mark.parametrize(
    "name,model",
    [
        ("execution-config.v1.schema.json", ExecutionConfigV1),
        ("fixture-metadata.v1.schema.json", FixtureMetadataV1),
        ("evidence-manifest.v1.schema.json", EvidenceManifestV1),
    ],
)
def test_export_matches_committed_schemas(name, model):
    """Fails loudly if a model's shape changed without re-running the
    export. Regenerate with:
        python -m app.schemas.export_json_schemas
    from backend/, then commit the updated docs/phase1/schemas/*.json."""
    committed_path = SCHEMAS_DIR / name
    assert committed_path.exists(), f"Missing exported schema: {committed_path}"
    committed = json.loads(committed_path.read_text())
    current = model.model_json_schema()
    assert current == committed, (
        f"{name} is out of date with {model.__name__}. Re-run "
        "`python -m app.schemas.export_json_schemas` from backend/ and commit the result."
    )

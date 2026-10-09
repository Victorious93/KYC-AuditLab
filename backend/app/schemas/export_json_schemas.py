"""Regenerates the committed JSON Schema exports under docs/phase1/schemas/.

Run from backend/: python -m app.schemas.export_json_schemas

test_schemas.py::test_export_matches_committed_schemas fails if a model
changes without this being re-run and the result committed.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import EvidenceManifestV1, ExecutionConfigV1, FixtureMetadataV1

OUT_DIR = Path(__file__).resolve().parent.parent.parent.parent / "docs" / "phase1" / "schemas"

EXPORTS = {
    "execution-config.v1.schema.json": ExecutionConfigV1,
    "fixture-metadata.v1.schema.json": FixtureMetadataV1,
    "evidence-manifest.v1.schema.json": EvidenceManifestV1,
}


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for filename, model in EXPORTS.items():
        path = OUT_DIR / filename
        path.write_text(json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()

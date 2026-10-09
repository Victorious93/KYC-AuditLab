"""Versioned execution-configuration schema (M1 Task 1-2, M2 Task 1-2).

This formalizes, as a validated schema, the same values that
app/config.py's Settings already reads from the environment. config.py
stays the runtime source of truth (env vars); this model is what a
deployment's *intended* execution configuration should be checked against
before being accepted - e.g. a future `IDENTITYSHIELD_CONFIG_FILE` or a
CI check could load a JSON/YAML file, validate it against
ExecutionConfigV1, and fail closed on any violation before the app starts.
"""
from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "1.0.0"


class ExecutionConfigV1(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION, frozen=True)

    environment: str = Field(
        description="Deployment environment name, e.g. 'local', 'ci'. Never 'production' for this project."
    )
    allowed_targets: List[str] = Field(
        min_length=1,
        description="Server-side hostname allowlist. Must never be empty - an empty list would mean "
        "'nothing is allowed', which is the fail-closed default, but an empty list passed here is "
        "almost certainly a misconfiguration (no target can ever be tested), so it's rejected instead "
        "of silently accepted.",
    )
    enforce_local_only: bool = Field(
        default=True,
        description="Must be true for any deployment of this project. False is accepted by the schema "
        "(so a future legitimate non-local use case isn't structurally impossible) but every local "
        "default and every example in this repo keeps it true - see field_validator below for the "
        "specific strings this blocks regardless.",
    )
    evidence_dir: str = Field(description="Local filesystem path for evidence artifacts.")

    @field_validator("allowed_targets")
    @classmethod
    def no_prohibited_hosts(cls, v: List[str]) -> List[str]:
        prohibited_substrings = ("production", "prod.", ".prod", "live.")
        for host in v:
            lowered = host.lower()
            if any(p in lowered for p in prohibited_substrings):
                raise ValueError(
                    f"allowed_targets entry '{host}' looks like a production hostname - "
                    "this project's execution contract forbids targeting production systems "
                    "regardless of the enforce_local_only setting."
                )
        return v

    @field_validator("environment")
    @classmethod
    def environment_not_production(cls, v: str) -> str:
        if v.strip().lower() in ("prod", "production", "live"):
            raise ValueError(
                f"environment='{v}' is rejected: this project's execution contract has no "
                "production mode. Use 'local' or 'ci'."
            )
        return v

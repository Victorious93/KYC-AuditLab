"""
Central configuration for IdentityShield.

Safety-critical defaults live here: execution is local-only by default, and
every test run must pass an explicit target-allowlist check before any
module is permitted to run. These are not suggestions a module can opt out
of — orchestrator/scope.py enforces them centrally.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "IdentityShield"
    environment: str = os.getenv("IDENTITYSHIELD_ENV", "local")

    # SQLAlchemy connection string. Defaults to a local SQLite file so the
    # project runs with zero external dependencies for development/tests.
    # docker-compose.yml points this at Postgres for the "real" deployment.
    database_url: str = os.getenv(
        "DATABASE_URL", "sqlite:///./identityshield.db"
    )

    # Hard safety control: only hostnames/URLs listed here may ever be used
    # as a test target. The simulator's own address is added automatically.
    # This is intentionally NOT overridable via an API call - only via
    # server-side config/env, so a compromised or malicious test-run request
    # cannot widen scope at runtime.
    allowed_targets: List[str] = os.getenv(
        "IDENTITYSHIELD_ALLOWED_TARGETS",
        "localhost,127.0.0.1",
    ).split(",")

    # When true (default), the orchestrator refuses to run any network-facing
    # test module against a target that is not in allowed_targets, full stop.
    enforce_local_only: bool = os.getenv("IDENTITYSHIELD_LOCAL_ONLY", "true").lower() == "true"

    evidence_dir: str = os.getenv("IDENTITYSHIELD_EVIDENCE_DIR", "./evidence")

    simulator_base_url: str = os.getenv(
        "IDENTITYSHIELD_SIMULATOR_URL", "http://localhost:8000/simulator"
    )

    class Config:
        env_prefix = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()

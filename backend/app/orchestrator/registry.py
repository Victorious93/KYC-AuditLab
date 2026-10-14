"""
Modular test registry.

Each of the seven layers registers TestModule entries here. The registry is
pure metadata + a callable; it does nothing on import besides registering,
so importing the registry never touches the network or a device.

A TestModule function signature is:

    def run(ctx: TestContext) -> ModuleResult: ...

`TestContext` carries the target, DB session, and evidence directory.
`ModuleResult` is a plain dataclass the orchestrator turns into a TestRun +
Findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

from sqlalchemy.orm import Session


class Layer(str, Enum):
    DOCUMENT = "layer1_document"
    BIOMETRIC = "layer2_biometric"
    LIVENESS = "layer3_liveness"
    ANDROID = "layer4_android"
    API = "layer5_api"
    WORKFLOW = "layer6_workflow"
    FRAUD = "layer7_fraud"


class Capability(str, Enum):
    """Whether a module is fully implemented, a stub with a documented
    limitation, or an evaluation-only variant of something whose offensive
    counterpart was intentionally not built (see docs/LIMITATIONS.md)."""

    IMPLEMENTED = "implemented"
    STUB_NOT_IMPLEMENTED = "stub_not_implemented"
    EVALUATION_ONLY = "evaluation_only"  # e.g. biometric/liveness benchmarking without attack generation


@dataclass
class Finding:
    title: str
    description: str
    severity: str  # matches models.Severity values
    cwe: Optional[str] = None
    remediation: Optional[str] = None
    risk_score: float = 0.0


@dataclass
class ModuleResult:
    passed: bool
    summary: str
    findings: List[Finding] = field(default_factory=list)
    raw_output: Optional[str] = None
    # True when a prerequisite (adb, device, APK, expected value) was missing and
    # nothing was tested. The runner records SKIPPED - never PASSED.
    skipped: bool = False


@dataclass
class TestContext:
    target: str
    db: Session
    evidence_dir: str
    params: Dict = field(default_factory=dict)


@dataclass
class TestModule:
    id: str                      # unique, e.g. "api.auth.missing_token"
    layer: Layer
    title: str
    description: str
    capability: Capability
    run: Optional[Callable[[TestContext], ModuleResult]] = None
    limitation: Optional[str] = None  # required if capability != IMPLEMENTED

    def __post_init__(self) -> None:
        if self.capability == Capability.IMPLEMENTED and self.run is None:
            raise ValueError(f"Module {self.id} claims IMPLEMENTED but has no run()")
        if self.capability != Capability.IMPLEMENTED and not self.limitation:
            raise ValueError(f"Module {self.id} must document a limitation if not fully implemented")


class Registry:
    def __init__(self) -> None:
        self._modules: Dict[str, TestModule] = {}

    def register(self, module: TestModule) -> None:
        if module.id in self._modules:
            raise ValueError(f"Duplicate module id: {module.id}")
        self._modules[module.id] = module

    def get(self, module_id: str) -> TestModule:
        return self._modules[module_id]

    def all(self) -> List[TestModule]:
        return list(self._modules.values())

    def by_layer(self, layer: Layer) -> List[TestModule]:
        return [m for m in self._modules.values() if m.layer == layer]


registry = Registry()


def load_all_modules() -> None:
    """Import every layer package so its modules self-register.
    Safe to call multiple times (idempotent at the import level)."""
    from ..layers import (  # noqa: F401
        layer1_document,
        layer2_biometric,
        layer3_liveness,
        layer4_android,
        layer5_api,
        layer6_workflow,
        layer7_fraud,
    )

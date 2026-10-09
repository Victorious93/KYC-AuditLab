"""Failure-injection test for the ERROR path in runner.py (closes risk
register TEST-1). Builds a throwaway TestModule with a deliberately
raising run() - NOT registered in the global registry, so it never shows
up in /tests/modules or any real layer - and confirms execute_module
reports RunStatus.ERROR with the traceback captured, rather than silently
converting the crash into a false pass/fail or propagating the exception
out of the API layer."""
from __future__ import annotations

from app.db import SessionLocal
from app.orchestrator.registry import Capability, Layer, ModuleResult, TestContext, TestModule
from app.orchestrator.runner import execute_module


def _deliberately_raising_run(ctx: TestContext) -> ModuleResult:
    raise RuntimeError("deliberate failure for TEST-1 failure-injection coverage")


def test_module_exception_reports_error_status_with_traceback(live_server):
    throwaway_module = TestModule(
        id="test_only.failure_injection.deliberate_raise",
        layer=Layer.API,  # arbitrary; this module is never registered globally
        title="Deliberate failure (test fixture only)",
        description="Exists only to exercise runner.py's except Exception path.",
        capability=Capability.IMPLEMENTED,
        run=_deliberately_raising_run,
    )

    db = SessionLocal()
    try:
        # Bypass registry.get() by calling the same logic execute_module
        # uses, but with our throwaway module - replicate execute_module's
        # body here would duplicate runner.py, so instead we monkeypatch
        # the registry lookup for the duration of this one call.
        import app.orchestrator.runner as runner_module

        original_get = runner_module.registry.get
        runner_module.registry.get = lambda module_id: throwaway_module  # type: ignore[method-assign]
        try:
            run = execute_module(db, throwaway_module.id, live_server)
        finally:
            runner_module.registry.get = original_get

        assert run.status.value == "error"
        assert run.summary == "Module raised an unhandled exception."
        assert "RuntimeError" in run.raw_output
        assert "deliberate failure for TEST-1" in run.raw_output
    finally:
        db.close()

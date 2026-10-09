from __future__ import annotations

from fastapi import FastAPI

from .db import init_db
from .orchestrator.registry import load_all_modules
from .routers import results, scope_admin, tests
from .simulator.app import router as simulator_router

app = FastAPI(
    title="IdentityShield",
    description=(
        "Local-first KYC security assessment framework. Targets only the "
        "bundled simulator by default; see docs/THREAT_MODEL.md."
    ),
)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    load_all_modules()


app.include_router(simulator_router)
app.include_router(tests.router)
app.include_router(results.router)
app.include_router(scope_admin.router)


@app.get("/health")
def health():
    return {"status": "ok"}

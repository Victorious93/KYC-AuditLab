from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings

from .db import init_db
from .orchestrator.registry import load_all_modules
from .routers import auth_session, results, scope_admin, tests
from .simulator.app import router as simulator_router

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    load_all_modules()
    yield


app = FastAPI(
    lifespan=lifespan,
    title="IdentityShield",
    description=(
        "Local-first KYC security assessment framework. Targets only the "
        "bundled simulator by default; see docs/THREAT_MODEL.md."
    ),
)

# CORS for the browser dashboard (default origins: the Vite dev server on
# localhost/127.0.0.1:5173). Explicit allowlist only; no credentials/cookies
# are used; auth is the X-API-Key header or an Authorization: Bearer session
# token from POST /auth/session.
_cors_origins = get_settings().cors_origins
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["X-API-Key", "Authorization", "Content-Type"],
        max_age=600,
    )

app.include_router(simulator_router)
app.include_router(tests.router)
app.include_router(results.router)
app.include_router(scope_admin.router)
app.include_router(auth_session.router)


@app.get("/health")
def health():
    return {"status": "ok"}

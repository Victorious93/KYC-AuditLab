from __future__ import annotations

import logging

from sqlalchemy import Enum as SAEnum
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import get_settings

settings = get_settings()

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    # Import models so they register on Base before create_all.
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    ensure_postgres_enum_labels()


log = logging.getLogger(__name__)


def postgres_enum_label_statements() -> list[str]:
    """`ALTER TYPE ... ADD VALUE IF NOT EXISTS` for every label of every
    Python-Enum-backed column (runstatus, severity).

    SQLAlchemy's `Enum(PyEnum)` (no values_callable) stores member NAMES, so
    the Postgres labels are upper-case ('PENDING', ..., 'SKIPPED'), not the
    lower-case `.value`s. create_all() never alters an existing type, so a
    database created before a member was added (e.g. SKIPPED, added with the
    Layer 4 harness) needs this. Idempotent."""
    from . import models  # noqa: F401

    stmts: list[str] = []
    seen: set[str] = set()
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            t = col.type
            if not isinstance(t, SAEnum) or not t.name or t.name in seen:
                continue
            seen.add(t.name)
            for label in t.enums:  # member names, exactly what SQLAlchemy writes
                quoted = label.replace("'", "''")
                stmts.append(f"ALTER TYPE {t.name} ADD VALUE IF NOT EXISTS '{quoted}'")
    return stmts


def ensure_postgres_enum_labels(bind=None) -> list[str]:
    """Startup migration helper: on PostgreSQL, add any enum labels missing
    from existing types. No-op on other dialects. Runs in AUTOCOMMIT because
    a newly added enum label cannot be used inside the transaction that
    added it. Returns the statements executed."""
    bind = bind or engine
    if bind.dialect.name != "postgresql":
        return []
    insp = inspect(bind)
    existing = {e["name"] for e in insp.get_enums()}
    stmts = [s for s in postgres_enum_label_statements() if s.split()[2] in existing]
    with bind.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for stmt in stmts:
            conn.execute(text(stmt))
    if stmts:
        log.info("Ensured %d PostgreSQL enum labels", len(stmts))
    return stmts

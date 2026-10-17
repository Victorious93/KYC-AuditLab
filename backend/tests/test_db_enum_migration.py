"""Audit F3: SQLAlchemy `Enum(RunStatus)` stores member NAMES, so the
Postgres `runstatus` labels are upper-case. The documented migration must
add 'SKIPPED' (not 'skipped'); the startup helper emits exactly that."""
from app.db import engine, ensure_postgres_enum_labels, postgres_enum_label_statements
from app.models import RunStatus, Severity


def test_statements_use_member_names_not_values():
    stmts = postgres_enum_label_statements()
    assert "ALTER TYPE runstatus ADD VALUE IF NOT EXISTS 'SKIPPED'" in stmts
    assert not any("'skipped'" in s for s in stmts)
    for m in RunStatus:
        assert f"ALTER TYPE runstatus ADD VALUE IF NOT EXISTS '{m.name}'" in stmts
    for m in Severity:
        assert f"ALTER TYPE severity ADD VALUE IF NOT EXISTS '{m.name}'" in stmts


def test_helper_is_noop_on_sqlite():
    assert engine.dialect.name == "sqlite"
    assert ensure_postgres_enum_labels() == []


class _FakeConn:
    def __init__(self, log):
        self.log = log

    def execution_options(self, **kw):
        self.log.append(("opts", kw))
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, stmt):
        self.log.append(("sql", str(stmt)))


class _FakePgEngine:
    class dialect:
        name = "postgresql"

    def __init__(self):
        self.log = []

    def connect(self):
        return _FakeConn(self.log)


def test_helper_runs_autocommit_and_only_for_existing_types(monkeypatch):
    import app.db as db

    class _Insp:
        def get_enums(self):
            return [{"name": "runstatus"}]  # severity type absent -> skipped

    monkeypatch.setattr(db, "inspect", lambda bind: _Insp())
    fake = _FakePgEngine()
    ran = ensure_postgres_enum_labels(fake)
    assert ("opts", {"isolation_level": "AUTOCOMMIT"}) in fake.log
    assert "ALTER TYPE runstatus ADD VALUE IF NOT EXISTS 'SKIPPED'" in ran
    assert all(s.startswith("ALTER TYPE runstatus ") for s in ran)
    assert [x for k, x in fake.log if k == "sql"] == ran

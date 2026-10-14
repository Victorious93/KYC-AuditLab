import datetime as dt
import os
import stat
import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.evidence.redact import redact
from app.evidence.retention import cleanup
from app.evidence.store import write_evidence
from app.models import Finding, TestRun


@pytest.mark.parametrize(
    "raw,kind",
    [
        ("contact jane.doe@example.com now", "email"),
        ("card 4111 1111 1111 1111 exp", "card"),
        ("card 4111-1111-1111-1111", "card"),
        ("ssn 123-45-6789", "ssn"),
        ("iban DE89 3704 0044 0532 0130 00", "iban"),
        ("call +44 20 7946 0958", "phone"),
        ("Authorization: Bearer abcdef0123456789xyz", "token"),
        # Assembled at runtime so secret scanners do not flag a fake fixture.
        ("tok " + ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NSJ9", "c2lnbmF0dXJlMTIz"]), "jwt"),
    ],
)
def test_redacts_obvious_pii(raw, kind):
    out = redact(raw)
    assert f"[REDACTED:{kind}]" in out, out


@pytest.mark.parametrize(
    "raw",
    [
        "status 200 OK in 123ms",
        "run 3f2b6c1e-8a4d-4b7e-9c1f-2a3b4c5d6e7f",
        "2026-10-14T23:22:47Z",
        "order 1234567890123",  # 13 digits, fails Luhn
        "statuses [200, 403, 401, 429]",
        "127.0.0.1:8000",
    ],
)
def test_leaves_non_pii_alone(raw):
    assert redact(raw) == raw


def test_redact_none_and_empty():
    assert redact(None) is None
    assert redact("") == ""


def test_write_evidence_redacts_and_is_private(tmp_path):
    p = write_evidence(str(tmp_path), "../../etc/x.txt", "user a@b.co ssn 123-45-6789")
    assert os.path.dirname(p) == str(tmp_path)
    body = open(p).read()
    assert "a@b.co" not in body and "123-45-6789" not in body
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _seed(db, age_days):
    run = TestRun(layer="l", module_id="m", target="t",
                  started_at=dt.datetime.utcnow() - dt.timedelta(days=age_days))
    db.add(run)
    db.flush()
    db.add(Finding(run_id=run.id, title="f", description="d"))
    db.commit()
    return run.id


def test_retention_cleanup(db, tmp_path):
    old_id = _seed(db, 40)
    new_id = _seed(db, 1)
    old_f = tmp_path / "old.txt"
    new_f = tmp_path / "new.txt"
    old_f.write_text("x")
    new_f.write_text("y")
    past = time.time() - 40 * 86400
    os.utime(old_f, (past, past))

    dry = cleanup(db, str(tmp_path), days=30, dry_run=True)
    assert (dry.runs, dry.files) == (1, 1)
    assert db.get(TestRun, old_id) is not None and old_f.exists()

    rep = cleanup(db, str(tmp_path), days=30)
    assert (rep.runs, rep.files) == (1, 1)
    assert db.get(TestRun, old_id) is None
    assert db.get(TestRun, new_id) is not None
    assert db.query(Finding).count() == 1
    assert not old_f.exists() and new_f.exists()


def test_retention_rejects_nonpositive_days(db, tmp_path):
    with pytest.raises(ValueError):
        cleanup(db, str(tmp_path), days=0)

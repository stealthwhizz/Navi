from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Base, Issue, IssueScan, Scan


def test_issue_fingerprint_is_global_and_links_multiple_scans() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)

    with Session(engine) as session:
        first = Scan(source_root="/src", target_origin="http://127.0.0.1", created_at=now)
        second = Scan(source_root="/src", target_origin="http://127.0.0.1", created_at=now)
        issue = Issue(
            fingerprint="stable-fingerprint",
            status="code_only",
            severity="high",
            risk=70,
            cwe=89,
            title="SQL injection",
            first_seen=now,
            last_seen=now,
        )
        session.add_all([first, second, issue])
        session.flush()
        session.add_all([
            IssueScan(
                scan_id=first.id, issue_id=issue.id, status="confirmed", severity="high",
                risk=80, cwe=89, title="SQL injection", route={"/path": "/login"},
                location={"file": "login.php", "line": 8},
            ),
            IssueScan(
                scan_id=second.id, issue_id=issue.id, status="code_only", severity="high",
                risk=70, cwe=89, title="SQL injection", route={"/path": "/login"},
                location={"file": "login.php", "line": 8},
            ),
        ])
        session.commit()

        assert session.query(IssueScan).filter_by(issue_id=issue.id).count() == 2
        snapshots = session.query(IssueScan).filter_by(issue_id=issue.id).order_by(IssueScan.scan_id).all()
        assert {snapshot.status for snapshot in snapshots} == {"confirmed", "code_only"}

        session.add(Issue(
            fingerprint="stable-fingerprint",
            status="code_only",
            severity="high",
            risk=70,
            cwe=89,
            title="Duplicate issue",
            first_seen=now,
            last_seen=now,
        ))
        with pytest.raises(IntegrityError):
            session.commit()

    engine.dispose()

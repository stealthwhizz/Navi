from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import create_app
from app.models import Base, Issue, IssueScan, Route, Scan, Suppressed
from app.settings import Settings

ORIGIN = "http://127.0.0.1:4280"


def test_results_endpoints_serialize_scan_snapshots_and_report(tmp_path: Path) -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(
        database_url="postgresql+psycopg://user:pass@localhost/cyberforge",
        source_root=tmp_path,
        allowed_target_origin=ORIGIN,
    )
    with Session(engine) as session:
        now = datetime.now(UTC)
        scan = Scan(
            state="completed", source_root=str(tmp_path), target_origin=ORIGIN,
            created_at=now, finished_at=now, counts={"confirmed": 1, "code_only": 0, "runtime_only": 0, "suppressed": 1},
            coverage={"frameworks": [], "files_parsed": 1, "files_skipped": [], "routes_total": 1,
                      "routes_unmapped": 0, "unresolved": [], "rules_not_run": [],
                      "dast": {"requests": 5, "routes_tested": 1, "params_tested": 1, "blocked": 0, "timeouts": 0}, "errors": []},
        )
        confirmed = Issue(
            fingerprint="confirmed-fp", status="confirmed", severity="high", risk=75, cwe=79,
            title="XSS", first_seen=now, last_seen=now,
        )
        code_only = Issue(
            fingerprint="code-fp", status="code_only", severity="medium", risk=50, cwe=89,
            title="SQLi", first_seen=now, last_seen=now,
        )
        session.add_all([scan, confirmed, code_only])
        session.flush()
        session.add_all([
            IssueScan(
                scan_id=scan.id, issue_id=confirmed.id, status="confirmed", severity="high", risk=75,
                cwe=79, title="XSS", route={"method": "GET", "path": "/search.php"},
                location={"file": "search.php", "line": 4},
                sast={
                    "rule_id": "CWE-79", "file": "search.php", "line_start": 4, "line_end": 4,
                    "snippet": {"start_line": 4, "code": "echo $_GET['q'];"}, "highlight_line": 4,
                    "source": {"expr": "$_GET['q']", "type": "request_parameter", "location": "search.php:4"},
                    "sink": {"name": "echo", "type": "html_output", "location": "search.php:4"},
                    "path": [{"label": "source", "location": "search.php:4", "resolved": True},
                             {"label": "sink", "location": "search.php:4", "resolved": True}],
                    "sanitizers": [],
                },
                dast={
                    "rule_id": "CWE-79-DAST", "method": "GET", "url": f"{ORIGIN}/search.php",
                    "parameter": "q", "payload": "<script>probe</script>", "request": "GET /search.php?q=[probe]",
                    "response": {"status": 200, "excerpt": "<script>probe</script>", "truncated": False},
                    "evidence": "<script>probe</script>", "oracle": "unescaped reflection",
                },
                correlation={"accepted": True, "rationale": "evidence matched", "checks": []},
            ),
            IssueScan(scan_id=scan.id, issue_id=code_only.id, status="code_only", severity="medium", risk=50,
                      cwe=89, title="SQLi", route=None, location={"file": "db.php", "line": 9}),
        ])
        session.add(Route(
            scan_id=scan.id, method="GET", path="/search.php", handler_key="search.php:1",
            data={"declared_at": None, "handler": {"name": "search", "file": "search.php", "line_start": 1, "line_end": 10},
                  "params": ["q"], "provenance": "filesystem", "confidence": "medium", "tested": True, "issue_count": 1},
        ))
        session.add(Suppressed(
            scan_id=scan.id, source="sast", cwe=79, title="Safe output", file="search.php", line=3,
            sanitizer="htmlspecialchars", reason="HTML encoding covers the output context",
        ))
        session.commit()
        scan_id, issue_id = scan.id, confirmed.id

    with TestClient(create_app(settings, factory)) as client:
        issues = client.get(f"/issues?scan_id={scan_id}").json()
        code_issues = client.get(f"/issues?scan_id={scan_id}&status=code_only&cwe=89").json()
        detail = client.get(f"/issues/{issue_id}?scan_id={scan_id}")
        routes = client.get(f"/routes?scan_id={scan_id}").json()
        suppressed = client.get(f"/suppressed?scan_id={scan_id}").json()
        report = client.get(f"/reports/{scan_id}")

    assert [item["status"] for item in issues] == ["confirmed", "code_only"]
    assert len(code_issues) == 1 and code_issues[0]["cwe"] == 89
    assert detail.status_code == 200
    assert detail.json()["sast"]["rule_id"] == "CWE-79"
    assert detail.json()["dast"]["rule_id"] == "CWE-79-DAST"
    assert routes[0]["tested"] is True
    assert suppressed[0]["sanitizer"] == "htmlspecialchars"
    assert report.status_code == 200
    assert "attachment" in report.headers["content-disposition"]
    assert report.json()["scan"]["id"] == scan_id
    engine.dispose()


def test_issue_detail_uses_requested_scan_snapshot(tmp_path: Path) -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(
        database_url="postgresql+psycopg://user:pass@localhost/cyberforge",
        source_root=tmp_path,
        allowed_target_origin=ORIGIN,
    )
    now = datetime.now(UTC)
    older = Scan(state="completed", source_root=str(tmp_path), target_origin=ORIGIN, created_at=now)
    newer = Scan(
        state="completed", source_root=str(tmp_path), target_origin=ORIGIN,
        created_at=now + timedelta(seconds=1),
    )
    issue = Issue(
        fingerprint="same-issue", status="confirmed", severity="high", risk=75, cwe=79,
        title="XSS", first_seen=now, last_seen=now,
    )
    with Session(engine) as session:
        session.add_all([older, newer, issue])
        session.flush()
        older_id, newer_id, issue_id = older.id, newer.id, issue.id
        session.add_all([
            IssueScan(
                scan_id=older.id, issue_id=issue.id, status="code_only", severity="medium",
                risk=50, cwe=79, title="XSS", location={"file": "older.php", "line": 4},
            ),
            IssueScan(
                scan_id=newer.id, issue_id=issue.id, status="confirmed", severity="high",
                risk=75, cwe=79, title="XSS", location={"file": "newer.php", "line": 9},
            ),
        ])
        session.commit()

    with TestClient(create_app(settings, factory)) as client:
        older_detail = client.get(f"/issues/{issue_id}?scan_id={older_id}")
        newer_detail = client.get(f"/issues/{issue_id}?scan_id={newer_id}")

    assert older_detail.status_code == newer_detail.status_code == 200
    assert older_detail.json()["scan_id"] == older_id
    assert older_detail.json()["status"] == "code_only"
    assert older_detail.json()["location"] == {"file": "older.php", "line": 4}
    assert newer_detail.json()["status"] == "confirmed"
    assert newer_detail.json()["location"] == {"file": "newer.php", "line": 9}
    engine.dispose()

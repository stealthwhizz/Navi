"""Transactional scan history and stable issue occurrences in PostgreSQL."""

from __future__ import annotations

from pathlib import Path
import json

import psycopg
from psycopg.types.json import Jsonb


class Store:
    def __init__(self, database_url: str):
        self.database_url = database_url

    def connect(self):
        return psycopg.connect(self.database_url, connect_timeout=5, options="-c statement_timeout=15000 -c lock_timeout=5000")

    def migrate(self):
        with self.connect() as db:
            db.execute("SELECT pg_advisory_xact_lock(736824129)")
            db.execute((Path(__file__).parent / "schema.sql").read_text())

    def health(self):
        with self.connect() as db:
            return db.execute("SELECT 1").fetchone()[0] == 1

    def previous(self, project: str):
        with self.connect() as db:
            row = db.execute("SELECT report FROM cf_scans WHERE project=%s ORDER BY started DESC, id DESC LIMIT 1", (project,)).fetchone()
        return row[0] if row else None

    def get(self, scan_id: str):
        with self.connect() as db:
            row = db.execute("SELECT report FROM cf_scans WHERE id=%s", (scan_id,)).fetchone()
        return row[0] if row else None

    def history(self, project: str, limit: int = 30):
        with self.connect() as db:
            rows = db.execute("SELECT id, started, report->'summary', report->>'status' FROM cf_scans WHERE project=%s ORDER BY started DESC, id DESC LIMIT %s", (project, min(100, max(1, limit)))).fetchall()
        return [{"id": r[0], "started": r[1].isoformat(), "summary": r[2], "status": r[3]} for r in rows]

    def save_experiment(self, experiment):
        with self.connect() as db:
            db.execute("INSERT INTO cf_experiments VALUES (%s,%s,%s,%s)",
                       (experiment["id"], experiment["project"], experiment["created"], Jsonb(experiment)))

    def experiments(self, project, limit=20):
        with self.connect() as db:
            return [row[0] for row in db.execute("SELECT evidence FROM cf_experiments WHERE project=%s ORDER BY created DESC LIMIT %s", (project, min(50, max(1, limit)))).fetchall()]

    def save(self, report: dict):
        with self.connect() as db:
            db.execute("INSERT INTO cf_scans VALUES (%s, %s, %s, %s, %s)",
                       (report["id"], report["project"], report["started"], report["finished"], Jsonb(report)))
            for issue in report["issues"]:
                db.execute("INSERT INTO cf_issues VALUES (%s, %s, %s, %s) ON CONFLICT(project, id) DO UPDATE SET last_scan=excluded.last_scan",
                           (report["project"], issue["id"], report["id"], report["id"]))
                db.execute("INSERT INTO cf_occurrences VALUES (%s, %s, %s)", (report["id"], issue["id"], Jsonb(issue)))


def compare(previous: dict | None, current: dict) -> dict:
    old = {i["id"] for i in previous["issues"]} if previous else set()
    new = {i["id"] for i in current["issues"]}
    return {"previous_scan": previous["id"] if previous else None, "new": sorted(new - old), "still_observed": sorted(new & old),
            "not_observed": sorted(old - new), "note": "Not observed is not proof of a fix; compare coverage and rerun the relevant verification."}


def previous_export(output, project, scan_id):
    """Find a same-project baseline even when PostgreSQL is not configured."""
    output = Path(output)
    candidates = [output / 'report.json']
    if output.parent.name == 'scans':
        candidates.extend(output.parent.glob('*/report.json'))
    reports = []
    for path in candidates:
        try:
            if path.is_symlink() or not path.is_file(): continue
            reports.append((path.stat().st_mtime, path))
        except OSError:
            continue
    for _, path in sorted(reports, reverse=True)[:100]:
        try:
            report = json.loads(path.read_text())
            if report.get('project') == project and report.get('id') != scan_id and isinstance(report.get('issues'), list):
                return report
        except (OSError, ValueError, AttributeError):
            continue
    return None

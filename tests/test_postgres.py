import os
import uuid

import pytest

from navi.store import Store


def test_postgres_round_trip_idempotent_migration_and_issue_history():
    dsn = os.getenv("TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("Set TEST_DATABASE_URL to run the real PostgreSQL connection/history integration test.")
    store = Store(dsn)
    store.migrate(); store.migrate()
    project = "integration-test-" + uuid.uuid4().hex
    issue = {"id":"stable-operation", "cwe":"CWE-89", "status":"Confirmed", "evidence":[{"marker":"round-trip"}]}
    first = {"id":uuid.uuid4().hex,"project":project,"started":"2026-10-31T00:00:00+00:00","finished":"2026-10-31T00:00:01+00:00","issues":[issue],"summary":{"total":1},"status":"completed"}
    second = {**first,"id":uuid.uuid4().hex,"started":"2026-10-31T00:01:00+00:00"}
    trial = {"id":uuid.uuid4().hex,"project":project,"created":"2026-10-31T00:00:00+00:00",
             "before":{"outcome":"violation","request":{"status":200}},
             "after":{"outcome":"blocked","request":{"status":403}},"comparison":{"verified":True}}
    later_trial = {**trial,"id":uuid.uuid4().hex,"created":"2026-10-31T00:01:00+00:00"}
    try:
        store.save(first); store.save(second)
        store.save_experiment(trial); store.save_experiment(later_trial)
        # A new connection owner models loading history after a process restart.
        store = Store(dsn)
        assert store.health()
        assert store.get(first["id"]) == first
        assert store.previous(project) == second
        assert len(store.history(project)) == 2
        assert store.experiments(project) == [later_trial, trial]
        assert store.experiments(project, limit=1) == [later_trial]
        assert store.experiments(project + "-absent") == []
        with store.connect() as db:
            assert db.execute("SELECT count(*) FROM cf_issues WHERE project=%s", (project,)).fetchone()[0] == 1
            assert db.execute("SELECT count(*) FROM cf_occurrences WHERE scan_id IN (%s,%s)", (first["id"],second["id"])).fetchone()[0] == 2
    finally:
        with store.connect() as db:
            db.execute("DELETE FROM cf_experiments WHERE project=%s", (project,))
            db.execute("DELETE FROM cf_issues WHERE project=%s", (project,))
            db.execute("DELETE FROM cf_scans WHERE project=%s", (project,))

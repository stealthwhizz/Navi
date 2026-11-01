from copy import deepcopy
import asyncio
import json
import threading
import time

from fastapi.testclient import TestClient
import pytest

from navi.api import Settings, create_app
from navi.engine import scan
from navi.report import portable_html, sarif
from navi.runtime import load_config
from navi.store import compare
from conftest import ROOT


def local_client(application):
    # The managed workspace blocks the socket write used by asyncio's cross-thread
    # wakeup. A periodic timer keeps genuine ASGI requests progressing without TCP.
    def loop_factory():
        loop = asyncio.new_event_loop()
        def tick():
            if not loop.is_closed():
                loop.call_later(.01, tick)
        loop.call_soon(tick)
        return loop
    return TestClient(application, backend_options={"loop_factory":loop_factory})


@pytest.fixture
def report(shop, tmp_path):
    config = load_config(str(ROOT / "examples/shop/policy.json")); config["interval"] = 0
    return scan(ROOT / "examples/shop", "http://127.0.0.1:5050", config, tmp_path, browser=False)


def test_reports_written_and_events_complete(report, tmp_path):
    assert json.loads((tmp_path / "report.json").read_text())["id"] == report["id"]
    assert json.loads((tmp_path / "report.sarif").read_text())["version"] == "2.1.0"
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert events[0]["type"] == "scan_started"
    assert events[-1]["type"] == "scan_finished"
    assert any(e["type"] == "runtime_finding" for e in events)
    assert (tmp_path / "report.html").stat().st_size > 15000


def test_sarif_has_code_locations_and_stable_fingerprints(report):
    result = sarif(report)
    findings = result["runs"][0]["results"]
    assert len(findings) == len(report["issues"])
    assert all(f["partialFingerprints"]["navi/issue/v1"] for f in findings)
    sql = next(f for f in findings if f["ruleId"] == "CWE-89" and "locations" in f)
    assert sql["locations"][0]["physicalLocation"]["region"]["startLine"] > 0


def test_portable_report_escapes_embedded_attacker_html(report):
    poisoned = deepcopy(report)
    poisoned["issues"][0]["title"] = '</script><script>alert("injected")</script>'
    output = portable_html(poisoned)
    assert '</script><script>alert("injected")' not in output
    assert "\\u003c/script>" in output
    assert 'href="/style.css"' not in output
    assert 'src="/app.js"' not in output


def test_scan_comparison_does_not_claim_unobserved_is_fixed(report):
    later = deepcopy(report); later["issues"].pop()
    result = compare(report,later)
    assert len(result["not_observed"]) == 1
    assert "not proof of a fix" in result["note"]
    assert "fixed" not in result


def test_postgres_failure_retains_reports(shop, tmp_path, monkeypatch):
    def fail(*args):
        raise RuntimeError("secret-database-password")
    monkeypatch.setattr("navi.store.Store.migrate", fail)
    result = scan(ROOT / "examples/shop", "http://127.0.0.1:5050", load_config(str(ROOT / "examples/shop/policy.json")), tmp_path, browser=False, database_url="unavailable")
    assert result["persistence"] == "exports only"
    assert result["status"] == "partial"
    assert "secret-database-password" not in (tmp_path / "report.json").read_text()
    assert any(g["component"] == "storage" for g in result["coverage"]["gaps"])


def test_fastapi_scan_lifecycle_and_issue_details(shop, tmp_path):
    settings = Settings(source=str(ROOT / "examples/shop"), target="http://127.0.0.1:5050", config_path=str(ROOT / "examples/shop/policy.json"), output=str(tmp_path), browser=False)
    with local_client(create_app(settings)) as client:
        assert client.get("/").status_code == 200
        assert client.get("/style.css").status_code == 404
        assert client.get("/app.js").status_code == 404
        assert client.get("/health").status_code == 503
        assert client.get("/api/issues").status_code == 404
        assert client.post("/api/scans", json={}).status_code == 403
        headers = {"X-Navi":"local-scan"}
        assert client.post("/api/scans", json={}, headers={**headers,"Origin":"https://attacker.invalid"}).status_code == 403
        assert client.post("/api/scans", json={"target":"http://elsewhere.invalid"}, headers=headers).status_code == 422
        response = client.post("/api/scans",json={},headers=headers)
        assert response.status_code == 202
        scan_id = response.json()["id"]
        for _ in range(100):
            state = client.get("/api/state").json()
            if not state["running"]:
                break
            time.sleep(.02)
        assert not state["running"]
        assert state["error"] is None
        assert state["report"]["id"] == scan_id
        assert client.get(f"/api/scans/{scan_id}").status_code == 200
        confirmed = client.get("/api/issues?status=Confirmed").json()
        assert not confirmed
        provisional = client.get("/api/issues?status=Runtime%20only").json()
        assert any(i["source_link"]["status"] == "Probable source link" for i in provisional)
        issue = client.get(f'/api/issues/{provisional[0]["id"]}').json()
        assert issue["evidence"]
        assert client.get("/api/issues/not-real").status_code == 404
        assert client.get("/api/report.json").json()["id"] == scan_id
        assert client.get("/api/report.sarif").json()["version"] == "2.1.0"
        assert client.get("/api/function-map").json()["nodes"]
        assert "embedded-report" in client.get("/api/report.html").text
        events = client.get("/api/events").json()
        assert events["events"][-1]["type"] == "scan_finished"
        assert not client.get(f'/api/events?after={events["sequence"]}').json()["events"]


def test_api_concurrent_scan_rejected(tmp_path, monkeypatch):
    ready, release = threading.Event(), threading.Event()
    def blocked_scan(*args, **kwargs):
        ready.set(); release.wait(timeout=3)
        raise ValueError("deliberate failure")
    monkeypatch.setattr("navi.api.scan", blocked_scan)
    with local_client(create_app(Settings(source=str(ROOT / "examples/shop"), output=str(tmp_path)))) as client:
        headers = {"X-Navi":"local-scan"}
        assert client.post("/api/scans",json={},headers=headers).status_code == 202
        assert ready.wait(timeout=1)
        try:
            assert client.post("/api/scans",json={},headers=headers).status_code == 409
        finally:
            release.set()


def test_host_header_protection():
    with local_client(create_app()) as client:
        assert client.get("/",headers={"Host":"elsewhere.invalid"}).status_code == 400

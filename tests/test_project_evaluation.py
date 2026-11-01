import json
from copy import deepcopy
from pathlib import Path

import pytest

from navi.cli import main
from navi.engine import scan
from navi.evaluate import evaluate, validate_key
from navi.project import initialize, load_project, plan
from navi.runtime import load_config
from navi.static import analyze
from navi.candidates import native_candidates
from conftest import ROOT


def test_project_relative_paths_secrets_and_repeatable_cli(tmp_path, monkeypatch):
    project_file = tmp_path / "project.json"
    config = tmp_path / "scan.json"
    config.write_text(json.dumps({"requests": {"GET /products": {"headers": {"Authorization": {"$env": "CF_TEST_TOKEN"}}}}}))
    monkeypatch.setenv("CF_TEST_TOKEN", "private-value-do-not-export")
    initialize(project_file, ROOT / "examples/shop", config=config)
    project = load_project(project_file)
    assert project["source"] == str(ROOT / "examples/shop")
    assert load_config(str(config))["requests"]["GET /products"]["headers"]["Authorization"] == "private-value-do-not-export"
    assert "private-value-do-not-export" not in project_file.read_text()
    destination = tmp_path / "reports"
    for _ in range(2):
        assert main(["scan", "--project", str(project_file), "--output", str(destination), "--no-browser"]) == 0
    reports = [json.loads(p.read_text()) for p in destination.glob("scans/*/report.json")]
    assert len(reports) == 2 and reports[0]["project"] == reports[1]["project"] and reports[0]["id"] != reports[1]["id"]
    assert json.loads((destination / "report.json").read_text())["id"] in {r["id"] for r in reports}
    with pytest.raises(ValueError, match="already exists"): initialize(project_file, ROOT / "examples/shop")
    monkeypatch.delenv("CF_TEST_TOKEN")
    with pytest.raises(ValueError, match="CF_TEST_TOKEN"): load_config(str(config))


def test_plan_shares_runtime_candidates_without_network(monkeypatch):
    def forbidden(*a, **k): raise AssertionError("Planning contacted target")
    monkeypatch.setattr("navi.transport.Transport.request", forbidden)
    config = load_config(str(ROOT / "examples/shop/policy.json"))
    config["runtime_inputs"] = [{"route": "/extra", "parameter": "q"}]
    result = plan(ROOT / "examples/shop", "https://stage.example", config, False)
    actual = list(native_candidates(analyze(ROOT / "examples/shop"), config))
    assert len(result["tests"]) == len(actual)
    assert len([t for t in result["tests"] if t["route"] == "/extra"]) == 5
    assert "requests" not in result


@pytest.mark.parametrize("value", [{"scope": {"allowed_origins": ["https://stage.example/path"]}}, {"scope": {"allowed_origins": "https://stage.example"}}, {"limits": {"max_seconds": 0}}, {"limits": {"max_seconds": float("inf")}}, {"limits": {"max_seconds": True}}])
def test_new_configuration_contract(tmp_path, value):
    path = tmp_path / "scan.json"; path.write_text(json.dumps(value))
    with pytest.raises(ValueError): load_config(str(path))


def test_manual_fixture_answer_key_scored_independently(shop, tmp_path):
    key = json.loads((ROOT / "examples/answer-keys/shop.json").read_text())
    report = scan(ROOT / "examples/shop", "http://127.0.0.1:5050", load_config(str(ROOT / "examples/shop/policy.json")), tmp_path, browser=False)
    result = evaluate(report, key)
    assert result["metrics"]["code_recall"]["percent"] == 100
    assert result["metrics"]["runtime_recall"]["percent"] == 80
    assert result["metrics"]["correct_links"]["percent"] == 75
    assert result["metrics"]["decoy_issue_share"]["percent"] == 0
    assert result["metrics"]["unseen_pairs"]["percent"] is None
    assert not result["thresholds"]["great"]["metrics"]["runtime_recall"]["passes"]  # PRD is >80, not >=80
    assert not result["thresholds"]["good"]["all_thresholds_pass"]
    assert main(["evaluate", str(tmp_path / "report.json"), "--answer-key", str(ROOT / "examples/answer-keys/shop.json"), "--require", "good"]) == 3


def example():
    key = {"version": 1, "dataset": {"name": "unit", "provenance": "manually declared test anchors", "partition": "unseen"}, "complete": True,
           "cases": [{"id": f"pair-{n}", "kind": "paired", "cwe": "CWE-89", "source": {"file": "app.py", "line": n},
                      "runtime": {"route": f"/items{n}", "method": "GET", "parameter": "id", "location": "query"}} for n in (1, 2)]}
    findings = []
    for n, case in enumerate(key["cases"], 1):
        findings.extend([{"id": f"s{n}", "origin": "sast", "cwe": "CWE-89", "source": case["source"]},
                         {"id": f"d{n}", "origin": "dast", "cwe": "CWE-89", "verification": "verified", "bindings": [case["runtime"]]}])
    return {"schema_version": "1.0", "id": "scan", "status": "completed", "duration_seconds": 1, "findings": findings,
            "issues": [{"id": "i1", "status": "Confirmed", "findings": ["s1", "d1"]}, {"id": "i2", "status": "Confirmed", "findings": ["s2", "d2"]}]}, key


def test_evaluator_catches_crossed_links_without_losing_channel_recall():
    report, key = example()
    report["issues"][0]["findings"] = ["s1", "d2"]
    report["issues"][1]["findings"] = ["s2", "d1"]
    result = evaluate(report, key)
    assert result["metrics"]["code_recall"]["percent"] == result["metrics"]["runtime_recall"]["percent"] == 100
    assert result["metrics"]["correct_links"]["percent"] == 0
    assert result["metrics"]["wrong_links"]["percent"] == 100


def test_evaluator_deduplicates_hits_and_exposes_incomplete_truth():
    report, key = example()
    duplicate = deepcopy(report["findings"][0]); duplicate["id"] = "another-code-report"
    report["findings"].append(duplicate)
    assert evaluate(report, key)["metrics"]["code_recall"]["numerator"] == 2
    key["cases"].pop(); key["complete"] = False
    result = evaluate(report, key)
    assert result["unassessed_link_issue_ids"] == ["i2"]
    assert result["metrics"]["wrong_links"]["percent"] is None
    assert result["metrics"]["decoy_issue_share"]["percent"] is None


def test_evaluator_rejects_duplicate_case_anchors():
    _, key = example()
    duplicate = deepcopy(key["cases"][0]); duplicate["id"] = "inflated-recall"
    key["cases"].append(duplicate)
    with pytest.raises(ValueError, match="Duplicate source anchors"): validate_key(key)


def test_known_decoy_report_includes_code_and_runtime_issues():
    report, key = example()
    key["cases"][0]["kind"] = "decoy"
    result = evaluate(report, key)
    assert result["decoy_issue_ids"] == ["i1"]
    assert result["metrics"]["decoy_issue_share"]["percent"] == 50
    assert result["metrics"]["wrong_links"]["percent"] == 0


def test_unseen_pair_metric_uses_separate_application():
    report, key = example()
    key['dataset']['partition'] = 'provided'
    unseen_report, unseen_key = example()
    unseen_report['id'] = 'unseen-scan'
    unseen_report['issues'][1]['status'] = 'Code only'
    result = evaluate(report, key, unseen_report, unseen_key)
    assert result['metrics']['correct_links']['percent'] == 100
    assert result['metrics']['unseen_pairs']['percent'] == 50
    with pytest.raises(ValueError, match='different application'): evaluate(report, key, report, unseen_key)


def test_channel_precision_and_link_accuracy_are_distinct():
    report, key = example()
    result = evaluate(report, key)
    assert result['metrics']['code_precision']['percent'] == 100
    assert result['metrics']['runtime_precision']['percent'] == 100
    assert result['metrics']['link_accuracy']['percent'] == 100
    report['issues'][0]['findings'] = ['s1', 'd2']
    report['issues'][1]['findings'] = ['s2', 'd1']
    crossed = evaluate(report, key)
    assert crossed['metrics']['runtime_recall']['percent'] == 100
    assert crossed['metrics']['link_accuracy']['percent'] == 0


def test_unmatched_precision_requires_complete_truth():
    from copy import deepcopy
    report, key = example()
    extra = deepcopy(next(f for f in report['findings'] if f['origin'] == 'dast'))
    extra['id'] = 'unknown-runtime'; extra['bindings'][0]['route'] = '/unreviewed'
    report['findings'].append(extra)
    complete = evaluate(report, key)
    assert complete['metrics']['runtime_precision']['percent'] == 66.667
    key['complete'] = False
    partial = evaluate(report, key)
    assert partial['metrics']['runtime_precision']['percent'] is None
    assert partial['metrics']['runtime_precision']['unavailable_reason']


def test_probable_links_do_not_inflate_confirmed_link_scores():
    report, key = example()
    for issue in report['issues']:
        issue.update(status='Runtime only', source_link={'status': 'Probable source link'})
    result = evaluate(report, key)
    assert result['metrics']['code_recall']['percent'] == 100
    assert result['metrics']['runtime_recall']['percent'] == 100
    assert result['metrics']['correct_links']['percent'] == 0
    assert result['metrics']['link_accuracy']['percent'] is None
    assert result['probable_source_link_issue_ids'] == ['i1', 'i2']

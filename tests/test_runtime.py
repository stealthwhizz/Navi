from copy import deepcopy
import runpy

from flask import Flask, jsonify, request
import pytest

from navi.correlate import correlate
from navi.model import Binding
from navi.runtime import Runtime, load_config
from navi.static import analyze
from conftest import ROOT


def shop_runtime(browser=False):
    config = load_config(str(ROOT / "examples/shop/policy.json"))
    config["interval"] = 0
    return Runtime(analyze(ROOT / "examples/shop"), "http://127.0.0.1:5050", config, browser=browser)


def test_native_runtime_and_policy_results(shop):
    runtime = shop_runtime()
    findings = runtime.run()
    assert runtime.build["status"] == "matched"
    assert {f.cwe for f in findings} == {"CWE-89", "CWE-22", "CWE-601", "CWE-639"}
    assert not any(f.cwe == "CWE-79" for f in findings)
    assert any(c.cwe == "CWE-79" and c.outcome == "inconclusive" for c in runtime.checks)
    assert all(c.outcome == "not_reproduced" for c in runtime.checks if c.route.startswith(("/safe", "/shared")))
    idor = next(f for f in findings if f.cwe == "CWE-639")
    assert len(idor.evidence) == 4  # Two objects, permitted and forbidden requests each.
    assert idor.verification == "verified"
    assert all(value == "[redacted]" for evidence in idor.evidence for value in evidence["request"]["headers"].values())
    issues = correlate(runtime.analysis, findings, runtime.build)
    assert len(issues) == 9
    assert sum(i["status"] == "Confirmed" for i in issues) == 0
    assert sum(i["source_link"]["status"] == "Probable source link" for i in issues) == 3
    assert next(i for i in issues if i["cwe"] == "CWE-639")["status"] == "Runtime only"


def test_second_app_runs_without_first_app_routes(connect_app):
    app = connect_app(runpy.run_path(str(ROOT / "examples/library/app.py"))["app"])
    config = load_config(str(ROOT / "examples/library/policy.json")); config["interval"] = 0
    runtime = Runtime(analyze(ROOT / "examples/library"), "http://127.0.0.1:5051", config, browser=False)
    findings = runtime.run()
    assert {f.cwe for f in findings} == {"CWE-89", "CWE-22", "CWE-601"}
    issues = correlate(runtime.analysis, findings, runtime.build)
    sql = next(i for i in issues if i["cwe"] == "CWE-89")
    assert sql["source_link"]["status"] == "Probable source link"
    candidate = next(i for i in issues if i["id"] in sql["candidate_source_ids"])
    assert candidate["source"]["file"] == "queries.py"
    assert sql["status"] == "Runtime only"
    assert all(b["route"].startswith("/v2/") for i in issues for b in i["bindings"])


def test_build_mismatch_withholds_source_links(shop):
    shop.view_functions["build"] = lambda: jsonify(source_digest="different-build")
    runtime = shop_runtime()
    findings = runtime.run()
    assert runtime.build["status"] == "mismatch"
    issues = correlate(runtime.analysis, findings, runtime.build)
    assert not any(i["status"] == "Confirmed" for i in issues)
    assert any(i["candidate_source_ids"] for i in issues if i["status"] == "Runtime only")


def test_same_route_and_cwe_do_not_merge_ambiguous_operations(shop):
    runtime = shop_runtime()
    findings = runtime.run()
    sql = next(f for f in runtime.analysis.findings if f.cwe == "CWE-89")
    second = deepcopy(sql); second.id = "second-operation"; second.source["line"] += 1
    runtime.analysis.findings.append(second)
    sql_issues = [i for i in correlate(runtime.analysis, findings, runtime.build) if i["cwe"] == "CWE-89"]
    assert len(sql_issues) == 3
    assert not any(i["status"] == "Confirmed" for i in sql_issues)
    runtime_issue = next(i for i in sql_issues if i["status"] == "Runtime only")
    assert runtime_issue["link_confidence"] == "ambiguous"
    assert set(runtime_issue["candidate_source_ids"]) == {sql.id, second.id}


def test_duplicate_runtime_observations_preserve_one_issue(shop):
    runtime = shop_runtime(); findings = runtime.run()
    once = correlate(runtime.analysis, findings, runtime.build)
    repeated = correlate(runtime.analysis, findings + deepcopy(findings), runtime.build)
    assert once == repeated


def test_no_policy_never_guesses_authorization(shop):
    runtime = shop_runtime(); runtime.config.pop("authorization")
    runtime.authorization()
    assert not runtime.findings
    assert runtime.checks[0].outcome == "skipped"


def test_unverified_identity_prevents_idor_claim(shop):
    runtime = shop_runtime()
    runtime.config["authorization"]["identities"]["alice"]["expected_identity"] = "someone-else"
    runtime.authorization()
    assert not runtime.findings
    assert any(c.outcome == "inconclusive" for c in runtime.checks)


def test_http_200_denial_is_not_idor(shop):
    shop.view_functions["order"] = lambda order_id: jsonify(message="permission denied")
    runtime = shop_runtime(); runtime.authorization()
    assert not runtime.findings
    assert any(c.outcome == "inconclusive" and c.route == "/orders/<int:order_id>" for c in runtime.checks)


def test_parameterized_query_does_not_verify(shop):
    runtime = shop_runtime()
    outcome, _, _ = runtime.sql(Binding("/safe/products", "GET", "id", "query", "safe_products"))
    assert outcome == "not_reproduced"


def test_reflection_is_not_sql_proof(connect_app):
    app = Flask(__name__)
    @app.get("/echo")
    def echo():
        return jsonify(value=request.args.get("value"))
    connect_app(app)
    runtime = shop_runtime()
    outcome, _, _ = runtime.sql(Binding("/echo", "GET", "value", "query", "echo"))
    assert outcome == "not_reproduced"


def test_missing_traversal_fixture_is_inconclusive(shop):
    runtime = shop_runtime(); runtime.config["traversal_fixtures"] = []
    outcome, _, _ = runtime.traversal(Binding("/download", "GET", "file", "query", "download"))
    assert outcome == "inconclusive"


def test_request_budget_failure_preserves_completed_findings(shop):
    runtime = shop_runtime(); runtime.transport.max_requests = 7
    findings = runtime.run()
    assert any(f.cwe == "CWE-89" for f in findings)
    assert any(c.outcome == "error" for c in runtime.checks)
    assert runtime.transport.count == 7


def test_missing_browser_does_not_abort_other_checks(shop, monkeypatch):
    from navi.browser import BrowserUnavailable
    runtime = shop_runtime(browser=True)
    def unavailable():
        raise BrowserUnavailable("No browser installed")
    monkeypatch.setattr(runtime.browser, "start", unavailable)
    findings = runtime.run()
    assert {"CWE-89", "CWE-22", "CWE-601"}.issubset({f.cwe for f in findings})
    assert any(c.cwe == "CWE-79" and c.outcome == "inconclusive" for c in runtime.checks)

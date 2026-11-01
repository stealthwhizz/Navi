from copy import deepcopy
import runpy
import shutil

from navi.api import Settings, create_app
from navi.engine import scan
from navi.lab import AccessLab
from navi.runtime import load_config
from conftest import ROOT
from test_api_reports import local_client


def lab():
    return AccessLab(ROOT / "examples/shop", "http://127.0.0.1:5050",load_config(str(ROOT / "examples/shop/policy.json")))


def selection(instance):
    return next(r for r in instance.catalog()["resources"] if r["route"] == "/orders/<int:order_id>" and r["value"] == "2")


def test_lab_violation_and_protected_implementation_use_real_policy_checks(shop):
    instance=lab(); selected=selection(instance)
    result=instance.experiment(selected["id"],"alice",compare=True)
    assert result["before"]["outcome"] == "violation"
    assert result["before"]["request"]["status"] == 200
    assert result["after"]["outcome"] == "blocked"
    assert result["after"]["request"]["status"] == 403
    assert result["comparison"]["verified"]
    assert any("resource[\"owner\"]" in line for line in result["comparison"]["source_diff"])
    assert result["before"]["baseline"]["request"]["identity"] == "bob"
    assert result["before"]["request"]["request"]["identity"] == "alice"
    assert result["before"]["build"]["status"] == "matched"


def test_permitted_owner_is_not_labeled_as_a_breach(shop):
    instance=lab(); selected=selection(instance)
    result=instance.experiment(selected["id"],"bob",compare=True)
    assert result["before"]["outcome"] == "permitted"
    assert result["after"]["outcome"] == "permitted"
    assert not result["comparison"]["verified"]


def test_lab_does_not_export_authentication_headers(shop):
    instance=lab()
    catalog=instance.catalog()
    assert "headers" not in str(catalog)
    result=instance.experiment(selection(instance)["id"],"alice")
    assert all(value == "[redacted]" for value in result["before"]["request"]["request"]["headers"].values())


def test_lab_invalid_identity_leaves_result_inconclusive(shop):
    instance=lab()
    instance.config["authorization"]["identities"]["alice"]["expected_identity"]="not-alice"
    result=instance.experiment(selection(instance)["id"],"alice",compare=True)
    assert result["before"]["outcome"] == "inconclusive"
    assert not result["comparison"]["verified"]


def test_lab_api_restricts_tests_to_configured_resources(shop,tmp_path):
    settings=Settings(source=str(ROOT/"examples/shop"),target="http://127.0.0.1:5050",config_path=str(ROOT/"examples/shop/policy.json"),output=str(tmp_path),browser=False)
    with local_client(create_app(settings)) as client:
        catalog=client.get("/api/lab").json()
        assert catalog["available"]
        headers={"X-Navi":"local-scan"}
        assert client.post("/api/lab/experiments",json={"resource_id":"external","actor":"alice"},headers=headers).status_code == 422
        selected=next(r for r in catalog["resources"] if r["comparison_route"] and r["value"] == "2")
        result=client.post("/api/lab/experiments",json={"resource_id":selected["id"],"actor":"alice","compare":True},headers=headers)
        assert result.status_code == 200
        assert result.json()["comparison"]["verified"]


def test_recreated_demo_keeps_scan_and_experiment_project_identity(tmp_path, connect_app):
    reports = []
    projects = []
    for directory in ("first-start", "after-restart"):
        source = tmp_path / directory
        shutil.copytree(ROOT / "examples/shop", source, ignore=shutil.ignore_patterns("__pycache__"))
        connect_app(runpy.run_path(str(source / "app.py"))["app"])
        config = load_config(str(source / "policy.json"))
        config["interval"] = 0
        target = "http://127.0.0.1:5050"
        report = scan(source, target, config, tmp_path / (directory + "-reports"),
                      browser=False, project_key="builtin:shop")
        instance = AccessLab(source, target, config, project_key="builtin:shop")
        experiment = instance.experiment(selection(instance)["id"], "alice", compare=True)
        assert experiment["comparison"]["verified"]
        assert experiment["project"] == report["project"]
        reports.append(report)
        projects.append(experiment["project"])
    assert reports[0]["source"] != reports[1]["source"]
    assert projects[0] == projects[1]
    assert reports[0]["source_digest"] == reports[1]["source_digest"]
    assert {issue["id"] for issue in reports[0]["issues"]} == {issue["id"] for issue in reports[1]["issues"]}

import json

import pytest

from navi.cli import main
from navi.runtime import load_config
from conftest import ROOT


@pytest.mark.parametrize("value", [[], {"unknown":True}, {"timeout":-1}, {"max_requests":2.5}, {"requests":[]}, {"requests":{"GET /x":{"json":{},"form":{}}}}, {"allowed_methods":["get"]}, {"authorization":{"identities":[]}}])
def test_invalid_configuration_is_rejected(tmp_path,value):
    path = tmp_path / "policy.json"; path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_config(str(path))


def test_static_cli_exports_and_partial_exit(tmp_path):
    result = main(["scan","--source",str(ROOT / "examples/shop"),"--output",str(tmp_path),"--require-complete"])
    assert result == 3
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["summary"]["code_only"] == 5
    assert report["function_map"]["nodes"]


def test_uninstrumented_verified_issue_does_not_trigger_confirmed_gate(shop, tmp_path):
    result = main(["scan","--source",str(ROOT / "examples/shop"),"--target","http://127.0.0.1:5050","--config",str(ROOT / "examples/shop/policy.json"),"--output",str(tmp_path),"--no-browser","--fail-on-confirmed-high"])
    assert result == 0  # Runtime proof is retained; use --fail-on-verified-high to gate it.

import io
from pathlib import Path
import runpy
import shutil

import pytest

from scripts.showcase_fixture import execute_php_fixture, prepare_showcase
from navi.model import Binding
from navi.runtime import Runtime, load_config
from navi.static import analyze
from conftest import ROOT


pytestmark = pytest.mark.skipif(not shutil.which("php"), reason="PHP CLI is required for PHP lexer and real execution fixtures")


def test_php_request_helper_shell_flow_and_quoted_decoy():
    result = analyze(ROOT / "examples/php_shell")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.cwe == "CWE-78" and finding.severity == "critical"
    assert finding.source["function"] == "run_diagnostic"
    assert finding.source["file"] == "helpers.php"
    assert finding.bindings[0].parameter == "target"
    assert finding.bindings[0].route == "/diagnostics.php"
    assert "helpers.php:run_diagnostic" in finding.bindings[0].flow
    helper = next(n for n in result.function_map["nodes"] if n["name"] == "run_diagnostic")
    assert helper["callers"]
    assert not any(f.source["function"] == "run_safe_diagnostic" for f in result.findings)


@pytest.mark.parametrize("statement,expected", [
    ("system('printf %s ' . $_GET['x']);", 1),
    ("exec(escapeshellarg($_GET['x']));", 1),
    ("passthru('printf %s ' . escapeshellarg($_GET['x']));", 0),
    ("proc_open(['printf', $_GET['x']], [], $pipes);", 0),
    ("$x=$_POST['value']; shell_exec('printf %s ' . $x);", 1),
    (' $x=$_GET[\'x\']; echo `printf "$x"`; ', 1),
    ("$x=$_GET['x']; $command='printf %s '; $command.=$x; system($command);", 1),
    ("shell_exec('sh -c ' . escapeshellarg($_GET['x']));", 1),
    ('''shell_exec("printf '" . escapeshellarg($_GET['x']) . "'");''', 1),
])
def test_php_patterns(tmp_path, statement, expected):
    (tmp_path / "index.php").write_text("<?php " + statement)
    result=analyze(tmp_path)
    assert len(result.findings) == expected


def test_php_fingerprint_survives_blank_lines(tmp_path):
    file=tmp_path / "index.php"
    file.write_text("<?php\n$x=$_GET['x'];\nsystem('printf %s ' . $x);\n")
    before=analyze(tmp_path).findings[0]
    file.write_text("<?php\n\n\n$x=$_GET['x'];\n\nsystem('printf %s ' . $x);\n")
    after=analyze(tmp_path).findings[0]
    assert before.id == after.id
    assert before.source["line"] != after.source["line"]


def test_php_actual_command_execution_and_safe_replay(tmp_path,connect_app):
    root=prepare_showcase(tmp_path / "showcase")
    connect_app(runpy.run_path(str(root / "app.py"))["app"])
    runtime=Runtime(analyze(root), "http://127.0.0.1:5050", load_config(str(root / "policy.json")), browser=False)
    outcome,reason,evidence=runtime.command(Binding("/diagnostics.php","GET","target","query","<entry>"))
    assert outcome == "verified",reason
    probes=[e for e in evidence if "execution_proof" in e]
    assert len(probes) == 2
    assert all(e["execution_proof"]["observed"] and not e["execution_proof"]["marker_in_payload"] for e in probes)
    safe=runtime.command(Binding("/diagnostics_safe.php","GET","target","query","<entry>"))
    assert safe[0] == "not_reproduced"


def test_php_plain_reflection_cannot_satisfy_marker_proof(shop):
    from flask import request
    shop.add_url_rule("/reflect", "reflect", lambda: request.args.get("target", ""))
    runtime=Runtime(analyze(ROOT / "examples/php_shell"),"http://127.0.0.1:5050",{},browser=False)
    assert runtime.command(Binding("/reflect","GET","target","query","reflect"))[0] == "not_reproduced"


def test_escape_decoding_reflection_is_not_command_execution(shop):
    import codecs
    from flask import request
    shop.add_url_rule("/decode", "decode", lambda: codecs.decode(request.args.get("target", ""), "unicode_escape"))
    runtime=Runtime(analyze(ROOT / "examples/php_shell"),"http://127.0.0.1:5050",{},browser=False)
    assert runtime.command(Binding("/decode","GET","target","query","decode"))[0] == "inconclusive"


def test_showcase_never_overwrites_existing_source(tmp_path):
    (tmp_path / "valuable.py").write_text("keep me")
    with pytest.raises(ValueError): prepare_showcase(tmp_path)
    assert (tmp_path / "valuable.py").read_text() == "keep me"

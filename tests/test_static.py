import textwrap

import pytest

from navi.static import analyze
from conftest import ROOT


PREFIX = "from flask import Flask, request, jsonify, redirect, send_from_directory, Response\nfrom markupsafe import escape\napp=Flask(__name__)\n"


def endpoint(body, route="/probe"):
    return PREFIX + f'@app.get("{route}")\ndef probe(value=None):\n' + textwrap.indent(body, "    ") + "\n"


@pytest.mark.parametrize("body,cwe", [
    ('value=request.args.get("q")\ndb.execute(f"SELECT * FROM t WHERE x=\'{value}\'")\nreturn jsonify(ok=True)', "CWE-89"),
    ('return "<b>" + request.args["name"] + "</b>"', "CWE-79"),
    ('return redirect(request.args.get("next"))', "CWE-601"),
    ('return open("public/" + request.args["file"]).read()', "CWE-22"),
    ('data=request.get_json()\nvalue=data.get("search")\ndb.execute("SELECT * FROM t WHERE x=" + value)\nreturn jsonify(ok=True)', "CWE-89"),
])
def test_native_patterns(source, body, cwe):
    analysis = analyze(source(endpoint(body)))
    findings = [f for f in analysis.findings if f.cwe == cwe]
    assert len(findings) == 1
    assert findings[0].bindings[0].route == "/probe"


@pytest.mark.parametrize("body", [
    'db.execute("SELECT * FROM t WHERE x=?", (request.args["q"],))\nreturn jsonify(ok=True)',
    'return "<h1>" + escape(request.args["name"]) + "</h1>"',
    'return jsonify(value=request.args["name"])',
    'return {"value":request.args["name"]}',
    'return send_from_directory("public",request.args["file"])',
    'return Response(request.args["x"],mimetype="text/plain")',
    'value=int(request.args["id"])\ndb.execute(f"SELECT * FROM t WHERE id={value}")\nreturn jsonify(ok=True)',
])
def test_protected_patterns(source, body):
    assert analyze(source(endpoint(body))).findings == []


def test_fixture_detection_and_decoys():
    result = analyze(ROOT / "examples/shop")
    assert {f.cwe for f in result.findings} == {"CWE-89", "CWE-79", "CWE-22", "CWE-601", "CWE-798"}
    assert not any(b.route.startswith("/safe") for f in result.findings for b in f.bindings)
    secret = next(f for f in result.findings if f.cwe == "CWE-798")
    assert "[redacted literal]" in secret.source["snippet"]
    assert "7q9x2" not in secret.source["snippet"]


def test_imported_helper_and_blueprint():
    result = analyze(ROOT / "examples/library")
    sql = next(f for f in result.findings if f.cwe == "CWE-89")
    assert sql.source["file"] == "queries.py"
    assert sql.bindings[0].route == "/v2/search"
    assert "queries.py:find_book" in sql.bindings[0].flow
    xss = next(f for f in result.findings if f.cwe == "CWE-79")
    assert xss.bindings[0].method == "POST"
    assert xss.bindings[0].location == "form"
    search = next(n for n in result.function_map["nodes"] if n["name"] == "search")
    helper = next(n for n in result.function_map["nodes"] if n["name"] == "find_book")
    assert search["id"] in helper["callers"]
    assert helper["reachable_from"] == [{"route":"/v2/search","methods":["GET"]}]
    assert helper["operations"][0]["cwe"] == "CWE-89"
    assert any(e["caller"] == search["id"] and e["callee"] == helper["id"] for e in result.function_map["edges"])


def test_identity_survives_line_number_changes(source):
    code = endpoint('return request.args["name"]')
    original = analyze(source(code)).findings[0]
    moved = analyze(source("\n\n\n" + code)).findings[0]
    assert original.id == moved.id
    assert original.source["line"] != moved.source["line"]


def test_shared_helper_keeps_one_source_operation(source):
    code = PREFIX + '''
def lookup(value):
    db.execute("SELECT * FROM t WHERE id=" + value)
@app.get("/one")
def one():
    lookup(request.args["id"])
    return "ok"
@app.get("/two")
def two():
    lookup(request.args["id"])
    return "ok"
'''
    findings = analyze(source(code)).findings
    assert len(findings) == 1
    assert {b.route for b in findings[0].bindings} == {"/one", "/two"}


def test_two_identical_operations_are_distinct(source):
    result = analyze(source(endpoint('value=request.args["q"]\ndb.execute("SELECT " + value)\ndb.execute("SELECT " + value)\nreturn "ok"')))
    assert len(result.findings) == 2
    assert len({f.id for f in result.findings}) == 2


def test_integer_path_converter_is_modeled(source):
    result = analyze(source(endpoint('db.execute(f"SELECT * FROM t WHERE id={value}")\nreturn "ok"', "/item/<int:value>")))
    assert result.findings == []


def test_syntax_error_is_coverage_gap(source):
    result = analyze(source("invalid python ???"))
    assert result.gaps
    assert result.files == 0


def test_dynamic_route_is_not_invented(source):
    result = analyze(source(PREFIX + '@app.get(prefix + "/dynamic")\ndef view():\n    return request.args["x"]\n'))
    assert result.routes == []
    assert any("Dynamic route" in g["reason"] for g in result.gaps)


def test_custom_escape_function_does_not_imply_safety(source):
    code = 'from flask import Flask, request\napp=Flask(__name__)\ndef escape(x):\n    return x\n@app.get("/x")\ndef view():\n    return escape(request.args["x"])\n'
    assert any(f.cwe == "CWE-79" for f in analyze(source(code)).findings)


def test_unknown_transformation_can_undo_sanitizer(source):
    code = endpoint('return unknown_transform(escape(request.args["value"]))')
    assert any(f.cwe == "CWE-79" for f in analyze(source(code)).findings)


def test_html_escaping_does_not_prove_url_context_safe(source):
    code = endpoint('value=escape(request.args["value"])\nreturn f\'<a href="{value}">Go</a>\'')
    assert any(f.cwe == "CWE-79" for f in analyze(source(code)).findings)


def test_function_without_route_path_remains_unknown(source):
    code = PREFIX + 'def background_job():\n    unknown_library.work()\n'
    result = analyze(source(code))
    node = result.function_map["nodes"][0]
    assert node["reachability"] == "unknown"
    assert result.function_map["edges"][0]["resolved"] is False

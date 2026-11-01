from pathlib import Path
import runpy
import shutil

from navi.model import Binding
from navi.runtime import Runtime, load_config
from navi.static import analyze
from conftest import ROOT


def test_fix_and_retest_preserves_legitimate_behavior(tmp_path, connect_app):
    source = tmp_path / "shop"
    shutil.copytree(ROOT / "examples/shop", source, ignore=shutil.ignore_patterns("__pycache__"))
    config = load_config(str(source / "policy.json")); config["interval"] = 0
    connect_app(runpy.run_path(str(source / "app.py"))["app"])
    before = Runtime(analyze(source), "http://127.0.0.1:5050", config, browser=False)
    assert {f.cwe for f in before.run()} == {"CWE-89", "CWE-22", "CWE-601", "CWE-639"}

    # Apply actual source fixes to the copy, then load the changed application.
    code = (source / "app.py").read_text()
    code = code.replace('APP_SECRET = "cf-local-lab-credential-7q9x2"', 'APP_SECRET = None')
    code = code.replace('db.execute(f"SELECT id, name FROM products WHERE id = \'{item}\'")', 'db.execute("SELECT id, name FROM products WHERE id = ?", (item,))')
    code = code.replace('name = request.args.get("name", "visitor")', 'name = escape(request.args.get("name", "visitor"))')
    code = code.replace('return send_file(ROOT / "public" / name)', 'return send_from_directory(ROOT / "public", name)')
    code = code.replace('return redirect(destination)', 'return redirect("/")')
    code = code.replace('    return jsonify(orders[order_id])', '    if request.headers.get("X-Test-User") != orders[order_id]["owner"]:\n        abort(403)\n    return jsonify(orders[order_id])')
    (source / "app.py").write_text(code)
    fixed = connect_app(runpy.run_path(str(source / "app.py"))["app"])
    after = Runtime(analyze(source), "http://127.0.0.1:5050", config, browser=False)
    assert after.analysis.findings == []
    assert after.run() == []
    assert after.build["status"] == "matched"

    # Replay the old targeted verifiers even though static suspicion disappeared.
    assert after.sql(Binding("/products","GET","id","query","products"))[0] == "not_reproduced"
    assert after.traversal(Binding("/download","GET","file","query","download"))[0] == "not_reproduced"
    assert after.redirect(Binding("/leave","GET","next","query","leave"))[0] == "not_reproduced"
    client = fixed.test_client()
    assert client.get("/products?id=1").json == [[1,"Notebook"]]
    assert client.get("/download?file=welcome.txt").status_code == 200
    assert client.get("/orders/1",headers={"X-Test-User":"alice"}).status_code == 200
    assert client.get("/orders/1",headers={"X-Test-User":"bob"}).status_code == 403
    response = client.get("/greet",query_string={"name":"<svg onload=alert(1)>"})
    assert b"&lt;svg" in response.data and b"<svg" not in response.data

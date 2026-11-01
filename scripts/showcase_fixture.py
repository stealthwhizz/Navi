"""Local demo composition. These intentionally vulnerable targets are not product endpoints."""

from pathlib import Path
import json
import shutil
import subprocess


PHP_RUNNER = r'''$input=json_decode(stream_get_contents(STDIN),true);$_GET=$input['query'];$_POST=[];$_REQUEST=$_GET;include $input['file'];'''


def execute_php_fixture(root, script, query):
    root = Path(root).resolve()
    path = (root / script).resolve()
    if script not in {"diagnostics.php", "diagnostics_safe.php"} or not path.is_relative_to(root):
        raise ValueError("Only bundled PHP diagnostic fixtures may be executed.")
    result = subprocess.run(["php", "-r", PHP_RUNNER], input=json.dumps({"file": str(path), "query": query}),
                            text=True, capture_output=True, timeout=3)
    return (result.stdout, 200) if result.returncode == 0 else ("PHP fixture execution failed.", 500)


def prepare_showcase(destination):
    """Compose bundled, inspectable source into a new demo directory."""
    root = Path(__file__).resolve().parent.parent
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("Showcase generation requires an empty destination; existing files are never replaced.")
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(root / "examples/shop", destination, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__"))
    for path in (root / "examples/php_shell").glob("*.php"):
        shutil.copy2(path, destination / path.name)
    bridge = '''

# Local demo transport: real PHP execution, exposed only through these fixed fixtures.
from scripts.showcase_fixture import execute_php_fixture

@app.get("/diagnostics.php")
def php_diagnostics():
    body, status = execute_php_fixture(ROOT, "diagnostics.php", request.args.to_dict())
    return app.response_class(body, status=status, mimetype="text/plain")

@app.get("/diagnostics_safe.php")
def php_diagnostics_safe():
    body, status = execute_php_fixture(ROOT, "diagnostics_safe.php", request.args.to_dict())
    return app.response_class(body, status=status, mimetype="text/plain")
'''
    application = destination / "app.py"
    application_source = application.read_text()
    customers = {"alice": {"customer_email": "alice.rao@example.test", "delivery_address": "Apartment 12, 8 Sample Street", "order_total": "INR 6,499"},
                 "bob": {"customer_email": "bob.sen@example.test", "delivery_address": "Apartment 7, 21 Example Avenue", "order_total": "INR 12,990"}}
    for owner, note in [("alice", "ALICE-PRIVATE-ORDER-7c8d"), ("bob", "BOB-PRIVATE-ORDER-4e5f")]:
        original = f'"private_note": "{note}"'
        extra = ", ".join(f'{json.dumps(key)}: {json.dumps(value)}' for key, value in customers[owner].items())
        application_source = application_source.replace(original, original + ", " + extra)
    application.write_text(application_source + bridge)
    config_file = destination / "policy.json"
    config = json.loads(config_file.read_text())
    config["requests"]["GET /diagnostics.php"] = {"query": {"target": "demo"}}
    config["requests"]["GET /diagnostics_safe.php"] = {"query": {"target": "demo"}}
    for resource in config["authorization"]["resources"]:
        if len(resource["allowed"]) == 1 and resource["allowed"][0] in customers:
            customer = customers[resource["allowed"][0]]
            resource["json_match"].update(customer_email=customer["customer_email"], delivery_address=customer["delivery_address"])
    config_file.write_text(json.dumps(config, indent=2) + "\n")
    return destination

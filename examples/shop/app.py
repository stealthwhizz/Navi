"""Intentionally vulnerable local fixture. Never deploy this application."""

from pathlib import Path
import sqlite3

from flask import Flask, abort, jsonify, redirect, request, send_file, send_from_directory
from markupsafe import escape

from navi.static import source_digest


app = Flask(__name__)
ROOT = Path(__file__).resolve().parent
STARTUP_DIGEST = source_digest(ROOT)
APP_SECRET = "cf-local-lab-credential-7q9x2"


def database():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE products (id INTEGER, name TEXT)")
    connection.executemany("INSERT INTO products VALUES (?, ?)", [(1, "Notebook"), (2, "Headphones"), (3, "Coffee")])
    return connection


@app.get("/")
def home():
    return "<h1>Navi local shop fixture</h1><p>Use the scanner dashboard to inspect this application.</p>"


@app.get("/__navi__/build")
def build():
    return jsonify(source_digest=STARTUP_DIGEST)


@app.get("/whoami")
def whoami():
    # This fixture intentionally uses a deterministic test identity header.
    return jsonify(user=request.headers.get("X-Test-User", "anonymous"))


@app.get("/products")
def products():
    item = request.args.get("id", "1")
    db = database()
    rows = db.execute(f"SELECT id, name FROM products WHERE id = '{item}'").fetchall()
    db.close()
    return jsonify(rows)


@app.get("/greet")
def greet():
    name = request.args.get("name", "visitor")
    return f"<main><h1>Hello, {name}</h1></main>"


@app.get("/download")
def download():
    name = request.args.get("file", "welcome.txt")
    return send_file(ROOT / "public" / name)


@app.get("/leave")
def leave():
    destination = request.args.get("next", "/")
    return redirect(destination)


@app.get("/orders/<int:order_id>")
def order(order_id):
    orders = {1: {"id": 1, "owner": "alice", "private_note": "ALICE-PRIVATE-ORDER-7c8d"},
              2: {"id": 2, "owner": "bob", "private_note": "BOB-PRIVATE-ORDER-4e5f"}}
    if order_id not in orders:
        abort(404)
    return jsonify(orders[order_id])


@app.get("/safe/products")
def safe_products():
    item = request.args.get("id", "1")
    db = database()
    rows = db.execute("SELECT id, name FROM products WHERE id = ?", (item,)).fetchall()
    db.close()
    return jsonify(rows)


@app.get("/safe/greet")
def safe_greet():
    name = escape(request.args.get("name", "visitor"))
    return f"<main><h1>Hello, {name}</h1></main>"


@app.get("/safe/download")
def safe_download():
    name = request.args.get("file", "welcome.txt")
    return send_from_directory(ROOT / "public", name)


@app.get("/safe/leave")
def safe_leave():
    # A fixed destination gives the static engine an unambiguous protected case.
    return redirect("/")


@app.get("/safe/orders/<int:order_id>")
def safe_order(order_id):
    orders = {1: {"id": 1, "owner": "alice", "private_note": "ALICE-PRIVATE-ORDER-7c8d"},
              2: {"id": 2, "owner": "bob", "private_note": "BOB-PRIVATE-ORDER-4e5f"}}
    resource = orders.get(order_id)
    if resource is None:
        abort(404)
    if request.headers.get("X-Test-User") != resource["owner"]:
        abort(403)
    return jsonify(resource)


@app.get("/shared/orders/<int:order_id>")
def shared_order(order_id):
    if order_id != 3:
        abort(404)
    return jsonify(id=3, private_note="DELIBERATELY-SHARED-ORDER")

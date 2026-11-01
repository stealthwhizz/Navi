"""Second fixture: different routes, a blueprint, POST data, and an imported helper."""

from pathlib import Path

from flask import Blueprint, Flask, jsonify, redirect, request, send_file

from navi.static import source_digest
from examples.library.queries import find_book


app = Flask(__name__)
catalog = Blueprint("catalog", __name__, url_prefix="/v2")
ROOT = Path(__file__).resolve().parent
STARTUP_DIGEST = source_digest(ROOT)


@app.get("/__navi__/build")
def build():
    return jsonify(source_digest=STARTUP_DIGEST)


@catalog.get("/search")
def search():
    reference = request.args.get("reference", "BK1")
    return jsonify(find_book(reference))


@catalog.post("/preview")
def preview():
    caption = request.form.get("caption", "Hello")
    return "<section>" + caption + "</section>"


@catalog.get("/document")
def document():
    document_name = request.args.get("document", "readme.txt")
    return send_file(ROOT / "public" / document_name)


@catalog.get("/continue")
def continue_to():
    return redirect(request.args.get("destination", "/v2/search"))


app.register_blueprint(catalog)

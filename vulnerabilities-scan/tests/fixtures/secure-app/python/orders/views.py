"""Secure look-alike of python/orders/views.py.

Each function performs the same task as its vulnerable twin and is protected by
a control the analyzer knows how to recognise. The tests assert that none of
these produce a finding.
"""
import os
from pathlib import Path

import bcrypt
import jwt
import requests
import yaml
from flask import Flask, HttpResponse, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

ALLOWED_COLUMNS = {"name", "created_at"}
ALLOWED_HOSTS = {"api.partner.example"}
ALLOWED_EXTENSIONS = {"png", "jpg"}


def validate_url(candidate):
    return candidate if candidate.split("/")[2] in ALLOWED_HOSTS else None


@app.get("/orders")
@login_required
def list_orders():
    term = request.args["term"]
    # Parameterised: the value is bound, never part of the statement text.
    rows = db.execute("SELECT * FROM orders WHERE name = %s", (term,)).fetchall()
    column = request.args["sort"]
    order_by = ALLOWED_COLUMNS.get(column, "name")
    return str(rows) + order_by


@app.get("/orders/<order_id>")
@login_required
def show_order(order_id):
    # Ownership is part of the lookup, so one tenant cannot read another's row.
    order = Order.query.filter_by(id=order_id, owner_id=current_user.id).first_or_404()
    return str(order)


@app.post("/orders/report")
def report():
    # Argument vector, no shell: the name is a separate argv entry.
    subprocess.run(["tar", "-czf", "/tmp/report.tar", request.args["name"]])
    return "ok"


@app.get("/files")
def download():
    # The client name is reduced to a basename and confined to the data root.
    target = (Path("/srv/data") / secure_filename(request.args["name"])).resolve()
    return target.read_text()


@app.get("/preview")
def preview():
    # Only allow-listed hosts are fetched.
    target = validate_url(request.args["url"])
    return requests.get(target).text if target else "blocked"


@app.post("/orders/price")
@login_required
def quote():
    # The amount is computed server-side from the stored cart.
    price = calculate_total(request.json["cart_id"])
    return {"price": price}


@app.post("/admin/promote")
@login_required
def promote():
    # The role is never taken from the client; the caller's own record decides.
    if not current_user.is_admin:
        abort(403)
    return {"role": current_user.role}


@app.get("/session")
def session():
    token = request.cookies.get("token")
    # The signature is verified against the configured key and algorithm.
    claims = jwt.decode(token, JWT_PUBLIC_KEY, algorithms=["RS256"])
    return str(claims)


@app.post("/users")
@login_required
def create_user():
    password = request.form["password"]
    # Adaptive hash, per-password salt.
    digest = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return str(digest)


@app.post("/import")
@login_required
def import_state():
    # Safe loader: no arbitrary object construction.
    return str(yaml.safe_load(request.data))


@app.get("/hello")
def hello():
    # Escaped before it reaches the response body.
    return HttpResponse(f"<h1>{html.escape(request.args['name'])}</h1>")


def render_order(order):
    # Escaped at render time.
    return f'<div class="cart">{bleach.clean(order.note)}</div>'


@app.post("/login")
@limiter.limit("5/minute")
def login():
    # Credential endpoint with a rate limit and a lockout counter.
    login_attempts.record(request.form["user"])
    return authenticate(request.form["user"], request.form["password"])

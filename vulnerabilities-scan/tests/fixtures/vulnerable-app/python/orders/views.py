"""Intentionally vulnerable Flask views.

Every sink below is deliberate and is asserted by tests/fixtures/expected_findings.json.
Do not copy any of this into a real application.
"""
import hashlib
import os
import pickle

import jwt
import requests
from flask import Flask, HttpResponse, request

app = Flask(__name__)


@app.get("/orders")
def list_orders():
    term = request.args["term"]
    # py-sql-concat: statement composed from request data
    rows = db.execute("SELECT * FROM orders WHERE id = " + term).fetchall()
    return str(rows)


@app.get("/orders/<order_id>")
def show_order(order_id):
    # idor-fetch-by-request-id: record loaded straight from the supplied id
    order = Order.objects.get(request.args["id"])
    return str(order)


@app.post("/orders/report")
def report():
    # cmd-shell-true: shell=True with a composed command
    subprocess.run("tar -czf /tmp/report.tar " + request.args["name"], shell=True)
    # cmd-os-system: variable handed to os.system
    os.system("ping -c1 " + request.args["host"])
    return "ok"


@app.get("/files")
def download():
    # path-traversal: request data used to build the path
    return open(os.path.join("/srv/data", request.args["name"])).read()


@app.get("/preview")
def preview():
    # ssrf-request-url: outbound request to a request-supplied URL
    return requests.get(request.args["url"]).text


@app.post("/orders/price")
def quote():
    # client-price: money taken from the client
    price = request.json["price"]
    return {"price": price}


@app.post("/admin/promote")
def promote():
    # authz-role-from-client: role chosen by the caller
    role = request.args.get("role")
    return {"role": role}


@app.get("/session")
def session():
    token = request.cookies.get("token")
    # jwt-no-verify: signature check disabled
    claims = jwt.decode(token, options={"verify_signature": False})
    return str(claims)


@app.post("/users")
def create_user():
    password = request.form["password"]
    # weak-password-hash: fast hash for a password
    digest = hashlib.md5(password.encode()).hexdigest()
    return digest


@app.post("/import")
def import_state():
    # unsafe-deserialization: untrusted bytes unpickled
    return str(pickle.loads(request.data))


@app.get("/hello")
def hello():
    # xss-response-request: request data written into the response body
    return HttpResponse(f"<h1>Hello {request.args['name']}</h1>")


def render_order(order):
    # xss-stored-unsafe: stored value interpolated into markup unescaped
    return f'<div class="{order.theme}">{order.note}</div>'

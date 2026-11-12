"""Secure look-alike of python/orders/uploads.py."""
from flask import request
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"png", "jpg", "pdf"}


def allowed(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def store():
    upload = request.files["file"]
    # The stored name is generated, not supplied; the extension is allow-listed.
    name = secure_filename(upload.filename)
    if not allowed(name):
        abort(400)
    upload.save("/srv/uploads/" + str(uuid4()) + "." + name.rsplit(".", 1)[1])
    return "stored"

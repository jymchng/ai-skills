"""Intentionally unsafe upload handling."""
from flask import request


def store():
    upload = request.files["file"]
    # upload-filename: stored under the client-supplied name
    upload.save("/srv/uploads/" + upload.filename)
    return "stored"

"""Secure look-alike of python/orders/identity.py."""
import os

from flask import request

# Authentication is on; the flag is not a bypass.
skip_auth = False


def current_user():
    # Identity comes from the verified session, never from a client header.
    return session_store.load(request.cookies.get("session_id"))


def delete_account(account):
    if account.owner_id != current_user().id:
        abort(403)
    return account.delete()

"""Identity and authorization mistakes for the fixture."""
from flask import request

# auth-disabled: the flag turns authentication off
skip_auth = True


def current_user():
    # auth-identity-header: identity taken from an unverified header
    return request.headers["X-User-Id"]


def delete_account(account):
    # authz-check-commented: the guard is commented out
    # @login_required
    return account.delete()

"""Secure look-alike of python/orders/settings.py."""

# An explicit allow-list of origins, and no wildcard.
CORS_ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"]
CORS_ALLOW_CREDENTIALS = True

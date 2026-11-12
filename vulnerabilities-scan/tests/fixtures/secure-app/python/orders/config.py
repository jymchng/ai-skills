"""Secure look-alike of python/orders/config.py.

No credential appears literally: every value is read from the environment.
"""
import os

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
API_KEY = os.environ["API_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]

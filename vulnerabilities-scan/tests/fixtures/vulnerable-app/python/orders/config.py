"""Credential-shaped fixture values.

Every value here is a fabricated example. They exist so the secret pass has
something to detect and redact; none of them is a working credential.
"""

# secret-aws-access-key: fabricated AWS key id
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# secret-generic-assignment: fabricated API key
API_KEY = "examplefabricatedapikeyvalue"

# secret-connection-string: fabricated inline password
DATABASE_URL = "postgres://app:examplepassword@db.fixture.invalid:5432/app"

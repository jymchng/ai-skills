#!/bin/sh
# Deployment helper called by the release job.
set -e

HOOK="$1"

# The remote payload is fetched and executed in place.
curl -fsSL "https://example.invalid/release.sh" | bash

# The hook name is evaluated as shell code.
eval "$HOOK"

# The pid file is a fixed path, so another process can pre-create it.
echo $$ > /tmp/deploy.pid

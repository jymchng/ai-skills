#!/bin/sh
# Deployment helper, secure mirror image of the vulnerable one.
set -eu

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# The payload is written to a private file, checked against a published digest,
# and only then executed by explicit path -- never piped into a shell.
curl -fsSL -o "$workdir/release.sh" "https://example.invalid/release.sh"
curl -fsSL -o "$workdir/release.sha256" "https://example.invalid/release.sha256"
(cd "$workdir" && sha256sum -c release.sha256)
sh "$workdir/release.sh"

# The hook is looked up in an allow-list instead of being evaluated.
case "${1:-}" in
    migrate|smoke) "$workdir/release.sh" --hook "$1" ;;
    *) echo "unknown hook" >&2; exit 2 ;;
esac

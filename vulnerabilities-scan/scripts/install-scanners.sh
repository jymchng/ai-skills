#!/bin/sh
# Bootstrap the scanner installer on Linux and macOS.
#
# This wrapper does one thing: find a Python 3, then hand every argument to
# scripts/install_scanners.py, which owns the tool matrix, the plan and the
# verification. Nothing about which package manager a tool needs lives here,
# because a second copy of that knowledge is a second thing to drift.
#
# It deliberately does not pipe a download into a shell, and it does not use
# sudo: the engine prints the exact command for a step that needs root, and
# running it is the operator's decision.
#
# Usage
#   scripts/install-scanners.sh                     # print the plan
#   scripts/install-scanners.sh --list              # the install matrix as JSON
#   scripts/install-scanners.sh --check             # probe what is installed
#   scripts/install-scanners.sh --yes --allow-sudo  # install, elevating per step
#
# Exit codes: 0 plan printed or everything installed; 1 a tool is still missing;
# 2 Python 3 is missing, or the engine refused the request.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
engine="$script_dir/install_scanners.py"

if [ ! -f "$engine" ]; then
    echo "error: install_scanners.py not found next to this wrapper ($script_dir)" >&2
    exit 2
fi

find_python() {
    for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python; do
        if command -v "$candidate" >/dev/null 2>&1 &&
           "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

if ! python=$(find_python); then
    uname_s=$(uname -s 2>/dev/null || echo unknown)
    case "$uname_s" in
        Darwin)
            echo "error: no Python 3.8+ found." >&2
            echo "  macOS: run 'xcode-select --install' for the system Python, or" >&2
            echo "         install Homebrew (https://brew.sh) and run 'brew install python'." >&2
            ;;
        Linux)
            echo "error: no Python 3.8+ found." >&2
            if command -v apt-get >/dev/null 2>&1; then
                echo "  Debian/Ubuntu: sudo apt-get install -y python3" >&2
            elif command -v dnf >/dev/null 2>&1; then
                echo "  Fedora/RHEL:   sudo dnf install -y python3" >&2
            elif command -v pacman >/dev/null 2>&1; then
                echo "  Arch:          sudo pacman -S --noconfirm python" >&2
            elif command -v apk >/dev/null 2>&1; then
                echo "  Alpine:        sudo apk add --no-cache python3" >&2
            else
                echo "  Install Python 3.8+ with the package manager for this distribution." >&2
            fi
            ;;
        *)
            echo "error: no Python 3.8+ found on $uname_s." >&2
            ;;
    esac
    exit 2
fi

exec "$python" "$engine" "$@"

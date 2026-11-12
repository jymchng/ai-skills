"""Shared test configuration.

``/tmp`` on this host is a full 12 GB shared tmpfs, so pytest's default
``tmp_path`` — which lives under the system temp directory — fails with
``ENOSPC`` in teardown. Every test therefore gets a scratch directory inside the
repository (``.scratch/tests``), which is git-ignored, and a ``TMPDIR`` that
points at it so any code under test that calls :mod:`tempfile` stays off ``/tmp``
too.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import shutil

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRATCH = REPO / ".scratch" / "tests" / "tmp"


@pytest.fixture(autouse=True, scope="session")
def _scratch_tmpdir():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    previous = os.environ.get("TMPDIR")
    os.environ["TMPDIR"] = str(SCRATCH)
    yield
    if previous is None:
        os.environ.pop("TMPDIR", None)
    else:
        os.environ["TMPDIR"] = previous


@pytest.fixture()
def tmp_path(request):
    """A per-test directory under ``.scratch``, removed afterwards."""
    digest = hashlib.sha1(request.node.nodeid.encode("utf-8")).hexdigest()[:12]
    path = SCRATCH / digest
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    yield path
    shutil.rmtree(path, ignore_errors=True)

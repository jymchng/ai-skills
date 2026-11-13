#!/usr/bin/env python3
"""Stage 6 \u2014 generate every report format from one findings dataset.

This is the entry point an audit actually calls. It builds the report view model
**once** and passes that same object to the Markdown, HTML, PDF and JSON
generators, so all four deliverables share one ``generated_at``, one set of
counts and one verdict. Nothing is re-read from disk between formats.

It also writes ``report-manifest.json``: the machine-readable record of what was
written (path, size, digest, page count, finding ids) and the shared numbers the
formats were supposed to contain. ``validate_reports.py`` checks the four files
against that manifest, which is how a report set that disagrees with itself is
caught before it reaches a client.

Exit status
-----------
``0``  every requested format was produced, and the PDF was either produced or
       documented as unavailable (pandoc/xelatex not installed).
``1``  a format failed. The other formats are still written and the manifest
       records which one failed and why \u2014 losing the whole report set because
       the PDF engine is broken would be the worst possible outcome.

Usage::

    python3 scripts/generate_reports.py --dataset findings.json --outdir audit/ \\
        --metadata audit/audit-metadata.json --analysis audit/scanners.json

    python3 scripts/generate_reports.py --dataset findings.json --outdir audit/ \\
        --formats markdown,html,json      # skip the PDF toolchain
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import report_model as rm  # noqa: E402
import generate_html as gh  # noqa: E402
import generate_json as gj  # noqa: E402
import generate_markdown as gm  # noqa: E402
import generate_pdf as gp  # noqa: E402

TOOL_NAME = "generate_reports.py"

ALL_FORMATS = ("markdown", "html", "pdf", "json")


def generate_all(model: Mapping[str, Any], outdir: str,
                 formats: Sequence[str] = ALL_FORMATS,
                 dataset_path: Optional[str] = None,
                 findings_dir: Optional[str] = None,
                 keep_build: bool = False) -> Dict[str, Any]:
    """Render every requested format from one view model, then write a manifest."""
    rm.ensure_outdir(outdir)
    selected = [name for name in ALL_FORMATS if name in formats]
    unknown = [name for name in formats if name not in ALL_FORMATS]
    if unknown:
        raise SystemExit("unknown format(s): %s (choose from %s)"
                         % (", ".join(unknown), ", ".join(ALL_FORMATS)))

    results: Dict[str, Any] = {}
    for name in selected:
        if name == "markdown":
            results[name] = gm.generate(model, outdir)
        elif name == "html":
            results[name] = gh.generate(model, outdir)
        elif name == "json":
            results[name] = gj.generate(model, outdir, findings_dir=findings_dir)
        elif name == "pdf":
            results[name] = gp.generate(model, outdir, keep_build=keep_build)

    findings = [entry for entry in model.get("findings") or [] if isinstance(entry, dict)]
    per_finding = results.get("json", {}).get("findings") or []
    manifest = {
        "schema_version": "1.0",
        "kind": "security-audit-report-manifest",
        "tool": {"name": (model.get("tool") or {}).get("name"),
                 "version": (model.get("tool") or {}).get("version")},
        "generated_at": model.get("generated_at"),
        "dataset": {"path": dataset_path} if dataset_path else {},
        "meta": model.get("meta"),
        "counts": model.get("counts"),
        "verdict_text": model.get("verdict_text"),
        "ids": [entry.get("id") for entry in findings],
        "needs_investigation_ids": [entry.get("id")
                                    for entry in model.get("needs_investigation") or []],
        "unvalidated_ids": [entry.get("id") for entry in model.get("unvalidated") or []],
        "suppressed_ids": [entry.get("id") for entry in model.get("suppressed") or []],
        "formats": {name: {key: value for key, value in result.items()
                           if key in ("format", "status", "path", "bytes", "sha256",
                                      "lines", "pages", "engine", "fonts", "reason",
                                      "detail", "log", "preserved", "document",
                                      "findings_dir", "by_disposition")}
                    for name, result in results.items()},
        "findings": per_finding,
        # The per-finding register: one entry per finding, with the bucket it was
        # filed under and the path of the file written for it. ``findings`` above
        # is the same set with digests; this record makes the index a
        # first-class deliverable of the run.
        "findings_index": results.get("json", {}).get("index") or {},
        "findings_dir": results.get("json", {}).get("findings_dir"),
        "failed": sorted(name for name, result in results.items()
                         if result.get("status") == "failed"),
        "unavailable": sorted(name for name, result in results.items()
                              if result.get("status") == "unavailable"),
    }
    written = rm.write_report(
        os.path.join(outdir, rm.OUTPUT_NAMES["manifest"]),
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    manifest["manifest"] = written
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Generate the Markdown, HTML, PDF and JSON audit reports from one "
                    "findings dataset, plus report-manifest.json.",
        epilog="Run validate_reports.py on the output directory before delivering: it "
               "checks that the four formats exist, are valid, and agree on ids, totals "
               "and severity distribution.")
    rm.add_common_arguments(parser)
    parser.add_argument("--formats", default=",".join(ALL_FORMATS),
                        help="comma-separated subset of %s (default: all)"
                             % ",".join(ALL_FORMATS))
    parser.add_argument("--findings-dir", "--ticket-dir", dest="findings_dir",
                        help="directory for the per-finding JSON files")
    parser.add_argument("--keep-build", action="store_true",
                        help="keep the LaTeX build inputs after a successful PDF")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    formats: List[str] = [part.strip() for part in args.formats.split(",") if part.strip()]
    model = rm.model_from_args(args)
    manifest = generate_all(model, args.outdir, formats, dataset_path=args.dataset,
                            findings_dir=args.findings_dir, keep_build=args.keep_build)
    rm.emit(manifest, args.indent)
    return 1 if manifest["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())

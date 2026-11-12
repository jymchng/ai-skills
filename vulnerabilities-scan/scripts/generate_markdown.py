#!/usr/bin/env python3
"""Stage 6 \u2014 render the Markdown security audit report.

The Markdown report is the human-readable deliverable and the source document
the PDF is typeset from, so it must stand on its own: verdict, summary, coverage
limitations, one section per validated finding, the items still under
investigation, the suppressions, the methodology, and the audit provenance.

Everything here comes from :mod:`report_model`, the single view model built from
``findings.json``. This module adds no facts of its own \u2014 it only renders
``templates/report.md.j2`` \u2014 which is what makes the cross-format consistency
check in ``validate_reports.py`` meaningful rather than circular.

Markdown escaping
-----------------
Finding text is attacker-influenced: a title containing ``|`` would silently
split a table row and a newline would end it. The template therefore applies the
``mdcell`` filter to every table cell and ``mdline`` to every free-text
paragraph, so untrusted text can never restructure the document.

Usage::

    python3 scripts/generate_markdown.py --dataset findings.json --outdir audit/ \\
        --metadata audit/audit-metadata.json --analysis audit/scanners.json

Prints a JSON description of the written file (path, bytes, sha256, ids, counts).
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, Mapping, Optional, Sequence

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import report_model as rm  # noqa: E402

TOOL_NAME = "generate_markdown.py"


def render_markdown(model: Mapping[str, Any],
                    template: Optional[str] = None) -> str:
    """Render the Markdown report for an already-built view model."""
    path = template or rm.template_path("report.md.j2")
    return rm.render_file(path, rm.context_for(model), autoescape=False)


def generate(model: Mapping[str, Any], outdir: str, out: Optional[str] = None,
             template: Optional[str] = None) -> Dict[str, Any]:
    """Write the Markdown report into ``outdir`` and describe what was written."""
    rm.ensure_outdir(outdir)
    text = render_markdown(model, template)
    target = out or os.path.join(outdir, rm.OUTPUT_NAMES["markdown"])
    return rm.format_result(model, rm.write_report(target, text), "markdown")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Render the Markdown security audit report from findings.json.",
        epilog="Runs after validate_findings.py; generate_reports.py drives this "
               "together with the HTML and PDF generators from one dataset.")
    rm.add_common_arguments(parser)
    parser.add_argument("--template", help="override templates/report.md.j2")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    model = rm.model_from_args(args)
    result = generate(model, args.outdir, args.out, args.template)
    rm.emit(result, args.indent)
    return 0


if __name__ == "__main__":
    sys.exit(main())

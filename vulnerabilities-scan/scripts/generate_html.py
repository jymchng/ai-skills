#!/usr/bin/env python3
"""Stage 6 \u2014 render the self-contained HTML security audit report.

One file, no network. The stylesheet from ``templates/report.css`` is inlined
into a single ``<style>`` block and the only script is a few lines of vanilla
JavaScript that filters findings client-side, so the report can be opened from a
laptop in an air-gapped network, emailed to a client, or attached to a ticket
without a CDN dependency, a font fetch, or a tracking pixel. There is no
``<link>``, no ``<script src>``, no ``url(http...)`` \u2014 ``validate_reports.py``
asserts that.

Untrusted content
-----------------
Every finding field is attacker-influenced: titles, descriptions and evidence
come out of the audited repository, which may itself contain HTML. The template
is rendered with ``autoescape=True``, so substitution values are HTML-escaped
(with quotes) unless the template explicitly asks for ``safe`` \u2014 used only for
the inlined stylesheet, which ships with the skill. A finding titled
``<script>alert(1)</script>`` therefore renders as visible text.

Usage::

    python3 scripts/generate_html.py --dataset findings.json --outdir audit/ \\
        --metadata audit/audit-metadata.json

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

TOOL_NAME = "generate_html.py"


def load_stylesheet(path: Optional[str] = None) -> str:
    """Read the report stylesheet that is inlined into every HTML report."""
    return rm.read_text_file(path or rm.template_path("report.css"))


def render_html(model: Mapping[str, Any], template: Optional[str] = None,
                stylesheet: Optional[str] = None) -> str:
    """Render the HTML report for an already-built view model."""
    path = template or rm.template_path("report.html.j2")
    context = rm.context_for(model, css=load_stylesheet(stylesheet))
    return rm.render_file(path, context, autoescape=True)


def generate(model: Mapping[str, Any], outdir: str, out: Optional[str] = None,
             template: Optional[str] = None,
             stylesheet: Optional[str] = None) -> Dict[str, Any]:
    """Write the HTML report into ``outdir`` and describe what was written."""
    rm.ensure_outdir(outdir)
    text = render_html(model, template, stylesheet)
    target = out or os.path.join(outdir, rm.OUTPUT_NAMES["html"])
    return rm.format_result(model, rm.write_report(target, text), "html")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Render the self-contained HTML security audit report.",
        epilog="The output has no external references: CSS is inlined and the "
               "filtering script is embedded.")
    rm.add_common_arguments(parser)
    parser.add_argument("--template", help="override templates/report.html.j2")
    parser.add_argument("--stylesheet", help="override templates/report.css")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    model = rm.model_from_args(args)
    result = generate(model, args.outdir, args.out, args.template, args.stylesheet)
    rm.emit(result, args.indent)
    return 0


if __name__ == "__main__":
    sys.exit(main())

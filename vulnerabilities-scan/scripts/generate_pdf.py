#!/usr/bin/env python3
"""Stage 6 \u2014 typeset the Markdown report to PDF with pandoc and xelatex.

The PDF is generated from the *same* Markdown the Markdown deliverable contains,
which is rendered from the *same* view model as the HTML report. That chain
matters: there is exactly one dataset behind the three formats, so a number
cannot differ between them unless a generator is broken \u2014 and
``validate_reports.py`` is written to notice when one is.

What the PDF adds
-----------------
* a cover page (repository, commit, working-tree state, audit date, scope),
* a table of contents,
* running headers with the report title and repository, and a page footer with
  the page number,
* Unicode-safe fonts (DejaVu by default) so an em dash in a finding title does
  not become a missing glyph, and monospace code excerpts stay legible,
* clickable links and bookmarks.

Failure is documented, never silent
-----------------------------------
PDF tooling is optional. Three outcomes are distinguished:

``generated``
    The PDF exists; the result records its size, digest and page count.
``unavailable``
    ``pandoc`` or ``xelatex`` is not installed. This is a *documented* failure:
    the exit status is 0, the reason names what is missing, and the Markdown and
    HTML deliverables are untouched and remain the deliverable.
``failed``
    The tools exist but typesetting failed (a LaTeX error, a timeout). The exit
    status is 1, the LaTeX log is kept next to the build inputs, and the
    Markdown and HTML deliverables are still preserved \u2014 a PDF failure may never
    cost the audit its report.

Usage::

    python3 scripts/generate_pdf.py --dataset findings.json --outdir audit/ \\
        --metadata audit/audit-metadata.json

Prints a JSON description of the outcome.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import report_model as rm  # noqa: E402
import generate_markdown as md  # noqa: E402

TOOL_NAME = "generate_pdf.py"

PANDOC = "pandoc"
PDF_ENGINE = "xelatex"
BUILD_DIRNAME = ".pdf-build"

#: Tried in order; the first set installed is used. DejaVu ships with nearly
#: every LaTeX distribution and has the widest Latin/Cyrillic/Greek coverage.
FONT_SETS: Tuple[Tuple[str, str, str], ...] = (
    ("DejaVu Serif", "DejaVu Sans", "DejaVu Sans Mono"),
    ("Noto Serif", "Noto Sans", "Noto Sans Mono"),
    ("Latin Modern Roman", "Latin Modern Sans", "Latin Modern Mono"),
)

_GEOMETRY = "a4paper,left=2.2cm,right=2.2cm,top=2.7cm,bottom=2.5cm"

_LATEX_ESCAPES = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}


def escape_latex(text: Any) -> str:
    """Escape text for LaTeX.

    The cover page is the one place where report content becomes *code* rather
    than being passed through pandoc's markdown reader, so a repository name like
    ``acme_web#2`` must not become a LaTeX error or a comment.
    """
    out: List[str] = []
    for char in str(text if text is not None else ""):
        out.append(_LATEX_ESCAPES.get(char, char))
    return "".join(out)


def tool_availability() -> Tuple[bool, str]:
    """Return (available, reason). The reason names every missing program."""
    missing = [name for name in (PANDOC, PDF_ENGINE) if not shutil.which(name)]
    if missing:
        return False, ("%s not found on PATH; the PDF was not produced. The Markdown "
                       "and HTML reports are complete and are the deliverables."
                       % " and ".join(missing))
    return True, ""


def _version(program: str) -> str:
    try:
        result = subprocess.run([program, "--version"], capture_output=True, text=True,
                                timeout=30)
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - unlikely
        return "unknown"
    first = (result.stdout or "").splitlines()
    return first[0].strip() if first else "unknown"


def cover_tex(model: Mapping[str, Any]) -> str:
    """The LaTeX title page: what was audited, when, and at which commit."""
    meta = model.get("meta") or {}
    counts = model.get("counts") or {}
    facts = [
        ("Repository", meta.get("repository")),
        ("Commit", meta.get("commit_short")),
        ("Branch", meta.get("branch")),
        ("Working tree", meta.get("dirty_display")),
        ("Audited", meta.get("audit_date")),
        ("Scope", meta.get("scope")),
        ("Findings", counts.get("total")),
        ("Critical and High", counts.get("critical_high")),
    ]
    rows = "\n".join(
        r"  \textbf{%s} & %s \\" % (escape_latex(label), escape_latex(value))
        for label, value in facts)
    return "\n".join([
        r"\begin{titlepage}",
        r"\thispagestyle{empty}",
        r"\centering",
        r"\vspace*{3.2cm}",
        r"{\Huge\bfseries Security Audit Report\par}",
        r"\vspace{0.8cm}",
        r"{\LARGE %s\par}" % escape_latex(meta.get("repository") or "Not recorded"),
        r"\vspace{2.0cm}",
        r"\begin{tabular}{@{}r@{\hspace{1.2em}}l@{}}",
        rows,
        r"\end{tabular}",
        r"\vfill",
        r"{\small Generated %s by %s %s from a single findings dataset.\par}"
        % (escape_latex(model.get("generated_at") or ""),
           escape_latex((model.get("tool") or {}).get("name") or "vulnerabilities-scan"),
           escape_latex((model.get("tool") or {}).get("version") or "")),
        r"{\small Line numbers refer to the audited snapshot named above.\par}",
        r"\end{titlepage}",
        r"\clearpage",
        "",
    ])


def header_tex(model: Mapping[str, Any]) -> str:
    """LaTeX preamble additions: page style, headers, footers, page numbers."""
    meta = model.get("meta") or {}
    repository = escape_latex(meta.get("repository") or "")
    return "\n".join([
        r"\usepackage{fancyhdr}",
        r"\usepackage{lastpage}",
        # The title travels as pandoc metadata so the PDF keeps its title
        # (hypersetup writes pdftitle), but pandoc's default template answers it
        # with \maketitle, which printed a near-empty first page holding only
        # the title and a page number, pushing the real cover to page 2. Our
        # cover page is the title page, so neutralise \maketitle instead of
        # dropping the metadata.
        r"\renewcommand{\maketitle}{}",
        r"\pagestyle{fancy}",
        r"\fancyhf{}",
        r"\fancyhead[L]{\small\itshape Security Audit Report}",
        r"\fancyhead[R]{\small\itshape %s}" % repository,
        r"\fancyfoot[C]{\small Page \thepage\ of \pageref{LastPage}}",
        r"\renewcommand{\headrulewidth}{0.4pt}",
        r"\renewcommand{\footrulewidth}{0.4pt}",
        r"\setlength{\parindent}{0pt}",
        r"\setlength{\parskip}{4pt}",
        # Long code excerpts and wide tables must wrap rather than run off the page.
        r"\usepackage{fvextra}",
        r"\fvset{breaklines=true,breakanywhere=true,fontsize=\small}",
        r"\usepackage{longtable}",
        r"\setlength{\LTleft}{0pt}",
        r"\setlength{\LTright}{0pt}",
        "",
    ])


def _pandoc_command(markdown_path: str, pdf_path: str, build: Mapping[str, str],
                    fonts: Optional[Tuple[str, str, str]]) -> List[str]:
    command = [
        PANDOC, markdown_path, "-o", pdf_path,
        "--pdf-engine=" + PDF_ENGINE,
        "--toc", "--toc-depth=2",
        "--metadata", "title=Security Audit Report",
        "--metadata", "lang=en",
        "--include-in-header", build["header"],
        "--include-before-body", build["cover"],
        "--variable", "geometry:" + _GEOMETRY,
        "--variable", "fontsize=10pt",
        "--variable", "colorlinks:true",
        "--variable", "linkcolor=MidnightBlue",
        "--variable", "urlcolor=MidnightBlue",
        "--variable", "bookmarks:true",
    ]
    if fonts:
        command += ["--variable", "mainfont=" + fonts[0],
                    "--variable", "sansfont=" + fonts[1],
                    "--variable", "monofont=" + fonts[2]]
    return command


def _page_count(pdf_path: str) -> Optional[int]:
    if not shutil.which("pdfinfo"):
        return None
    try:
        result = subprocess.run(["pdfinfo", pdf_path], capture_output=True, text=True,
                                timeout=30)
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - unlikely
        return None
    match = re.search(r"^Pages:\s+(\d+)\s*$", result.stdout or "", re.MULTILINE)
    return int(match.group(1)) if match else None


def generate(model: Mapping[str, Any], outdir: str, out: Optional[str] = None,
             workdir: Optional[str] = None, keep_build: bool = False,
             timeout: int = 300) -> Dict[str, Any]:
    """Typeset the PDF report and describe the outcome without raising."""
    rm.ensure_outdir(outdir)
    target = out or os.path.join(outdir, rm.OUTPUT_NAMES["pdf"])
    available, reason = tool_availability()
    if not available:
        return {"format": "pdf", "status": "unavailable", "reason": reason,
                "path": None, "bytes": None, "sha256": None,
                "preserved": [os.path.join(outdir, rm.OUTPUT_NAMES["markdown"]),
                              os.path.join(outdir, rm.OUTPUT_NAMES["html"])]}

    build_dir = workdir or os.path.join(outdir, BUILD_DIRNAME)
    os.makedirs(build_dir, exist_ok=True)
    build = {
        "markdown": os.path.join(build_dir, "report.md"),
        "cover": os.path.join(build_dir, "cover.tex"),
        "header": os.path.join(build_dir, "header.tex"),
        "pdf": os.path.join(build_dir, "report.pdf"),
        "log": os.path.join(build_dir, "pandoc.log"),
    }
    with open(build["markdown"], "w", encoding="utf-8") as handle:
        handle.write(md.render_markdown(model))
    with open(build["cover"], "w", encoding="utf-8") as handle:
        handle.write(cover_tex(model))
    with open(build["header"], "w", encoding="utf-8") as handle:
        handle.write(header_tex(model))

    # xelatex and pandoc both use the system temporary directory, which may be
    # full or read-only; keeping it inside the output directory makes a PDF
    # attempt independent of the host's /tmp.
    environment = dict(os.environ)
    environment["TMPDIR"] = build_dir

    attempts: List[Tuple[str, str]] = []
    for fonts in list(FONT_SETS) + [None]:
        command = _pandoc_command(build["markdown"], build["pdf"], build, fonts)
        if os.path.exists(build["pdf"]):
            os.remove(build["pdf"])
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=timeout, env=environment)
            stderr, code = result.stderr or "", result.returncode
        except subprocess.TimeoutExpired:
            stderr, code = "pandoc timed out after %ss" % timeout, -1
        except OSError as exc:  # pragma: no cover - tool vanished mid-run
            stderr, code = str(exc), -1
        attempts.append((fonts[0] if fonts else "default", stderr[-4000:]))
        if code == 0 and os.path.exists(build["pdf"]):
            with open(build["log"], "w", encoding="utf-8") as handle:
                handle.write(stderr)
            os.makedirs(os.path.dirname(os.path.abspath(target)) or ".", exist_ok=True)
            os.replace(build["pdf"], target)
            with open(target, "rb") as handle:
                data = handle.read()
            if not keep_build:
                shutil.rmtree(build_dir, ignore_errors=True)
            return {
                "format": "pdf", "status": "generated", "path": target,
                "bytes": len(data),
                "sha256": __import__("hashlib").sha256(data).hexdigest(),
                "pages": _page_count(target),
                "engine": PDF_ENGINE, "fonts": fonts[0] if fonts else "engine default",
                "pandoc": _version(PANDOC),
            }
        # A font that xelatex cannot find must not end the attempt: retry with the
        # engine default before declaring failure.
        if fonts is not None and "font" not in stderr.lower():
            break

    combined = "\n\n".join("--- attempt %d (%s) ---\n%s" % (index + 1, name, log)
                           for index, (name, log) in enumerate(attempts))
    with open(build["log"], "w", encoding="utf-8") as handle:
        handle.write(combined)
    tail = [line for line in attempts[-1][1].splitlines() if line.strip()][-12:]
    return {
        "format": "pdf", "status": "failed",
        "reason": "pandoc/%s could not typeset the report; see %s"
                  % (PDF_ENGINE, build["log"]),
        "detail": "\n".join(tail),
        "path": None, "bytes": None, "sha256": None, "log": build["log"],
        "preserved": [os.path.join(outdir, rm.OUTPUT_NAMES["markdown"]),
                      os.path.join(outdir, rm.OUTPUT_NAMES["html"])],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Typeset the security audit report to PDF with pandoc and xelatex.",
        epilog="A missing pandoc or xelatex is reported as status 'unavailable' with "
               "exit code 0; a typesetting error is status 'failed' with exit code 1. "
               "Neither case deletes the Markdown or HTML report.")
    rm.add_common_arguments(parser)
    parser.add_argument("--workdir", help="build directory (default: <outdir>/.pdf-build)")
    parser.add_argument("--keep-build", action="store_true",
                        help="keep the LaTeX inputs and pandoc log after success")
    parser.add_argument("--timeout", type=int, default=300,
                        help="seconds before pandoc is killed (default: 300)")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    model = rm.model_from_args(args)
    result = generate(model, args.outdir, args.out, args.workdir,
                      args.keep_build, args.timeout)
    rm.emit(result, args.indent)
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())

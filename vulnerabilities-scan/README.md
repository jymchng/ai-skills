# vulnerabilities-scan

A Claude Code skill for repository-wide security audits: it inventories a repository, maps its
attack surface, runs 97 built-in detection rules plus any external scanners that are installed,
validates every candidate against the actual code, scores what survives with CVSS 4.0, and renders
one findings dataset as Markdown, HTML, PDF and per-finding JSON.

Three properties define it, and they are the reason to prefer it over a scanner wrapper:

- **A pattern is a candidate, a dataflow is a finding, a bypassed control is a confirmed finding.**
  Nothing is reported as CONFIRMED on the strength of a regex.
- **No silent success.** A scanner that is not installed, a file that could not be read, a bucket
  that was empty — each is recorded as a coverage limitation in the report, never as a clean result.
- **One dataset, four deliverables.** The Markdown, HTML, PDF, JSON and ticket files are rendered
  from the same validated dataset, so they cannot disagree; a verifier proves it before delivery.

Read-only by construction: the audit never edits the repository it is auditing, never authenticates
to anything, and never exploits a finding.

---

## 1. Requirements

**Required**

| Requirement | Why |
|---|---|
| Claude Code | The skill is invoked as `/vulnerabilities-scan` or discovered from its description |
| Python 3.8+ (standard library only) | Every script under `scripts/` runs with no third-party imports |

`jsonschema` is used **when importable** and never required: the finding model falls back to a
stdlib validator with a recorded reason. `pyproject.toml` dependency parsing needs Python 3.11+
(`tomllib`); on older interpreters those manifests are listed under `unparsed_manifests` rather than
silently skipped.

**Optional — external scanners.** All ten are detected at run time; any that is missing is reported
as a coverage limitation. Five of them query a registry or CVE database and therefore require
`--allow-network`:

| Scanner | Kind | Network | Languages / targets |
|---|---|---|---|
| `semgrep` | SAST | yes | many |
| `bandit` | SAST | no | Python |
| `brakeman` | SAST | no | Ruby |
| `gosec` | SAST | no | Go |
| `gitleaks` | secrets | no | any |
| `trivy` | SCA + IaC | yes | many |
| `osv-scanner` | SCA | yes | many |
| `pip-audit` | SCA | yes | Python |
| `npm-audit` | SCA | yes | JavaScript |
| `checkov` | IaC | no | Terraform, Kubernetes, Dockerfile, GitHub Actions |

Check what this machine actually has before trusting a coverage claim:

```bash
python3 scripts/scanner_orchestrator.py --probe-only     # availability, version per tool
python3 scripts/scanner_orchestrator.py --list-tools     # the matrix above, as JSON
```

**Installing them.** The audit never installs a scanner: a run that pip-installed a tool mid-audit
would make the coverage section depend on what the agent happened to fetch, and would modify a
machine nobody asked it to touch. Installation is a separate, operator-driven step that prints a
plan before it does anything:

```bash
scripts/install-scanners.sh --check          # what is here, from the audit's own probe
scripts/install-scanners.sh                  # the plan: exact commands for this host, per tool
scripts/install-scanners.sh --yes            # install; root steps are printed, not run
scripts/install-scanners.sh --yes --allow-sudo      # ...or run them with sudo -n
scripts/install-scanners.sh --yes --allow-download  # release binaries when no package covers a tool
```

On Windows (PowerShell 5.1+), the same engine behind a launcher that finds `py -3` or `python`:

```powershell
.\scripts\install-scanners.ps1 --check
.\scripts\install-scanners.ps1              # plan
.\scripts\install-scanners.ps1 --yes        # winget, then choco, then scoop
```

What it decides, and what it refuses to decide:

| Behaviour | Why |
| - | - |
| Prints a plan unless `--yes` | A CI job that forgets the flag gets a readable answer, not an invisible prompt |
| Prints root steps with `sudo` and stops there | Elevation is the operator's decision; `--allow-sudo` runs them as `sudo -n` so a missing password fails instead of hanging |
| Bootstraps `pipx` and Node.js only | `pipx` keeps the Python tools isolated and current; `npm audit` has no alternative. Go and Ruby are used when present and never installed; gitleaks, gosec and osv-scanner have release binaries, brakeman has its gem |
| Verifies with `scanner_orchestrator.probe` | The installer's opinion does not count, the audit's own probe does; a tool it installed but the audit cannot see is a failure (exit 1) |
| Checks downloads against the release's checksum | `--allow-download` needs `--allow-unverified` when a project publishes no checksum, and records `verified: false` |
| Installs downloads under `--prefix` (`~/.local/bin`) | Never over a system directory, never behind a package manager's back |

`--list` prints the per-OS matrix as JSON. `references/scanner-reference.md` §7 documents the
policy, the Debian/Fedora caveat for `trivy`, and the three PATH traps (`go install`,
`pipx ensurepath`, `--prefix`).

**Optional — PDF.** `pandoc` plus a LaTeX engine (`xelatex`) produce
`SECURITY-AUDIT-REPORT.pdf`. Without them the run still writes Markdown, HTML, JSON, the index and
the tickets, and records the PDF as `unavailable` with the exact reason (missing binary versus LaTeX
error with the log tail). A missing PDF is never a fabricated file.

**Tested on.** Python 3.13.13 with no network and no external scanners installed; 400 tests pass
(≈60 s). The scripts parse under Python 3.8 grammar, but 3.8–3.10 are untested — treat 3.13 as the
verified interpreter and 3.8 as a documented floor, not a promise.

---

## 2. Install

A skill is a directory whose `SKILL.md` carries YAML frontmatter; the directory name (or the
frontmatter `name`) becomes the command, so this directory is already named correctly
(`name: vulnerabilities-scan` must match its parent directory).

### Personal install (every project on this machine)

Copy it:

```bash
mkdir -p ~/.claude/skills
cp -R vulnerabilities-scan ~/.claude/skills/vulnerabilities-scan
```

or symlink it, so edits and `git pull` are picked up without re-copying (Claude Code reads
`SKILL.md` through the link and loads the skill once even if several locations point at the same
target):

```bash
mkdir -p ~/.claude/skills
ln -s "$PWD/vulnerabilities-scan" ~/.claude/skills/vulnerabilities-scan
```

Personal skills load in every project in your terminal sessions, but **not** in Cowork or cloud
sessions, and not in cloud scheduled tasks.

### Project install (checked in with the repository)

```bash
mkdir -p .claude/skills
ln -s "$PWD/vulnerabilities-scan" .claude/skills/vulnerabilities-scan   # or cp -R
```

Commit `.claude/skills/vulnerabilities-scan` (or just the link target) and everyone who works in
that repository gets the skill. Nested repositories load it from `<subdir>/.claude/skills/` once
Claude works inside that subdirectory.

### Verify before you trust it

```bash
claude plugin validate ~/.claude/skills      # frontmatter parses (Claude Code v2.1.233+)
```

Then in a session, `/skills` lists it and `/vulnerabilities-scan` invokes it. Two install traps:

- Do **not** name the folder `synced` (any capitalisation) — that name is reserved for skills
  downloaded from claude.ai.
- If the folder is missing later, check `~/.claude/skills/.trash/`: syncing from claude.ai does not
  move folders you created, but older versions could.

---

## 3. Invocation

Explicit, with an optional target:

```
/vulnerabilities-scan                       # audit the current repository
/vulnerabilities-scan path/to/repo          # audit another checkout
```

Discovered automatically when the request matches its description, for example:

- "scan this repo for vulnerabilities", "run a security audit", "audit this codebase"
- "find security issues in this project", "review this code for SQL injection / XSS / SSRF / IDOR"
- "check for hardcoded secrets", "is this Dockerfile or Terraform safe", "check our CI/CD permissions"
- "assess OWASP Top 10 coverage", "map the attack surface", "generate a vulnerability report"

The audit writes its output to a separate directory and leaves the audited tree untouched. If the
skill is invoked on a repository that is itself uncommitted, say so in the request — a finding
belongs to a snapshot, and a dirty tree means the snapshot is not reproducible.

---

## 4. Quick start (what the agent runs, and what you get)

```bash
root=.                                    # the repository under audit
out=security-audit                        # output directory, never inside the audited tree
mkdir -p "$out/reports"

python3 scripts/repository_inventory.py --root "$root" --out "$out/inventory.json"
python3 scripts/detect_technologies.py  --root "$root" --inventory "$out/inventory.json" \
        --out "$out/technologies.json"
python3 scripts/attack_surface.py       --root "$root" --inventory "$out/inventory.json" \
        --technologies "$out/technologies.json" --out "$out/attack-surface.json"
python3 scripts/builtin_analyzers.py    --root "$root" --inventory "$out/inventory.json" \
        --technologies "$out/technologies.json" --attack-surface "$out/attack-surface.json" \
        --out "$out/analysis.json" --quiet
python3 scripts/deduplicate_findings.py "$out/analysis.json" --out "$out/deduped.json"
python3 scripts/validate_findings.py    "$out/deduped.json" --root "$root" \
        --out "$out/findings.json" --transcript "$out/transcript.json"
python3 scripts/generate_reports.py     --dataset "$out/findings.json" --outdir "$out/reports" \
        --analysis "$out/analysis.json" --inventory "$out/inventory.json" \
        --formats markdown,html,json                    # add pdf when the toolchain exists
python3 scripts/validate_reports.py     --outdir "$out/reports" --dataset "$out/findings.json" \
        > "$out/verification.json"
```

Every stage is independently re-runnable and its `--help` is the reference. To mix in external
scanners, replace the analyzer and dedupe steps with one orchestrated run:

```bash
python3 scripts/scanner_orchestrator.py --root "$root" --outdir "$out" \
        --timeout 300                       # add --allow-network for registry/CVE lookups
```

`scanner_orchestrator.py` runs the built-in analyzers *and* every available external scanner,
normalises all of them into one shape, keeps the raw output under `$out/raw-scans/`, and records
`unavailable` / `failed` tools explicitly.

---

## 5. What it produces

```
security-audit/
├── inventory.json                  files, languages, sizes, binaries, submodules, manifests, git state
├── technologies.json               frameworks, runtimes, build systems, package managers
├── attack-surface.json             routes, entry points, trust boundaries, auth mechanisms, workers
├── analysis.json                   raw detector output, before consolidation
├── deduped.json                    one finding per real issue, provenance merged
├── findings.json                   the validated dataset — the single source of truth
├── transcript.json                 what validation did (redactions applied, suppressions, statuses)
├── verification.json               the report verifier's verdict (SHA-256 per artefact)
└── reports/
    ├── SECURITY-AUDIT-REPORT.md    the report, for humans in a terminal or a pull request
    ├── SECURITY-AUDIT-REPORT.html  self-contained: no CDN, no external font, opens offline
    ├── SECURITY-AUDIT-REPORT.pdf   cover page, TOC, page numbers (needs pandoc + xelatex)
    ├── SECURITY-AUDIT-REPORT.json  the same content as data
    ├── findings-index.json         one entry per finding + run totals
    ├── report-manifest.json        run identity, counts, size and SHA-256 of every artefact
    └── tickets/
        └── VULN-001.json …         exactly one JSON per finding, ticketable or not
```

Each finding in `findings.json` carries the fields the report needs: `id`, `title`, `category`,
`cwe`, `owasp_reference`, `severity`, `cvss_version`/`cvss_score`/`cvss_vector` (or an explicit
unscored status), `confidence`, `location` (file, line range), description, root cause, attack
scenario, preconditions, impact, evidence with line context, `validation_status`, remediation,
recommended fix and references. `schemas/finding.schema.json` is the formal contract, and
`scripts/finding_model.py validate findings.json` checks a dataset against it.

Suppressed findings are not deleted: they stay in the dataset with the suppression reason, count in
the totals, and are the one thing excluded from the human-readable report — which is why the HTML
article count and the dataset count legitimately differ.

---

## 6. Capabilities

**Built-in detection — 97 rules across 40 categories, no installation.** The rule inventory is
data, not prose:

```bash
python3 scripts/builtin_analyzers.py --list-rules      # every rule_id, category, language, severity
```

Covered: SQL/NoSQL/command/SSTI/XSS/LDAP/XPath/CRLF injection; path traversal, file upload, SSRF,
open redirect, deserialization, XXE/zip-slip; weak password hashing, weak randomness, TLS
verification, hardcoded secrets; authentication, authorization, IDOR/BOLA, function-level
authorization, JWT validation, session handling, rate limiting; business-logic and race-condition
patterns; security headers, CORS, debug mode, fail-open error handling; vulnerable and unpinned
dependencies; Dockerfile, Kubernetes, Terraform and GitHub Actions configuration.

File types with rule coverage: Python, JavaScript/TypeScript, Go, Ruby, PHP, Java, Kotlin, C#,
Rust, Swift, C/C++, shell, PowerShell, SQL, `Dockerfile`, Kubernetes YAML, Helm values,
Terraform, CloudFormation, Ansible playbooks, docker-compose, GitLab CI, Jenkinsfiles, GitHub
Actions workflows, `.env`, JSON, INI, YAML.

**Beyond pattern matching.** Each stage feeds the next, so later stages can reason with context
instead of guessing: routes and auth mechanisms from stage 2 decide which authorization rules are
credible; evidence is re-read from the audited snapshot at validation time (so line numbers are the
snapshot's, not a stale cache); caplog-free compensating controls (parameterisation, escaping,
ownership checks, framework middleware) are looked for before a finding is promoted; secrets are
redacted at ingestion and re-redacted on every re-quote.

**Scoring.** CVSS 4.0 through the vendored FIRST reference implementation
(`scripts/cvss4.py`, `scripts/cvss4_LICENSE.txt`), mapped to the reporting bands Critical 9.0–10.0,
High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9, Informational for a qualifying observation with no CVSS
base score. A finding that cannot be scored defensibly is recorded as **unscored**, not given an
invented vector.

**Reporting.** Markdown, HTML (embedded CSS/JS, print styles, escaped untrusted content), PDF via
pandoc + xelatex, JSON, a per-finding index and one ticket JSON per finding. `validate_reports.py`
then checks that the files exist, parse, agree on IDs, totals and severity distribution, match the
manifest hashes, and contain no unredacted secret — and refuses (exit 1) if they do not.

---

## 7. Configuration

Everything is a flag on the stage that owns the concern; there is no config file to keep in sync.

| Concern | Flag | Stage |
|---|---|---|
| Target | `--root PATH` | every stage |
| Extra exclusions (repeatable, `.gitignore` syntax) | `--exclude PATTERN` | `repository_inventory.py` |
| Walk `node_modules`/`dist`/`vendor` instead of accounting for them | `--include-generated` | `repository_inventory.py` |
| Skip files larger than N bytes | `--max-bytes N` | `repository_inventory.py`, `builtin_analyzers.py` |
| Cap import scanning (huge repositories) | `--max-import-files N` | `detect_technologies.py` |
| Run only some categories | `--only cat1,cat2`, `--exclude cat1` | `builtin_analyzers.py` |
| Drop findings below a severity | `--min-severity {Critical,High,Medium,Low,Informational}` | `builtin_analyzers.py` |
| Cap findings per file | `--limit-per-file N` | `builtin_analyzers.py` |
| Choose scanners | `--scanners semgrep,bandit`, `--no-builtin`, `--builtin-only` | `scanner_orchestrator.py` |
| Per-scanner timeout (default 300 s) | `--timeout N` / `--probe-timeout N` | `scanner_orchestrator.py` |
| **Network access** (off by default) | `--allow-network` | `scanner_orchestrator.py` |
| Dedupe window and cross-file merging | `--line-window N`, `--min-fingerprint N`, `--no-cross-file` | `deduplicate_findings.py` |
| Undocumented-path policy | `--path-policy {separate,suppress,report}` | `validate_findings.py` |
| Score or leave unscored | `--no-score` | `validate_findings.py` |
| Cap the dataset | `--max-findings N` | `validate_findings.py` |
| Known raw secrets to hunt for | `--secrets-file FILE` | `validate_findings.py`, `validate_reports.py` |
| Refuse to write on a leak (default on) | `--fail-on-leak` / `--no-fail-on-leak` | `validate_findings.py` |
| Report formats | `--formats markdown,html,pdf,json` | `generate_reports.py` |
| Ticket output directory | `--ticket-dir DIR` | `generate_reports.py` |
| Run metadata (repository, commit, date, environment) | `--metadata audit-metadata.json` | `generate_reports.py`, `generate_pdf.py` |
| Require a PDF | `--require-pdf` | `validate_reports.py` |
| PDF timeout / keep LaTeX build | `--timeout N`, `--keep-build`, `--workdir DIR` | `generate_pdf.py` |

The installer is the one script with its own flags, because it is the one script that changes the
machine rather than reading a repository: `--check`, `--list`, `--yes`, `--dry-run`,
`--only`/`--skip`, `--prefix`, `--allow-sudo`, `--allow-download`, `--allow-unverified`, `--json`.
`python3 scripts/install_scanners.py --help` is the reference; §1 explains the policy behind each.

Exit codes are part of the interface: `0` means the stage did what it was asked; `1` from
`generate_reports.py` or `generate_pdf.py` means a format failed (the others are still written and
the manifest records which); `1` from `validate_findings.py` means a secret survived redaction and
nothing was written; `2` means the dataset failed schema validation; `1` from `validate_reports.py`
means the report set must not be delivered — the `problems` list says exactly what disagrees; `1`
from `install_scanners.py` means a requested tool is still missing after the run, and `2` that the
request cannot be satisfied on this host (unsupported platform, or the orchestrator module is
absent).

---

## 8. Limitations

State these in the report, not just in this file.

- **Static only.** No DAST, no live traffic, no credential testing, no exploitation. A
  runtime-only flaw (an environment variable set in production, a misconfiguration applied at
  deploy time) is out of reach unless its source is in the repository.
- **Precision is measured against fixtures, not your codebase.** The corpus in `tests/fixtures/`
  proves the rules fire on the 20 required classes and stay quiet on the secure look-alikes, with
  six documented false positives (`expected_findings.json → known_false_positives`). A production
  repository will surface different ones; treat the first run as a baseline to review, not a verdict.
- **`needs_review` is not a finding.** Findings whose attacker-reachable path cannot be established
  from source say so, are excluded from the ticketable count, and appear in their own report
  section. They are the honest middle ground between "confirmed" and "dropped".
- **Route coverage depends on enumerable routes.** Attribute-routed frameworks are mapped; a
  convention-routed controller (an ASP.NET Core MVC controller with no `[HttpGet]`/`[Route]`) can
  contribute no entry points, and parts of plain Java servlets likewise. Findings in that code carry
  no route context.
- **Business logic needs intent.** The rules can flag a client-controlled price, a missing state
  check or a one-time token that is not consumed; whether it is a vulnerability depends on the
  requirements, which are not in the repository.
- **Binaries and vendored blobs** are inventoried and reported as not analysed. A source audit
  cannot speak to a compiled artefact, and the report says so instead of implying coverage.
- **PDF is optional.** Without pandoc + xelatex there is no PDF, and the run says so in the manifest
  and the verifier's verdict. This repository's own validation was performed without that toolchain.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/vulnerabilities-scan` not offered | Skill directory not where Claude Code looks | `ls ~/.claude/skills/vulnerabilities-scan/SKILL.md`; personal skills are not read by Cowork/cloud sessions |
| Frontmatter rejected | YAML syntax or `name` ≠ directory name | `claude plugin validate ~/.claude/skills` |
| Skill never triggers by itself | Description too narrow for the request | Invoke it explicitly; or ask with the vocabulary in §3 |
| Report says scanners were unavailable | None of the ten external tools is installed | Install the ones you need, or accept the coverage limitation — the built-in analyzers still ran |
| A scanner "ran" but produced nothing | Exit code was non-zero (config error, crash) | Read `$out/scanners.json` / `raw-scans/`; the run marks it `failed`, not clean |
| No PDF | `pandoc` or `xelatex` missing | Install both, then `generate_pdf.py --help`; or keep the Markdown/HTML |
| PDF fails on Unicode | LaTeX font lacks the glyph | Use the default fonts, or pass `--keep-build` and inspect the log tail |
| Everything is slow on a big monorepo | Import scanning and rule matching over the whole tree | Audit module by module with `--root`; use `--max-import-files`, `--limit-per-file` |
| `No space left on device` | Output written to a small tmpfs (`/tmp`) | Point `--out`, `--outdir` and `TMPDIR` at a real disk |
| Permission denied reading files | The audit runs as a user without access | Fix permissions; unreadable files are listed under `not_analysed`, not silently skipped |
| `pyproject.toml` dependencies missing | Python < 3.11 has no `tomllib` | Run on 3.11+, or read the manifest listed in `unparsed_manifests` |
| Findings look stale after a fix | Evidence belongs to the snapshot that was audited | Re-run from stage 1; line numbers are pinned to the snapshot commit |
| Secrets appear in a raw scan file | Raw external tool output is preserved as evidence | Pass `--secrets-file` and check the verifier verdict; report a leak with the exact path |
| The installer printed steps instead of running them | Root steps are printed unless `--allow-sudo`, and nothing runs without `--yes` | Re-run with `--yes`; add `--allow-sudo` if you accept `sudo -n` execution |
| `install-scanners.sh` says no Python 3.8+ | The host has no interpreter on `PATH` | Follow the one-line install hint it prints for this distribution, or `brew install python` on macOS |
| A tool installed but `--check` still says MISSING | `go install`, `pipx` or `--prefix` put the binary outside `PATH` | Add `$(go env GOPATH)/bin`, `~/.local/bin` or the `--prefix` directory to `PATH`, then re-run `--check` |
| `--allow-download` refuses with "no checksum file" | The release publishes no checksum, so the archive cannot be verified | Pass `--allow-unverified` if you accept that, or install through a package manager instead |
| `pip` refuses to install into the system Python (PEP 668) | Debian/Ubuntu mark the system interpreter as externally managed | Install `pipx` from the distribution (`apt install pipx`) and let the installer use it; do not use `--break-system-packages` |

---

## 10. Development and validation

```bash
cd vulnerabilities-scan
python3 -m pytest tests -q          # 400 tests, ~60 s, offline, writes only under .scratch/
```

- `tests/fixtures/vulnerable-app/` — 34 files covering the 20 required vulnerability classes across
  Python, JavaScript/TypeScript, Go, Ruby, PHP, Java, Kotlin, C#, Rust, Swift, C, shell, PowerShell,
  SQL, Dockerfile, Kubernetes, Terraform, CloudFormation, Ansible, Compose, GitLab CI, Jenkins and
  GitHub Actions.
- `tests/fixtures/secure-app/` — the same shapes, correctly implemented, with every file
  byte-different from its vulnerable twin.
- `tests/fixtures/expected_findings.json` — the machine-readable expectation: per-class counts and
  the exact list of known false positives, with a reason for each.
- `tests/test_end_to_end_audit.py` — runs all eight stages over both corpora and asserts against the
  delivered artefacts: 20/20 classes, 6/6 recorded false positives and nothing else, per-finding
  JSON and index completeness, no raw secret in any deliverable, and a report set that passes its
  own verifier.

`docs/VALIDATION-RESULTS.md` records what was measured (108 findings on the vulnerable corpus,
78 validated / 28 needs_review / 2 suppressed, severity 17/37/45/9, 0 leaks, verifier exit 0), the
defects the audit found in the pipeline and how they were fixed, and the limitations that remain.
`docs/RESEARCH.md` records the standards, tool survey and dated sources behind the design, with
SHA-256 digests in `docs/RESEARCH-SOURCES.json`.

### Repository layout

```
vulnerabilities-scan/
├── SKILL.md                 the agent-facing workflow (the only file loaded at activation)
├── README.md                this file — install, use, configure, troubleshoot
├── references/              operational depth: methodology, taxonomy, scoring, language guides,
│                            scanner reference, false-positive handling, validation, reporting
├── scripts/                 the deterministic helpers, one per stage, each with --help
├── schemas/finding.schema.json   the formal finding contract
├── templates/               report layout for Markdown/HTML plus report.css
├── tests/                   pytest suite and both fixture corpora
├── prds/                    product requirements for future releases (not shipped in the skill)
└── docs/                    research, sources and validation results (development material)
```

Licence: MIT for this skill. `scripts/cvss4.py` and `scripts/cvss4_lookup.py` are vendored from the
FIRST CVSS 4.0 reference implementation; see `scripts/cvss4_LICENSE.txt`.

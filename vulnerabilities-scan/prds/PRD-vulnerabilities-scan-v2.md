# PRD — `vulnerabilities-scan` v2.0: from a defensible report to a defensible product

| Field | Value |
| - | - |
| Status | Draft for review |
| Document version | 1.0 |
| Target release | v2.0.0 of the skill |
| Date | 2026-11-13 |
| Scope | the skill in this directory: `SKILL.md`, `references/`, `schemas/`, `scripts/`, `templates/`, `tests/`, `docs/` |
| Evidence base | measured on 2026-11-13 at commit `f63dd0d`, Python 3.13.13, no network, no external scanners, no PDF toolchain |
| Related | [`SKILL.md`](../SKILL.md), [`README.md`](../README.md), [`references/reporting-standard.md`](../references/reporting-standard.md), [`docs/VALIDATION-RESULTS.md`](../docs/VALIDATION-RESULTS.md) |

---

## 1. Executive summary

The skill is in good structural health. Seventeen standard-library modules implement a nine-stage
audit; 97 detection rules feed a 20-field finding contract; CVSS 4.0 scoring is vendored from the
FIRST reference implementation; four report formats render from one dataset; 316 tests pass in 60
seconds with no network. Nothing in this PRD disputes that machinery, and nothing here proposes to
weaken the three properties that make the skill worth using: a pattern is a candidate, a dataflow is
a finding, a bypassed control is a confirmed finding; no silent success; one dataset, many views.

The problem is at the edges of that machinery, where the skill makes promises that no code keeps.
Five things the documentation names are not produced by anything: the `scope.json` record, a Score
stage, `raw_findings.json`, `verification.json` as a file, and `report.md` as a filename. The report
layout the reporting standard now mandates — one JSON per finding under `findings/review-required/`,
`findings/optional-hardening/`, `findings/no-action-suppressed/` — has no implementation: the code
writes a flat `tickets/` directory. Four documents disagree about what each stage writes, how many
stages there are, how many rules exist and how many findings the reference corpus yields. And the
output, while excellent for a human reader, is unusable by a security programme: there is no SARIF,
no baseline ("what is new since last week?"), no persistent suppression register, and no way to fail
a build because a Critical was found.

v2 is sequenced so that each of five milestones is independently shippable and independently useful:

1. **Truth.** One artefact registry, the bucketed `findings/` layout implemented, and a test that
   fails when the documentation and the code disagree about any artefact or stage. (M0)
2. **One command.** `scripts/run_audit.py` runs stages 0–8 with a `scope.json`, a real Score stage, a
   stage manifest and `--resume`; two stages stop writing different-quality data to one filename. (M1)
3. **CI-native.** SARIF 2.1.0 export, a persisted baseline with a diff view, a suppression register
   that survives re-runs, and severity gating through exit codes. (M2)
4. **Depth where the surface is widest.** Terraform, Kubernetes and Dockerfile get a detection
   reference and rules of their own; Kotlin, Rust, Swift, shell, PowerShell and SQL get real tables
   instead of five-line gestures. (M3)
5. **Measurement.** A blind third corpus, a precision/recall scoreboard, and documentation numbers
   generated from a measurement run rather than typed by hand. (M4)

Rough size: 30–40 engineer-days across five milestones, no new runtime dependency (the stdlib-only,
offline-by-default constraint survives intact), and a compatibility window that keeps
`tickets/VULN-NNN.json` readable for one release while consumers move to the index.

---

## 2. The skill today, measured

Every number in this PRD was produced on this machine on 2026-11-13. The commands are included so a
reviewer can re-derive them rather than trust the table.

### 2.1 Size and shape

| Measure | Value | Command |
| - | - | - |
| Tracked files | 126 | `git ls-files \| wc -l` |
| Python stage modules | 17 | `ls scripts/*.py \| wc -l` |
| Detection rules | 97 | `python3 scripts/builtin_analyzers.py --list-rules` → `{"rules": 97, "count": 97}` |
| Tests | 316, all passing, 59.9 s | `python3 -m pytest tests -q` |
| Test code | 4,456 lines across 14 modules | `wc -l tests/test_*.py \| tail -1` |
| Fixture corpora | 36 tracked files each, 74 under `tests/fixtures/` | `git ls-files tests/fixtures \| wc -l` |
| Reference documents | 8 files, ~81 KB | `wc -c references/*` |
| Agent-facing entry point | 169 lines, 12 KB | `wc -l SKILL.md` |
| Runtime | Python 3.13.13, stdlib only, offline | `python3 -V` |

### 2.2 Cost of an audit

Measured by auditing the skill's own tree (fixtures included, `.research/` and `.scratch/` excluded,
because they are large and machine-specific):

| Stage | Wall clock | Output |
| - | - | - |
| `repository_inventory.py` | 0.19 s | 126 files, 5 buckets |
| `builtin_analyzers.py` | 4.51 s | 176 raw findings |

That is ~36 ms per file for rule evaluation, i.e. roughly linear in file count and file size. It is
fast for a repository of this size and it says nothing about a 50 000-file monorepo, where the same
arithmetic predicts ~30 minutes with no way to resume a run that dies at minute 29.

The 176 findings on the skill's own tree are mostly the fixture corpora doing their job; the number
matters here only as a noise baseline for the self-audit target in §10.

### 2.3 What is genuinely strong

These are recorded because the PRD's job is to protect them, not to relitigate them:

* **One dataset, four views.** `generate_reports.py` builds a single view model
  (`scripts/generate_reports.py:140`) and hands the same object to all four generators, so counts,
  verdict and `generated_at` agree by construction rather than by inspection.
* **A verifier that refuses.** `validate_reports.py` exits 1 and names the disagreement when the
  formats diverge (`scripts/validate_reports.py:680-687` for its surface), and the 316-test suite
  includes the end-to-end artefact assertions that keep it honest.
* **Redaction at ingestion, one spelling per shape.** `builtin_analyzers.SECRET_PATTERNS` is the
  single source of the marker text and `finding_model.shape_marker` applies it in every redacting
  stage; `tests/test_redaction_markers.py` pins the invariant (documented at
  `docs/VALIDATION-RESULTS.md:315`).
* **Honest degradation.** A missing scanner, a missing PDF toolchain and an unreadable file all
  become recorded coverage limitations rather than clean results. This is the skill's identity and
  the reason the rest of this document is worth doing.

---

## 3. Problems

Each problem is stated as a claim that can be checked against the tree. Severity is about damage to
the skill's promise, not about the size of the fix.

### P1 — The reporting standard describes an artefact layout the code cannot produce

**Evidence.** `references/reporting-standard.md` (as of `f63dd0d`) specifies one JSON per finding,
filed under `findings/review-required/`, `findings/optional-hardening/` and
`findings/no-action-suppressed/`, with the bucket repeated as `disposition` in the file and in
`findings-index.json`. The code writes a flat directory: `TICKET_DIRNAME = "tickets"`
(`scripts/generate_json.py:74`), one directory for all three classifications
(`scripts/generate_json.py:368-386`), a single `ticket_dir` in the index
(`scripts/generate_json.py:345`), and the same flat name in `scripts/report_model.py:1006`. The
README and the validation record both document `tickets/` (`README.md:204-205`,
`docs/VALIDATION-RESULTS.md:227,283`).

**Why it matters.** A consumer that follows the standard finds nothing. A maintainer who trusts it
ships a documented contract that no test covers — the exact failure mode the skill accuses other
scanners of. This is the single most visible divergence in the tree because the standard is the
document that tells a reader how to trust the report.

**Severity:** high. **Fix:** WS-A, milestone M0.

### P2 — Stage 0 and stage 6 have no implementation

**Evidence.** `SKILL.md:44` says stage 0 writes `scope.json`; `SKILL.md:50` says stage 6 assigns CVSS
vectors and priority. `grep -rn "scope.json" scripts/` returns nothing, and `ls scripts/*.py` contains
no scoring module — scoring lives inside `validate_findings.py` behind `--no-score`
(`README.md:281`).

**Why it matters.** Stage 0 is the stage that records the commit being audited and the exclusions
that bound every later claim. If it is prose only, the "snapshot" identity depends on the agent
remembering to write a file, and the report's reproducibility claim rests on improvisation. Stage 6
being folded into stage 5 means the documented pipeline cannot be re-entered at the scoring step: the
only way to rescore is to re-validate, which re-reads evidence and can change other fields.

**Severity:** high. **Fix:** WS-B, milestone M1.

### P3 — Two stages write data of different quality to one filename

**Evidence.** `scanner_orchestrator.py --outdir` writes `<outdir>/findings.json`
(`scripts/scanner_orchestrator.py:1667-1669`) containing normalised, deduplicated, **unvalidated**
detections. `validate_findings.py --out` writes `<outdir>/findings.json` containing the **validated**
dataset. The README offers the orchestrator as a replacement for the analyzer and dedupe steps
(`README.md:175-181`), and separately runs validation with `--out "$out/findings.json"`
(`README.md:162-163`).

**Why it matters.** `findings.json` is defined as "the single source of truth" (`README.md:194`). A
file that sometimes holds raw merged scanner output and sometimes holds validated findings cannot be
a source of truth, and the moment validation overwrites it the pre-validation state is gone, so the
audit trail of "what the scanners said versus what we concluded" is unrecoverable. This is a
correctness defect in the most important filename in the system.

**Severity:** high. **Fix:** WS-B (rename to `raw_findings.json`, keep `findings.json` exclusively for
the validated dataset), milestone M1.

### P4 — Four documents disagree about the pipeline's own vocabulary

**Evidence.** See the divergence register in Appendix B. The headline rows: `SKILL.md` promises nine
stages, the README and the validation record say eight (`SKILL.md:42-52` vs `README.md:363`,
`docs/VALIDATION-RESULTS.md:6,24`); stage 3 produces `raw_findings.json` per `SKILL.md:47` but
`analysis.json` in the quick start (`README.md:160`); stage 4 produces `findings.json` per
`SKILL.md:48` but `deduped.json` in the quick start (`README.md:161`); stage 7 produces `report.md`
per `SKILL.md:51` but `SECURITY-AUDIT-REPORT.md` in `scripts/report_model.py:1000`; the attack
surface file is `attack_surface.json` in one document and `attack-surface.json` in another; raw
scanner output goes to `raw-scans/` per `README.md:180` but `raw/` per
`scripts/scanner_orchestrator.py:1628`; `verification.json` is listed as an output (`README.md:196`,
`scripts/report_model.py:1009`) while the validator deliberately writes its verdict to stdout
(`docs/VALIDATION-RESULTS.md:293-296`).

**Why it matters.** Re-entry at a stage — the property `SKILL.md:39-40` advertises — requires that
the file a stage reads is the file the previous stage wrote. When the names disagree, the agent
guesses, and a guessed path either fails loudly (good) or silently re-analyses the wrong artefact
(bad). The full register — nineteen rows, vocabulary and counts — is in Appendix B.

**Severity:** high. **Fix:** WS-A (registry + parity test) and WS-H (documentation), milestone M0.

### P5 — No machine-consumable output for a security programme

**Evidence.** `grep -ril sarif scripts/` returns nothing; SARIF appears twice in the corpus, once as
a format semgrep *can* emit (`references/scanner-reference.md:38`) and once as a line-base hazard
(`references/scanner-reference.md:142`). The pipeline neither reads nor writes it.

**Why it matters.** GitHub code scanning, GitLab SAST reports, DefectDojo, and most SIEM ingestion
speak SARIF. Today the skill's output can only be consumed by a human or by bespoke code that parses
`findings-index.json`. That caps adoption at "run it and read the PDF", which is the usage pattern
the skill is trying to graduate from.

**Severity:** high. **Fix:** WS-C, milestone M2.

### P6 — No baseline: every run re-reports the whole history

**Evidence.** No baseline, diff or changed-files flag exists (`grep -ril baseline scripts/` matches
only prose about the built-in analyzers being the "baseline"). The per-finding JSON already carries a
stable `fingerprint` (`scripts/generate_json.py:382-384`), so identity exists; what is missing is
anything that compares two runs.

**Why it matters.** A team that adopts the skill and fixes three of 93 findings runs it again and
receives 90 findings plus three new ones, indistinguishable from the previous report except by
reading both. That is how a security tool becomes a quarterly ceremony. The absence of a baseline is
also why the report cannot answer the only question a release manager asks: *what got worse?*

**Severity:** high. **Fix:** WS-C (baseline + diff view + gating), milestone M2.

### P7 — No persistent suppression register

**Evidence.** Suppression is expressed inside one dataset (`validation_status: suppressed` plus
`suppression_reason`); `validate_findings.py` re-derives it on every run from the code it re-reads.
There is no file an operator can edit to say "this is accepted risk until Q3", and no flag to load
one (`grep -ril "suppress-file\|suppression file" scripts/` returns nothing).

**Why it matters.** Accepted risk is a human decision with an owner and an expiry date. Recomputing
it from heuristics every run means the same argument is had again every run, and a finding that a
human explicitly accepted can reappear as noise — the exact failure that teaches teams to ignore the
tool.

**Severity:** medium-high. **Fix:** WS-C, milestone M2.

### P8 — The exit codes talk about formats, not about risk

**Evidence.** `validate_reports.py` accepts `--outdir`, `--dataset`, `--secrets-file`, `--manifest`,
`--require-pdf`, `--indent` (`scripts/validate_reports.py:680-687`). Nothing accepts
`--fail-on-severity`. Exit 1 means "a format failed" or "this report set must not be delivered"
(`README.md:291-295`); a Critical finding is exit 0.

**Why it matters.** A pre-merge gate is the highest-value integration a static auditor can offer,
and it is one flag away. Without it, the skill's CI story is "generate a PDF and hope someone reads
it".

**Severity:** medium-high. **Fix:** WS-C, milestone M2.

### P9 — Detection prose is thinnest exactly where the advertised surface is widest

**Evidence.** `references/language-security-guides.md` opens by claiming "the seven languages in
scope" (lines 3–4) while containing eleven language sections. Python, JavaScript/TypeScript, Go, Ruby,
PHP, Java and C# each get a 15–18 line sink/safe table. Rust gets 8 lines of prose, C/C++ 8 (an
acknowledged hand-off to compiler analyzers), Swift 5, Kotlin 7 folded under "JVM languages", shell 6,
PowerShell 6, SQL 6. Kubernetes appears only as three lines in
`references/vulnerability-taxonomy.md:247-249` and Terraform as two lines at `:250-251`; neither has
a section in the detection reference at all, and Dockerfile has no section, only a bullet merged with
Helm. Meanwhile `SKILL.md:3` advertises all of these, and `scripts/repository_inventory.py:65-85` and
`scripts/scanner_orchestrator.py:74-75` do parse `.tf`, `.hcl`, `.kt`, `.swift`, `.ps1` and
`IAC_FILE_RE`-matching paths.

**Why it matters.** Stage 3 and stage 5 tell the agent to read the language guide before calling a
sink dangerous. Where the guide is silent, validation has no safe-equivalent to rule out, so the
honest options are to report at MEDIUM with no controls checked or to guess — and the skill's own
rule ("cannot establish location and attacker-reachable path → downgrade") then degrades a whole
language family to advisory noise. Terraform is the sharpest case: the scanner emits findings for it,
the taxonomy names it, and no document tells the agent what a safe Terraform configuration looks like.

**Severity:** medium-high. **Fix:** WS-D, milestone M3.

### P10 — Precision is asserted from a corpus the rules were written against

**Evidence.** The suite proves 20/20 required classes fire and the secure look-alikes stay quiet
across 36 fixture files per corpus, plus six recorded false positives
(`README.md:354-365`, `docs/VALIDATION-RESULTS.md:155-178`). There is no measurement against code the
authors did not write, no recall estimate (a fixture can only prove a rule fires where a file was
written to make it fire), and no per-rule negative-case requirement outside the seven original
languages — the newer families rely on `tests/test_scan_families.py` (9 tests).

**Why it matters.** "Precision is measured against fixtures, not your codebase" is stated honestly in
`README.md:306-309`, which is the right thing to do — and it is also the ceiling of the current
claim. Without a blind corpus the 97 rules cannot be improved deliberately, only anecdotally, and the
first real audit becomes the QA run.

**Severity:** medium. **Fix:** WS-E, milestone M4.

### P11 — Documentation numbers are typed, not generated, and they have drifted

**Evidence.** `README.md:223` says 97 rules; `docs/VALIDATION-RESULTS.md:68,127` says 71. The same
validation record reports 135 findings, 93 validated, 39 `needs_review` and 3 suppressed
(`docs/VALIDATION-RESULTS.md:141,204,211`) and then, eight lines later, 108 findings, 78 validated and
28 `needs_review` (`:216-217,222-227,298`) — apparently two different runs merged into one document.
`README.md:368` carries the 108-run's severity split (17/37/45/9) while
`docs/VALIDATION-RESULTS.md:206-209` carries 18/43/62/12. The fixture corpora are described as 34
files (`docs/VALIDATION-RESULTS.md:75`) and as 24 files (`:125,247`) but are 36 tracked files each.
The defect table has ten rows and the closing paragraph calls them "the six defects above"
(`:379`). The README lists finding fields that the schema does not define — `owasp_reference`,
`cvss_version`, root cause, preconditions, `remediation` (`README.md:208-213`) versus the actual
contract's `owasp` and 20 required keys
(`schemas/finding.schema.json` → `$defs.finding.required`).

**Why it matters.** The skill's authority rests on falsifiability: every claim names a command and an
artefact. A number that cannot be reproduced turns a falsifiable document into marketing, and it
poisons the reader's trust in the numbers that *are* right. It also means the maintainer has no way to
notice drift — nothing fails when a count goes stale.

**Severity:** medium. **Fix:** WS-H, milestone M0 for the corrections, M4 for the generator.

### P12 — The skill is not tested against the thing it warns about

**Evidence.** `SKILL.md:26-29` makes repository content untrusted data a non-negotiable operating
rule, and stage 8 checks for unredacted secrets. No fixture contains a prompt-injection attempt, no
test asserts that an injected instruction is reported as an observation rather than obeyed, and no
test fuzzes the redaction path with adversarial secret shapes.

**Why it matters.** The most plausible way this skill causes harm in 2026 is not a missed SQL
injection; it is a malicious repository that talks the agent into exfiltrating `.env` or into
suppressing findings. The rule is stated but unproven, and an unproven rule is a wish.

**Severity:** medium-high. **Fix:** WS-I, milestone M2 (a corpus is cheap; it is the assertions that
need care).

### P13 — No release engineering

**Evidence.** No `.github/`, no CI configuration, no `pyproject.toml`, no changelog, no version field
anywhere. The frontmatter is `name`, `description`, `compatibility`, `license` (`SKILL.md:1-6`) while
the Agent Skills specification supports `metadata.version` and `allowed-tools`
(`.research/agentskills-spec.md:32-35,166-196`). Compatibility is claimed for Python 3.8+ with 3.13
tested (`README.md:65-67`).

**Why it matters.** The suite only runs when someone remembers. A 3.8 regression, a stale
`references/` link, or a rule that starts matching its own source ships silently. The missing
`metadata.version` means a consumer cannot tell v1.4 from v2.0, and the missing `allowed-tools` leaves
the read-only guarantee to good behaviour rather than to a declared capability set.

**Severity:** medium. **Fix:** WS-J, milestone M1 (CI on day one of M0's branch), hardening in M4.

### Problem → workstream map

| Problem | Workstream | Milestone |
| - | - | - |
| P1 artefact layout, P4 vocabulary, P11 stale numbers (corrections) | A, H | M0 |
| P2 stage 0/6, P3 filename collision | B | M1 |
| P5 SARIF, P6 baseline, P7 suppression register, P8 gating | C | M2 |
| P12 adversarial corpus | I | M2 |
| P9 detection depth | D | M3 |
| P10 precision measurement, P11 generated numbers | E, H | M4 |
| P13 release engineering | J | M1 → M4 |

---

## 4. Goals, non-goals, success metrics

### 4.1 Goals

| ID | Goal | Measured by |
| - | - | - |
| GO1 | Every artefact the documentation names is produced by code, and the test suite fails when that stops being true | doc-parity test; zero rows in Appendix B |
| GO2 | One command runs a complete audit, resumes after failure, and states what it did | `run_audit.py --resume`; stage manifest |
| GO3 | The output is consumable by CI without bespoke parsing | valid SARIF 2.1.0; baseline diff; severity gate |
| GO4 | Detection guidance exists for every format the skill advertises | one section per advertised family in the detection reference, each with a sink/safe table |
| GO5 | Precision and recall are measured, not asserted | scoreboard over three corpora, published per rule |
| GO6 | A 1 000-file repository audits in under 60 s and a 10 000-file monorepo resumes incrementally | timing harness in CI |
| GO7 | Activating the skill costs ≤ 6 000 tokens and teaches the workflow without reading `references/` | `SKILL.md` word count; staged-loading note |

### 4.2 Non-goals

* Dynamic analysis, traffic generation, credential testing, exploitation. Still out of scope, still
  stated in the report.
* Applying fixes or opening pull requests. The skill proposes; a human disposes.
* Replacing semgrep or CodeQL. The skill's differentiator is validation and the defensible report,
  not rule count parity.
* A hosted service, a dashboard, or a database. Files on disk remain the interface.
* Multi-target orchestration (auditing several repositories as one run). Out of scope for v2.
* A GUI. The HTML report is the GUI.

### 4.3 Success metrics

| Metric | Today | v2 target |
| - | - | - |
| Documented artefacts or stages that nothing produces | 5 | 0 |
| Doc↔code divergences in Appendix B | 19 | 0, enforced by test |
| Tests | 316 | ≥ 420, including 12 contract tests |
| Rules with a positive and a negative fixture | 97 (via 2 corpora) | 97 + every added rule, asserted per rule |
| Blind-corpus precision | unmeasured | ≥ 0.85 on MEDIUM+ after M4 |
| Blind-corpus recall on the 20 required classes | unmeasured | ≥ 0.90 |
| Self-audit findings on this repo (fixtures excluded) | 176 | ≤ 40 after M3 precision work; recorded, not hidden |
| Runtime, 1 000 files | ~36 s (extrapolated) | ≤ 60 s measured, with `--jobs` |
| Findings re-reported after a 3-fix run | 90 (no baseline) | 0 new, 3 fixed, 87 unchanged — from the diff |
| Time to a usable CI gate | n/a | one workflow file, 15 minutes |

---

## 5. Users and jobs to be done

| User | Job | What they need from v2 |
| - | - | - |
| **The agent** (primary consumer of `SKILL.md`) | Run a complete, resumable audit and never invent a claim | A stage contract that names real files, a one-command path, and failure semantics that are unambiguous |
| **The developer who receives a finding** | Understand and fix one issue without reading a 200-page report | One file per finding, in a directory that says how urgent it is, with location, evidence and a concrete fix |
| **The security lead** | Answer "are we better than last month?" and gate a release | Baseline diff, trend counts, `--fail-on-severity`, suppression register with owners and expiry |
| **The compliance reviewer** | Reproduce the audit's claims | `scope.json` with commit and exclusions, stage manifest, digests, SARIF for the tracker, and a verifier that exits 1 when the set disagrees |
| **The maintainer** | Change a rule without breaking a promise | CI on every push, doc-parity tests, generated numbers, per-rule fixtures |
| **The auditor of the auditor** | Check that the tool did what it said | Coverage section, negative findings, the control searches recorded per finding (`validation` field), and the prompt-injection observations |

---

## 6. Design principles

These constrain every requirement below. A proposal that violates one is rejected regardless of
value.

1. **The dataset is the only truth.** Every view — Markdown, HTML, PDF, SARIF, per-finding JSON,
   index — is derived and disposable. Hand-editing a view is a bug, not a hotfix.
2. **A path is a claim.** If a document names a file, code must write that file, and a test must fail
   when it stops. Prose that describes an intention is labelled as such.
3. **Silence is a bug.** An absent tool, an unreadable file, an empty bucket, a skipped stage: each is
   an explicit record. "Nothing found" is only a claim alongside what was examined.
4. **Deterministic or it does not ship.** Same input, same bytes — apart from `generated_at` and run
   identity, which are quarantined in `meta`.
5. **Stdlib only, offline by default.** No new runtime dependency. Network stays behind
   `--allow-network`. PDF stays optional.
6. **Untrusted input stays data.** Repository content is never an instruction; the agent's own output
   directory is the only place it writes.
7. **Numbers are measurements.** Any count in a document names the command that produces it, and is
   regenerated rather than edited.
8. **Cheap to activate.** `SKILL.md` is the only file loaded at activation; depth lives in
   `references/` and is read per stage.

---

## 7. Requirements

Priorities: **MUST** (release blocker for its milestone), **SHOULD** (deferred only with a recorded
reason), **COULD** (opportunistic). Each requirement names its milestone and a criterion that a test
or a command can decide.

### WS-A — Artefact and contract truth (M0)

**Intent.** Give the skill one registry of artefacts and one test that keeps documentation, code and
schema telling the same story. Everything else in this PRD depends on it: a bucketed layout is
worthless if four documents describe three different layouts.

| ID | Priority | Requirement | Acceptance criterion |
| - | - | - | - |
| A1 | MUST | One JSON per finding under `findings/review-required/`, `findings/optional-hardening/`, `findings/no-action-suppressed/`, assigned by the precedence table in `references/reporting-standard.md` §2 | Full pipeline run on `tests/fixtures/vulnerable-app`: every finding id appears exactly once across the three directories; `findings-index.json` entries carry `disposition` and a matching `json.path`; a finding moved to the wrong bucket makes `validate_reports.py` exit 1 |
| A2 | MUST | All three subdirectories are created on every run, even when empty | Running with `--formats json` on a clean corpus leaves three empty directories and an index with three zero totals |
| A3 | MUST | A single module owns artefact names and paths (`scripts/artefacts.py`), replacing `OUTPUT_NAMES`, `TICKET_DIRNAME` and the literal names in generators | Grepping the literal filenames outside `artefacts.py`, `tests/` and `docs/` returns nothing; generators import from it |
| A4 | MUST | `tickets/VULN-NNN.json` remains readable for one release behind `--legacy-tickets` (default on until v2.1) | Legacy output is written only when the flag is passed; docs mark it deprecated with a removal version |
| A5 | MUST | `tests/test_docs_contract.py` parses the stage table in `SKILL.md`, the layout block in `README.md`, the deliverables table in `references/reporting-standard.md` and `schemas/finding.schema.json`, and asserts every named artefact and field exists | Renaming `findings-index.json` in the registry, deleting a stage row, or removing a schema key each fail the test with a message naming the document and line |
| A6 | MUST | One vocabulary for stage artefacts: `scope.json`, `inventory.json`, `technologies.json`, `attack-surface.json`, `raw_findings.json`, `deduped.json`, `findings.json`, `verification.json`, `reports/*` | Appendix B's 19 rows are all closed; the register is re-run as a test that greps the four documents for artefact names |
| A7 | SHOULD | `verification.json` is written as a file when `--write-verdict` is passed, stdout otherwise | Both modes tested; the default behaviour documented in `README.md` and `references/reporting-standard.md` is the one the code performs |
| A8 | COULD | A `--print-contract` flag prints the registry as JSON so the agent can discover paths instead of parsing prose | Output validates against a small schema; used by `run_audit.py` (B1) |

**Specification notes.**

*Bucket precedence.* The standard's table is authoritative and ordered: suppressed first, then
`needs_review` and validated Critical/High/Medium (and P0–P2), then everything else. Two edge cases
must be decided in code, not prose: a validated **Medium with priority P3** (bucket:
`optional-hardening/`, because priority is the human-facing urgency signal) and a **suppressed
Critical** (bucket: `no-action-suppressed/` — the suppression is the decision that matters, and the
severity stays in the file). Both get table-driven tests.

*Compatibility.* Changing a documented path is a breaking change for anyone who scripted against
`tickets/`. The index already carries the path of every file, so the migration is: v2.0 writes both
layouts by default (`findings/` authoritative, `tickets/` a copy), v2.1 drops the legacy copy, v3.0
removes the flag. The warning is printed once, to stderr, naming the removal version.

*Why a registry module rather than constants per file.* The current names are spread across
`scripts/generate_json.py:74`, `scripts/report_model.py:999-1012`, `scripts/generate_reports.py:95-106`
and prose in four documents; each new artefact has to be added in four places and forgotten in one.
A registry makes "the document names a file the code does not write" a type error rather than a
proofreading task.

### WS-B — Audit execution: scope, one command, resumability, scoring (M1)

**Intent.** Make the nine documented stages executable as one deterministic run with a real stage 0
and a real stage 6, so the agent stops hand-assembling eight shell commands and stops guessing where
a partial run left off.

| ID | Priority | Requirement | Acceptance criterion |
| - | - | - | - |
| B1 | MUST | `scripts/run_audit.py` runs stages 0–8 in order and writes `stage-manifest.json` recording each stage's inputs, outputs, status, duration and digests | One command produces every artefact on both corpora; the manifest lists nine stages with `status: ok`; a deliberately failed stage records `status: failed` plus stderr tail and exits 1 |
| B2 | MUST | `run_audit.py --resume` re-enters at the first incomplete stage without replaying completed ones | Killing the run after stage 3 and resuming produces byte-identical artefacts to an uninterrupted run (except run identity) |
| B3 | MUST | Stage 0 implemented: `scope.json` written by code, carrying target, commit, branch, dirty state, exclusions, read-only confirmation and skill version | `scope.json` exists after every run; its commit equals `git rev-parse HEAD`; its exclusions equal the flags passed; the report's header copies it rather than re-deriving |
| B4 | MUST | Stage 6 implemented as `scripts/score_findings.py` with the CVSS 4.0 calculator as its only scoring engine | Scoring a dataset twice yields identical vectors and scores; `--no-score` still produces explicit `unscored` markers; no scoring code remains duplicated in `validate_findings.py` |
| B5 | MUST | `findings.json` means the validated dataset only; the orchestrator writes `raw_findings.json` | Grep for `findings.json` writes returns exactly one module; the quick start's two paths both end with validation writing `findings.json` |
| B6 | SHOULD | `--jobs N` parallelises per-file rule evaluation and per-finding validation with deterministic output ordering | `--jobs 8` on a 1 000-file corpus produces byte-identical `findings.json` to `--jobs 1`, and is measurably faster in the timing harness |
| B7 | SHOULD | `--changed-since REF` limits analysis to files touched in the diff while still emitting coverage for the unexamined rest | A two-file diff audits those two files, and the report's coverage section says the other N files were not re-examined |
| B8 | COULD | Stage-level `--only` and `--from STAGE` selectors on `run_audit.py`, so a debugging maintainer can run one stage against existing inputs | Covered by the resume test; help text documents the stage names from appendix C |

**Specification notes.**

*Why stage 6 must be separate.* Scoring is currently a side effect of validation, which means a
rescoring run re-reads evidence and can silently change `confidence` and `validation_status`. Splitting
it also makes the "unscored" contract enforceable in one place: a finding with `scoring: unscored`
must have `cvss_vector: null` and `cvss_score: null`, and that is easier to assert when one module owns
every write to those three fields.

*Why stage 0 must be code.* The report header currently derives repository identity from
`report_model`'s own reading of the snapshot. Two readers of the same fact will eventually disagree,
and the disagreement will be about the commit a finding belongs to. Writing `scope.json` first and
copying it into the header makes the identity a single record.

*Failure semantics* (to be documented in `README.md` §7 and `SKILL.md` stage 8):

| Condition | Exit | Effect |
| - | - | - |
| A stage fails | 1 | Manifest records the stage and stderr tail; no later stage runs; artefacts stay for resume |
| A format fails | 1 | Other formats still written; manifest records which (today's behaviour, preserved) |
| Schema validation fails | 2 | No dataset written (today's behaviour, preserved) |
| A secret survives redaction | 1 | Nothing written (today's behaviour, preserved) |
| `--fail-on-severity` threshold met | 3 | Report set written and verified, then the run fails, so CI blocks while the artefacts remain inspectable |

### WS-C — Interoperability: SARIF, baseline, suppression register, gating (M2)

**Intent.** Turn the report into an input for the systems a security team already runs, and make the
skill usable as a gate rather than as a ceremony.

| ID | Priority | Requirement | Acceptance criterion |
| - | - | - | - |
| C1 | MUST | `scripts/generate_sarif.py` emits SARIF 2.1.0: one `run` per tool, rules with CWE/OWASP tags and CVSS-derived `security-severity`, results with physical locations, partial fingerprints from the existing `fingerprint`, and `invocations` recording coverage limitations | Output validates against the official SARIF schema; a fixture report ingests into GitHub code scanning with every finding mapped to a file and line |
| C2 | MUST | SARIF severity mapping is documented and tested: Critical/High → `error`, Medium → `warning`, Low/Informational → `note`, and `security-severity` carries the CVSS number | Table-driven test over all five bands plus unscored |
| C3 | MUST | Suppressed and `needs_review` findings appear in SARIF with the correct SARIF `suppressions`/`baselineState` semantics, never as silent omissions | A suppressed finding is present with `suppressions[0].kind = "external"` and its reason |
| C4 | MUST | `--baseline FILE` classifies every finding as `new`, `unchanged` or `fixed` by fingerprint, and the report gains a "Changes since baseline" section | Diffing a run against itself yields zero new; after fixing three findings the diff reports three `fixed` and zero `new` |
| C5 | MUST | `findings-baseline.json` can be produced and consumed by the pipeline (`--write-baseline`), carrying fingerprint, id, location, severity and first-seen run identity | The baseline round-trips through the diff; a stale baseline (different commit, same fingerprints) still matches |
| C6 | MUST | A suppression register (`suppressions.json`) accepts `{fingerprint, reason, owner, expires, ticket}` and is applied at validation, recorded per finding, and reported when expired | An expired entry re-activates its finding and emits a coverage note; an unknown fingerprint is reported as stale rather than ignored |
| C7 | SHOULD | `validate_reports.py --fail-on-severity {Critical,High,Medium}` exits 3 when a delivered finding meets or exceeds the threshold | Gate test in CI: a corpus with a Critical fails; the same corpus with `--fail-on-severity Critical` after suppression passes |
| C8 | SHOULD | `--format junit` emits one test case per finding for CI systems that only understand JUnit XML | Schema-valid XML; one case per finding; skipped for suppressed |
| C9 | COULD | GitHub Actions composite action (`action.yml`) wrapping v2's one command with inputs for severity gate, baseline and SARIF upload | Exercised in this repository's own workflow on a fixture, not on a real user repository |

**Specification notes.**

*Fingerprint stability is the hinge.* C4–C6 all depend on the fingerprint surviving refactors that move
a line. The current fingerprint is built in `deduplicate_findings.py` and carried into the per-finding
file (`scripts/generate_json.py:382-384`). It must be defined once, documented in the standard, and
tested against three mutations: a line shift of +5, a file rename, and a code change inside the
finding's range. Line-shift and rename must keep identity; the code change may break it, and that is
acceptable — but it must be a stated rule, not an emergent behaviour.

*Why SARIF is not just another renderer.* SARIF is the only output with an external authority: a
schema, a consumer and a set of semantics for suppressions and baseline state. Producing it forces
the skill to state things it currently leaves implicit — the rule catalogue (currently only reachable
via `--list-rules`), the mapping from CVSS to a severity level, and what happens to a finding nobody
is allowed to act on.

### WS-D — Detection depth and coverage (M3)

**Intent.** Close the gap between what `SKILL.md` advertises and what `references/` can teach. The
rule engine already parses these formats; the human-facing guidance does not, so validation has
nothing to check against.

| ID | Priority | Requirement | Acceptance criterion |
| - | - | - | - |
| D1 | MUST | `references/language-security-guides.md` gains full sink/safe tables for Kotlin, Rust, Swift, shell, PowerShell and SQL, at the depth of the existing seven | Each section ≥ 15 lines with at least three danger/safe pairs and one framework-authorisation note where a framework exists |
| D2 | MUST | The same file gains a dedicated infrastructure section covering Dockerfile, Kubernetes, Terraform, CloudFormation, Ansible, Compose, GitLab/Jenkins and GitHub Actions, replacing the merged bullets | Each family has a table of at least four unsafe→safe pairs; the heading matches its body |
| D3 | MUST | Terraform coverage includes state handling, provider and module pinning, IAM wildcards, public bucket/ACL, security-group ingress and secrets in variables; each rule names the CWE and the safe alternative | At least six Terraform rules with positive and negative fixtures in `tests/fixtures/{vulnerable,secure}-app/infra/terraform/` |
| D4 | MUST | Kubernetes coverage includes privileged/hostPath/hostNetwork, missing resource limits, default service-account token automount, wildcard RBAC and missing NetworkPolicy | At least six rules with both-direction fixtures |
| D5 | MUST | Dockerfile coverage includes root user, `apt-get` without pin/cleanup, `ADD` from remote, secrets in `ARG`/`ENV`, `:latest`, and a hadolint-compatible rule id | At least six rules with both-direction fixtures |
| D6 | SHOULD | A per-rule fixture requirement: adding a rule without a positive and a negative fixture fails the suite | `test_rule_fixture_parity.py` compares `--list-rules` against the fixture manifest and fails on an unpaired rule |
| D7 | SHOULD | The "seven languages in scope" self-description is removed and the file states its actual coverage and its gaps | Doc-parity test asserts the count matches the sections present |
| D8 | COULD | Light taint tracking for the newer families: a sink reached from a request-binding construct without an intervening sanitiser is raised to HIGH; everything else stays MEDIUM | Measured on the blind corpus: recall gain recorded, false-positive delta recorded; merged only if precision holds at ≥ 0.85 |

**Specification notes.**

*What "depth" means here.* The existing tables are the template: a sink, the safe equivalent, and the
framework mechanism that supplies authentication or authorisation. Depth is not more prose; it is
more **pairs**, because a pair is what validation consumes. A section that says "Terraform can be
misconfigured" is worthless; a row that says "`acl = "public-read"` → use `acl = "private"` plus a
bucket policy scoped to a principal" is a rule and a validation step.

*Ordering inside M3.* Terraform, then Kubernetes, then Dockerfile, then the language sections. The
first three have scanner support already (checkov, trivy, hadolint), so a rule written there can be
cross-checked against an external tool the moment one is installed — the fastest path from prose to
measured precision.

### WS-E — Measurement and precision (M4)

**Intent.** Replace "precision is measured against fixtures" with a number, and give the maintainer a
way to know whether a rule change helped.

| ID | Priority | Requirement | Acceptance criterion |
| - | - | - | - |
| E1 | MUST | A blind third corpus of real-world code (vendored, licence-compatible, at least 20 000 lines across the 20 required classes) with adjudicated ground truth | Corpus committed with its licence and a per-finding adjudication note; audited by the harness, never by the rule author alone |
| E2 | MUST | A scoreboard command (`--scoreboard`) reports per-rule true/false positives, precision and recall over all three corpora | Printed table plus `scoreboard.json`; a deliberately broken rule changes the numbers in the expected direction |
| E3 | MUST | The 20 required classes carry a recall number, not only a presence check | Recall ≥ 0.90 on the blind corpus, recorded in `docs/VALIDATION-RESULTS.md` with the command |
| E4 | SHOULD | A mutation harness flips every safe look-alike into its vulnerable twin and asserts the rule notices | Each fixture pair yields a detection delta; a pair with no delta is reported as a weak fixture |
| E5 | SHOULD | Self-audit noise budget: auditing this repository reports a named set of findings, with any increase failing CI | `tests/fixtures/self-audit-expected.json`; the current 176 becomes a fixture-excluded baseline |
| E6 | COULD | Optionally run semgrep/bandit/trivy when present and use their hits as an adjudication cross-check in the scoreboard | Cross-check column populated when the tool exists, "not installed" otherwise — never silently blank |

**Specification notes.**

*Why a blind corpus is mandatory rather than nice-to-have.* The fixture corpora were written by the
same hands that wrote the rules; they prove a rule fires where it was designed to fire. Only code the
authors did not write can distinguish "97 rules that work" from "97 patterns that match their own
examples". E1 is the largest single item in this PRD (8–12 days of adjudication) and it is the one
that changes the product's claim from *defensible* to *measured*.

*Adjudication discipline.* Every blind-corpus finding needs a second opinion recorded as
`{file, line, verdict, reason}`, with `verdict ∈ {true, false, undecidable}`. Undecidable is a real
category — business-logic flaws need intent the corpus cannot supply — and it must not be silently
counted either way.

### WS-F — Performance and scale (M1 for the harness, M2 for incremental)

| ID | Priority | Requirement | Acceptance criterion |
| - | - | - | - |
| F1 | MUST | A timing harness measures inventory, detection, validation and rendering on 100, 1 000 and 10 000 file corpora, and CI records the numbers | Numbers in `docs/VALIDATION-RESULTS.md` are generated by the harness, not typed |
| F2 | SHOULD | Per-file caching keyed on content hash so an unchanged file is not re-analysed | Second run over an unchanged tree is ≥ 5× faster with identical output |
| F3 | SHOULD | Memory ceiling: the pipeline never holds more than N MB of file content at once, documented and asserted | Test with a synthetic 50 MB file: the run completes or records a coverage limitation, never OOMs |
| F4 | COULD | `--budget-seconds` stops analysis at a deadline and records a coverage limitation naming what was skipped | Exceeded budget yields exit 0 with an explicit limitation, never a truncated report presented as complete |

**Specification notes.** The measured 4.5 s for 126 files is a good sign, not a guarantee: rule
evaluation is regex per file, so cost scales with bytes as much as with files, and the `--max-bytes`
flag already exists (`README.md:271`). The honest v2 position is a measured envelope with a stated
limit, not a promise that monorepos are fast. Where the envelope is exceeded the run must **say so**
— F4 exists so that a slow repository produces an honest partial report instead of a timeout or an
OOM kill that leaves an unexplained gap.

### WS-G — Agent-facing ergonomics (M3)

**Intent.** `SKILL.md` is loaded at activation and is the only file the agent reads before it starts.
It must teach the workflow, name the real files, and fit in a sensible token budget.

| ID | Priority | Requirement | Acceptance criterion |
| - | - | - | - |
| G1 | MUST | `SKILL.md` names only artefacts the registry produces, and links each stage to the one command that performs it | Doc-parity test (A5) covers `SKILL.md`; a dry-run instruction block is copy-pasteable and works |
| G2 | MUST | `SKILL.md` stays ≤ 220 lines and ≤ 6 000 tokens, with depth pushed into `references/` and a one-line trigger for when to read each | Token count in CI; a reviewer can follow stages 0–8 without opening `references/` |
| G3 | SHOULD | Frontmatter gains `metadata.version`, `metadata.stage-contract: v2` and `allowed-tools` limited to read/execute operations the skill actually needs | `claude plugin validate` passes; `allowed-tools` reviewed against the read-only rule and documented in `README.md` |
| G4 | SHOULD | The description stays trigger-rich but is tested: a corpus of 20 realistic user requests maps to ≥ 18 matches, and 20 unrelated requests map to ≤ 1 | `tests/test_description_triggers.py` with the request corpus in `tests/fixtures/description-cases.json` |
| G5 | SHOULD | An explicit "when to refuse" block: binary-only target, live system, request to apply fixes, request to exfiltrate or validate a credential | Three refusal fixtures, asserted in the end-to-end test as exit-with-message rather than a report |
| G6 | COULD | A `--dry-run` planner that prints the commands stage 0–8 would execute, so the agent can show the plan before touching anything | Output is the same command list `run_audit.py` would run, in order |

**Specification notes.** The skill's current description is long but well built for discovery: it
enumerates the phrases a user would type. G4 protects that investment with a test rather than a
rewrite. G2 is a hard budget because every activation pays it; the current file is 169 lines and 12 KB,
which is defensible today, and the risk is that M1's new flags double it.

### WS-H — Documentation integrity (M0 for corrections, M4 for generation)

| ID | Priority | Requirement | Acceptance criterion |
| - | - | - | - |
| H1 | MUST | Every stale number in Appendix B is corrected against a fresh measurement | A reviewer re-runs the commands in §2 and gets the numbers printed |
| H2 | MUST | One measurement run produces `docs/measurements.json`; the counts in `README.md`, `SKILL.md` and `docs/VALIDATION-RESULTS.md` are generated from it by `scripts/render_docs.py` | Editing a number by hand is reverted by regeneration; CI diffs the generated blocks |
| H3 | MUST | `docs/VALIDATION-RESULTS.md` describes one run, not a merge of two | The 108/135 and 78/93 contradictions are gone; the document names the commit and date of the run it describes |
| H4 | SHOULD | `README.md`'s finding-field list matches `schemas/finding.schema.json` exactly, generated from the schema | `test_docs_contract.py` compares the two lists |
| H5 | SHOULD | `docs/RESEARCH.md` keeps its `RESEARCH-SOURCES.json` digests, and a check fails when a cited source has no digest entry | Small test over the two files |
| H6 | COULD | A `docs/ARCHITECTURE.md` with the stage/data-flow diagram generated from the registry, replacing three hand-drawn trees | Diagram regenerated by `render_docs.py`; `README.md` and `docs/` link to it instead of duplicating it |

**Specification notes.** The failure mode here is not laziness; it is that the same fact (how many
findings does the reference corpus yield?) lives in four places with no mechanism to keep them equal.
H2's generator is a small script — it reads `measurements.json` and replaces marked blocks — and its
value is that it makes drift *impossible* rather than *unlikely*.

### WS-I — Self-assurance: adversarial corpus and redaction hardening (M2)

| ID | Priority | Requirement | Acceptance criterion |
| - | - | - | - |
| I1 | MUST | A prompt-injection corpus in `tests/fixtures/injection-app/` containing instructions in comments, strings, config files, filenames, issue templates and lockfile metadata | The end-to-end run reports each attempt as a prompt-injection observation, quoted as data, and no finding count changes because of it |
| I2 | MUST | A test asserts that no repository-derived string reaches a shell, an `eval`, a template with autoescape off, or a network call | Static test over `scripts/` plus a runtime assertion in the redaction path |
| I3 | SHOULD | Redaction fuzzing: generated credential-shaped strings in 20 formats, asserting the marker names the shape and the raw value never appears in any artefact | Property test over 1 000 generated strings; zero survivors across all artefacts |
| I4 | SHOULD | A leak corpus: a repository whose `.env` must never appear in output, checked by the verifier with `--secrets-file` | `validate_reports.py` exits 1 when a fixture leak is injected deliberately, proving the guard works |
| I5 | COULD | Record prompt-injection observations in their own machine-readable file (`injection-observations.json`) so a SOC can consume them | Written on every run; empty array when none found, never absent |

**Specification notes.** I2 is deliberately static: the guarantee "repository content is data" is
easier to prove by forbidding the dangerous call sites than by auditing every path. The skill already
templates with Jinja autoescape and renders HTML through escaped interpolation; the test makes that a
property instead of a habit.

### WS-J — Release engineering (M1 onward)

| ID | Priority | Requirement | Acceptance criterion |
| - | - | - | - |
| J1 | MUST | CI workflow runs the suite on Python 3.8, 3.10, 3.12 and 3.13, offline, on every push | Four green jobs; a 3.8-only syntax regression fails the matrix |
| J2 | MUST | CI runs ruff with a pinned config and version (the repository already carries a `.ruff_cache/`, so the tool is in use informally) | Lint failures block merge; config committed |
| J3 | MUST | A version is declared once (`metadata.version`) and appears in the manifest, `scope.json` and the report header | Bumping the version changes all three; a test asserts they agree |
| J4 | SHOULD | `CHANGELOG.md` with a keep-a-changelog structure, plus a release checklist (regenerate measurements, re-run corpora, update the maximum-severity claim) | Release cut from the checklist on a clean tree |
| J5 | SHOULD | The doc-parity, contract and description tests run on every push, not only locally | CI job named explicitly in the workflow |
| J6 | COULD | A packaging step builds a distributable skill archive (only `SKILL.md`, `references/`, `scripts/`, `schemas/`, `templates/`) excluding `docs/`, `tests/`, `prds/` and `.research/` | Archive contents asserted; install from the archive passes the verifier on a fixture |

**Specification notes.** `prds/` is development material, like `docs/`. It belongs in the repository
and must not be shipped in the skill archive (J6), because it would spend the agent's context budget
on delivery history.

---

## 8. Data model changes (schema v2)

`schema_version` becomes `2.0`. The 20 required fields keep their meaning; `validation_status` and
severity vocabularies are unchanged, so existing datasets remain readable. Additions:

| Field | Type | Rule |
| - | - | - |
| `disposition` | enum `review-required` / `optional-hardening` / `no-action-suppressed` | Derived, deterministic, and the directory a finding is filed in. Must equal the bucket |
| `fingerprint` | string | Stable identity across runs; the baseline and SARIF hinges. One definition, documented |
| `first_seen` | object `{run_id, commit, date}` | Set once, preserved by the baseline; never rewritten by a later run |
| `baseline_state` | enum `new` / `unchanged` / `fixed` / `absent` | Only present when a baseline was supplied; absent otherwise (not `null`) |
| `suppression` | object `{reason, owner, expires, ticket, source}` | `source ∈ heuristic / register / code-marker`; `expires` is an ISO date or null |
| `controls_checked` | array of `{control, location, outcome}` | Replaces the free-text `validation` string as the authoritative record of the control search. `validation` stays for prose |
| `owasp` | object `{top10_2025, api_2023, asvs}` | Unchanged shape; documented consistently in all four places (README currently calls it `owasp_reference`) |
| `sarif_rule_id` | string | Stable rule id for SARIF `reportingDescriptor.id`; defaults to the analyzer rule id |

Schema-level requirements:

* Every new field is optional in v2.0 (so v1 datasets still validate) but required in
  `findings-index.json` where it is meaningful.
* `additionalProperties` on the finding object stays `true` (forward compatibility), while the index
  and the per-finding file use a closed schema so a consumer can rely on their shape.
* A `schema_version` mismatch between dataset and renderer is a hard error (exit 2), not a warning.

---

## 9. CLI surface changes

| Script | New or changed flag | Milestone |
| - | - | - |
| `run_audit.py` (new) | `--root`, `--out`, `--exclude`, `--allow-network`, `--formats`, `--jobs`, `--resume`, `--from`, `--only`, `--changed-since`, `--baseline`, `--write-baseline`, `--suppressions`, `--fail-on-severity`, `--budget-seconds`, `--dry-run` | M1, extended M2/M4 |
| `scope_init.py` (new) | `--root`, `--exclude`, `--out` | M1 |
| `score_findings.py` (new) | `--dataset`, `--out`, `--no-score`, `--only-unscored` | M1 |
| `generate_sarif.py` (new) | `--dataset`, `--out`, `--tool-name`, `--baseline`, `--include-suppressed` | M2 |
| `generate_reports.py` | `--baseline`, `--suppressions`, `--write-baseline`, `--sarif` (convenience passthrough) | M2 |
| `generate_json.py` | `--legacy-tickets`, `--buckets` (default on), `--disposition-report` | M0 |
| `validate_reports.py` | `--fail-on-severity`, `--write-verdict`, `--buckets` check, `--sarif` validation | M0/M2 |
| `validate_findings.py` | `--suppressions`, `--score` (default: call the scorer), `--profile` (timing summary) | M1/M2 |
| every stage | `--print-contract` (from the registry), uniform `--quiet`/`--indent` | M1 |

Rule: no flag is added without a line in `README.md` §7, a `--help` string, and a test. The README's
configuration table is currently the best part of the documentation; it must not decay.

---

## 10. Non-functional requirements

| ID | Requirement | Target |
| - | - | - |
| N1 | Determinism | Two runs on the same snapshot produce identical datasets and per-finding files; only `meta` run identity differs |
| N2 | Dependency floor | Stdlib only; `jsonschema`, `tomllib` remain optional-with-recorded-fallback |
| N3 | Offline by default | No network unless `--allow-network`; asserted by a test that blocks sockets |
| N4 | Read-only | No write outside `--out`/`--outdir`, asserted by a filesystem-watcher test over the audited root |
| N5 | Runtime | ≤ 60 s for 1 000 files, ≤ 10 min for 10 000 with `--jobs`, both measured by F1 |
| N6 | Activation cost | `SKILL.md` ≤ 220 lines, ≤ 6 000 tokens |
| N7 | Failure clarity | Every non-zero exit names the stage, the artefact and the reason; no stack trace as the only output |
| N8 | Portability | Python 3.8+ grammar, tested on the four matrix versions; no Linux-only syscalls outside optional probes |
| N9 | Locale | UTF-8 in, UTF-8 out, `ensure_ascii=False`; no reliance on the ambient locale |

---

## 11. Release acceptance criteria

A milestone ships only when every box is ticked; the release as a whole ships when all four are done.

**M0 — Truth**

- [ ] `findings/<bucket>/VULN-NNN.json` written and validated; wrong bucket fails the verifier
- [ ] Three subdirectories exist on every run, including a corpus with zero findings
- [ ] `scripts/artefacts.py` is the only place artefact names are written; generators import it
- [ ] `tests/test_docs_contract.py` fails on each of: a renamed artefact, a deleted stage row, a
      removed schema field
- [ ] Appendix B's 19 rows closed; the register is machine-checked
- [ ] `verification.json` behaviour documented and tested in both modes
- [ ] `README.md` and `docs/VALIDATION-RESULTS.md` agree with the code on every artefact name
- [ ] Suite green on 3.8 and 3.13 under the new CI workflow

**M1 — One command**

- [ ] `run_audit.py` completes both corpora in one invocation and writes `stage-manifest.json`
- [ ] `--resume` produces byte-identical artefacts after a mid-run kill
- [ ] `scope.json` written by `scope_init.py`, copied into the report header
- [ ] `score_findings.py` owns scoring; `validate_findings.py` no longer writes CVSS fields
- [ ] `raw_findings.json` and `findings.json` no longer collide
- [ ] Failure matrix in §7 (WS-B) implemented and tested
- [ ] `--jobs` deterministic and faster (measured)

**M2 — CI-native**

- [ ] SARIF 2.1.0 validates and ingests; severity mapping table tested
- [ ] Baseline write/diff/classify tested, including line-shift and rename identity
- [ ] Suppression register applies, expires and reports stale entries
- [ ] `--fail-on-severity` gate exits 3 with artefacts retained
- [ ] Injection corpus and prompt-injection assertions in the end-to-end test
- [ ] Leak corpus proves the secret guard fires

**M3 — Depth**

- [ ] Detection reference has full tables for six more languages and eight infrastructure families
- [ ] ≥ 18 new rules (six each for Terraform, Kubernetes, Dockerfile) with both-direction fixtures
- [ ] `test_rule_fixture_parity.py` fails on an unpaired rule
- [ ] Self-audit noise measured and recorded

**M4 — Measurement**

- [ ] Blind corpus committed with licence and adjudication notes
- [ ] Scoreboard prints precision/recall; recorded in `docs/VALIDATION-RESULTS.md` with the command
- [ ] Docs numbers generated from `measurements.json`; hand edits reverted by regeneration
- [ ] Timing harness reports 100/1 000/10 000 file numbers
- [ ] `CHANGELOG.md` and version discipline in place

---

## 12. Roadmap, sequencing and sizing

| Milestone | Scope | Depends on | Estimate (engineer-days) | Shippable value |
| - | - | - | - | - |
| **M0 Truth** | WS-A, WS-H (corrections), WS-J (CI) | — | 4–6 | The documentation stops lying; the layout matches the standard |
| **M1 One command** | WS-B, WS-F (harness), WS-J (version) | M0 | 6–8 | One command, resumable, with a real scope record |
| **M2 CI-native** | WS-C, WS-I, WS-G (partial) | M1 | 7–9 | A gate, a baseline and SARIF |
| **M3 Depth** | WS-D, WS-G | M0 | 8–10 | Guidance where the surface is widest |
| **M4 Measurement** | WS-E, WS-F (incremental), WS-H (generation) | M2, M3 | 5–7 | Precision and recall instead of assertion |

Total 30–40 engineer-days. Sequencing rationale: M0 is first because every later milestone writes
artefacts and would otherwise need updating twice. M1 precedes M2 because baseline and gating need one
command and one dataset identity. M3 is parallelisable with M2 — different files, no shared state,
which is why WS-D is the one workstream an outside contributor can own end to end.

---

## 13. Risks and mitigations

| # | Risk | Likelihood | Impact | Mitigation |
| - | - | - | - | - |
| 1 | The bucketed layout breaks a consumer that scripted `tickets/` | Medium | Medium | Two-release deprecation (A4); index is the documented pointer; a warning names the removal version |
| 2 | Doc-parity tests become brittle and block unrelated changes | Medium | Medium | Parse the minimum structure (fenced blocks and tables), allow prose drift, and assert on the registry rather than on exact wording |
| 3 | SARIF semantics mismatch (severity, fingerprints, suppressions) | Medium | High | Validate against the official schema in CI; ingest one fixture report into a real code-scanning endpoint before release |
| 4 | The blind corpus is not actually blind (author sees it while tuning) | Medium | High | Adjudication by a second person; scoreboard run recorded before and after each rule change; undecidable category prevents forced choices |
| 5 | Splitting the score stage changes verdicts on existing datasets | Medium | Medium | Golden-dataset test: the 135-finding reference output must be byte-identical after the split, except field ordering |
| 6 | Bucket assignment is ambiguous and the argument recurs | High | Low | Precedence table in the standard plus four table-driven edge-case tests (documented in WS-A notes) |
| 7 | Scope creep towards DAST or autofix | High | High | Non-goals in §4.2 are contractual; a change that violates one needs a new PRD |
| 8 | Performance work lands without measurement | Medium | Medium | F1's harness is a MUST in M1, before any optimisation |
| 9 | The new orchestration layer duplicates logic and drifts | Medium | High | `run_audit.py` may only call existing stage entry points; a test asserts it contains no analysis logic |
| 10 | Token budget grows until activation is expensive | Medium | Medium | GO7 enforced in CI; depth pushed to `references/` with per-stage triggers |

---

## 14. Open questions and decisions required

| # | Question | Recommendation | Decided by |
| - | - | - | - |
| 1 | Is a validated Medium with priority P3 "optional hardening" or "review required"? | Hardening, because priority is the urgency signal and severity is the damage signal. Documented and tested | product owner |
| 2 | Does `no-action-suppressed/` include `needs_review` findings a human has declined? | No. `needs_review` is "we could not prove it"; declining is a suppression and must be recorded as one, with an owner | security lead |
| 3 | Should `prds/` and `docs/` ship in the skill archive? | No. Repository-only, excluded by J6 | maintainer |
| 4 | Is Python 3.8 still a supported floor (EOL October 2024)? | Keep the grammar-compatible floor, test on 3.8 in CI, and state that 3.8 is a floor rather than a promise — or raise to 3.9 and say so. Decide once, in `metadata` | maintainer |
| 5 | Does v2 change any severity band or CVSS version? | No. Bands and CVSS 4.0 are stable; changing them would invalidate every baseline | product owner |
| 6 | Is a SARIF `rules` catalogue published as its own artefact (`rules.json`)? | Yes — `--list-rules` already produces it; publishing it makes rule-level suppression possible in code scanning | maintainer |
| 7 | Should the baseline live in the audited repository (committed) or in the output directory? | Committed by the team that owns the code, produced by the tool. The tool never writes into the audited tree (N4), so it prints the path to commit | security lead |
| 8 | What is the expiry policy when a suppression has no `expires`? | Warn once, then treat as expired after 90 days. Silence is the failure mode we are trying to remove | security lead |

---

## 15. Appendices

### Appendix A — Reproducing the baseline

```bash
cd vulnerabilities-scan
python3 -V                                          # 3.13.13
python3 -m pytest tests -q                          # 316 passed, ~60 s
python3 scripts/builtin_analyzers.py --list-rules \  # {"rules": 97, "count": 97}
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["rules"])'
git ls-files | wc -l                                # 126
git ls-files tests/fixtures | wc -l                 # 74
ls scripts/*.py | wc -l                             # 17
wc -l tests/test_*.py | tail -1                     # 4456 total

# self-audit cost
python3 scripts/repository_inventory.py --root . \
  --exclude '.research/**' --exclude '.scratch/**' --out /tmp/inv.json   # 0.19 s, 126 files
python3 scripts/builtin_analyzers.py --root . --inventory /tmp/inv.json \
  --out /tmp/analysis.json --quiet                                       # 4.51 s, 176 findings
```

### Appendix B — Divergence register (19 rows, closed by A6)

| # | Document says | Code does | Evidence |
| - | - | - | - |
| 1 | findings filed under `findings/<bucket>/` | flat `tickets/` | `references/reporting-standard.md` §2 vs `scripts/generate_json.py:74,368` |
| 2 | stage 0 writes `scope.json` | nothing writes it | `SKILL.md:44,63` vs `grep -rn "scope.json" scripts/` (no hits) |
| 3 | stage 6 scores findings | no scoring module; scoring inside validation | `SKILL.md:50` vs `ls scripts/*.py` |
| 4 | stage 3 writes `raw_findings.json` | `analysis.json` (builtin), `findings.json` (orchestrator) | `SKILL.md:47` vs `README.md:160`, `scripts/scanner_orchestrator.py:1667` |
| 5 | stage 4 writes `findings.json` | `deduped.json` | `SKILL.md:48` vs `README.md:161` |
| 6 | stage 7 writes `report.md`/`report.html`/`report.pdf` | `SECURITY-AUDIT-REPORT.*` | `SKILL.md:51` vs `scripts/report_model.py:1000-1004` |
| 7 | stage 8 writes `verification.json` | verdict printed to stdout | `SKILL.md:52`, `README.md:196`, `scripts/report_model.py:1009` vs `docs/VALIDATION-RESULTS.md:293-296` |
| 8 | attack surface file is `attack_surface.json` | `attack-surface.json` | `SKILL.md:46` vs `README.md:157` |
| 9 | raw scanner output under `raw-scans/` | `raw/` | `README.md:180` vs `scripts/scanner_orchestrator.py:1628` |
| 10 | `findings.json` is the validated dataset | the orchestrator writes its unvalidated merge there too | `README.md:194` vs `scripts/scanner_orchestrator.py:1667-1669` |
| 11 | nine stages (0–8) | "all eight stages" in prose | `SKILL.md:42-52` vs `README.md:363`, `docs/VALIDATION-RESULTS.md:6,24` |
| 12 | 97 rules | 71 rules | `README.md:223` vs `docs/VALIDATION-RESULTS.md:68,127` |
| 13 | 135 findings / 93 validated / 39 `needs_review` / 3 suppressed | same document also reports 108 / 78 / 28 / 2 | `docs/VALIDATION-RESULTS.md:141,204,211` vs `:216-217,222-227,298` |
| 14 | severity split 17/37/45/9 | 18/43/62/12 | `README.md:368` vs `docs/VALIDATION-RESULTS.md:206-209` |
| 15 | fixtures are 34 files, or 24 files, per corpus | 36 tracked files per corpus | `docs/VALIDATION-RESULTS.md:75,125,247` vs `git ls-files tests/fixtures` |
| 16 | "the six defects above" | the table has ten rows | `docs/VALIDATION-RESULTS.md:379` vs `:307-318` |
| 17 | findings carry `owasp_reference`, `cvss_version`, root cause, preconditions, `remediation` | schema requires `owasp`; the other keys do not exist | `README.md:208-213` vs `schemas/finding.schema.json` `$defs.finding.required` |
| 18 | "the seven languages in scope" | eleven language sections | `references/language-security-guides.md:3-4` |
| 19 | frontmatter has name/description/compatibility/license | spec also supports `metadata.version` and `allowed-tools`, unused | `SKILL.md:1-6` vs `.research/agentskills-spec.md:32-35` |

### Appendix C — Proposed layout after v2

```
security-audit/
├── scope.json                    stage 0 — target, commit, exclusions, read-only confirmation
├── stage-manifest.json           stages run, inputs, outputs, status, digests
├── inventory.json                stage 1
├── technologies.json             stage 2
├── attack-surface.json           stage 2
├── raw_findings.json             stage 3 — detections before validation (was: findings.json collision)
├── deduped.json                  stage 4
├── findings.json                 stage 5 — validated dataset, the single source of truth
├── transcript.json               stage 5 — redactions, suppressions, statuses
├── verification.json             stage 8 — written with --write-verdict, stdout otherwise
├── findings-baseline.json        fingerprint baseline (C5)
├── suppressions.json             register (C6, input)
├── injection-observations.json   prompt-injection records (I5)
└── reports/
    ├── SECURITY-AUDIT-REPORT.{md,html,pdf,json}
    ├── SECURITY-AUDIT-REPORT.sarif
    ├── findings-index.json
    ├── report-manifest.json
    ├── rules.json
    └── findings/
        ├── review-required/VULN-004.json
        ├── optional-hardening/VULN-019.json
        └── no-action-suppressed/VULN-007.json
```

### Appendix D — Glossary

| Term | Meaning in this skill |
| - | - |
| Candidate | A pattern match. Never reported as a finding |
| Finding | A located weakness with evidence and a stated missing or bypassed control |
| Confirmed | A finding whose attacker-reachable path was established from the snapshot |
| `needs_review` | A finding that could not be proven from source alone; reported, not ticketable |
| Suppressed | A finding recorded and deliberately closed, with a reason and (in v2) an owner and expiry |
| Disposition | The bucket a finding is filed in: review-required, optional-hardening, no-action-suppressed |
| Dataset | `findings.json` — the validated authority every view derives from |
| View | Any render: Markdown, HTML, PDF, SARIF, per-finding JSON, index |
| Fingerprint | Stable identity across runs; the hinge for baseline, suppression and SARIF |
| Baseline | A previous run's fingerprints, used to classify new/unchanged/fixed |
| Gate | A CI decision derived from severity, expressed as an exit code |
| Coverage limitation | A recorded reason a claim is narrower than it looks |

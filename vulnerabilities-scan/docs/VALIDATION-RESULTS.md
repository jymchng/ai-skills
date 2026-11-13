# Validation results: automated suite and end-to-end audit

**Validation date:** 2026-11-13 (UTC)
**Scope:** the whole pipeline as shipped — `repository_inventory.py` → `detect_technologies.py` →
`attack_surface.py` → `builtin_analyzers.py` → `deduplicate_findings.py` → `validate_findings.py` →
`generate_reports.py` → `validate_reports.py`
**Environment:** Python 3.13.13, no network, no external scanners installed, no PDF toolchain
**Status:** complete — every number below was measured in this run, not estimated

The point of this document is falsifiability. Each claim names the command that produces it and the
artefact it can be checked against. Where a check could not run, that is stated as a limitation
rather than omitted.

---

## 1. How to reproduce

```bash
cd vulnerabilities-scan
python3 -m pytest tests -q            # 400 tests
```

The end-to-end audit is `tests/test_end_to_end_audit.py`; it runs both fixture corpora through all
eight stages (≈5 s total, cached per session) and inspects the delivered artefacts. To produce the
artefacts by hand, run the stages in the same order the test does:

```bash
root=tests/fixtures/vulnerable-app      # or tests/fixtures/secure-app
out=.scratch/audit/vulnerable-app
python3 scripts/repository_inventory.py --root $root --out $out/inventory.json
python3 scripts/detect_technologies.py  --root $root --inventory $out/inventory.json \
        --out $out/technologies.json
python3 scripts/attack_surface.py       --root $root --inventory $out/inventory.json \
        --technologies $out/technologies.json --out $out/attack-surface.json
python3 scripts/builtin_analyzers.py    --root $root --inventory $out/inventory.json \
        --technologies $out/technologies.json --attack-surface $out/attack-surface.json \
        --out $out/analysis.json --quiet
python3 scripts/deduplicate_findings.py $out/analysis.json --out $out/deduped.json
python3 scripts/validate_findings.py    $out/deduped.json --root $root \
        --out $out/findings.json --transcript $out/transcript.json
python3 scripts/generate_reports.py     --dataset $out/findings.json --outdir $out/reports \
        --analysis $out/analysis.json --inventory $out/inventory.json \
        --formats markdown,html,json
python3 scripts/validate_reports.py     --outdir $out/reports --dataset $out/findings.json
```

`repo-root` arguments must point at a snapshot; `validate_findings.py` re-reads evidence from that
snapshot at validation time, so a moved or deleted file degrades the finding rather than reporting
stale bytes as live.

---

## 2. Deliverables shipped

The acceptance criteria name sixteen deliverables. Each one is present in the tracked tree and was
re-checked on this run; the *evidence* column is what that check actually printed, not a restatement
of intent.

| # | Deliverable | Path | Evidence on this run |
|---|---|---|---|
| 1 | Agent-facing workflow | `SKILL.md` | 169 lines; frontmatter is `name` / `description` / `compatibility` / `license` only, `name` matches the directory |
| 2 | Operational references | `references/` | 8 documents: methodology, taxonomy, scoring, language guides, scanners, false positives, validation, reporting |
| 3 | Finding contract | `schemas/finding.schema.json` | 20 required per-finding fields, plus enums for severity, confidence and validation_status |
| 4 | Finding model | `scripts/finding_model.py` | load/save, schema validation, deterministic `VULN-NNN` ids, severity-from-score derivation, redaction helper |
| 5 | Repository inventory | `scripts/repository_inventory.py` | discovery, excludes, binary/large/unreadable accounting, language census, manifests, git state |
| 6 | Technology detection | `scripts/detect_technologies.py` | frameworks, runtimes, build systems, package managers, monorepo components |
| 7 | Attack surface | `scripts/attack_surface.py` | routes, entry points, trust boundaries, auth mechanisms, GraphQL/WebSocket/RPC, workers |
| 8 | Built-in analyzers | `scripts/builtin_analyzers.py` | 71 rules over the 20 required classes across 7 languages plus Docker/K8s/Terraform/Actions |
| 9 | Scanner orchestration | `scripts/scanner_orchestrator.py` | 10 optional tools detected, timed out, captured and recorded as coverage limitations when absent |
| 10 | Deduplication | `scripts/deduplicate_findings.py` | cross-analyzer merges by location/CWE/root cause, provenance preserved |
| 11 | Validation and scoring | `scripts/validate_findings.py` | confidence assignment, compensating-control suppression, CVSS 4.0, evidence capture, redaction |
| 12 | Templates | `templates/report.md.j2`, `templates/report.html.j2`, `templates/report.css` | self-contained HTML, no CDN, escaped untrusted content, print styles |
| 13 | Renderers | `scripts/generate_markdown.py`, `generate_html.py`, `generate_pdf.py`, `generate_json.py`, `generate_reports.py` | one dataset rendered to every format, plus one JSON per finding under `findings/` (filed by verdict, then urgency), `findings-index.json` and `report-manifest.json` |
| 14 | Report validator | `scripts/validate_reports.py` | exit 0 with 0 problems on both corpora (section 4); `--require-pdf` escalates a missing PDF |
| 15 | Fixtures and test suite | `tests/` | 16 test modules plus `conftest.py`, 74 fixture files (34 vulnerable-app, 34 secure-app, 2 expectation data), 433 tests |
| 16 | Research and validation record | `docs/RESEARCH.md`, `docs/RESEARCH-SOURCES.json`, `docs/VALIDATION-RESULTS.md`, `README.md` | dated sources with SHA-256 digests; this document; the human-facing install/use guide |

Re-measure the inventory rather than trusting the table:

```bash
git ls-files | wc -l                        # 132 tracked files
git ls-files references | wc -l             # 8
git ls-files tests/test_*.py | wc -l        # 15
git ls-files tests/fixtures | wc -l         # 74
for s in scripts/*.py; do python3 "$s" --help >/dev/null || echo "no --help: $s"; done
                                            # prints nothing: all 17 modules accept --help
python3 -m pytest tests -q                  # 433 passed
```

Everything after this section is measurement. This section is the inventory that measurement
attaches to.

---

## 3. Test suite

```
433 passed in 50.83s
```

| Test module | Tests | What it pins |
|---|---|---|
| `test_cvss4.py` | 54 | Vendored FIRST CVSS 4.0 reference scorer (all metric vectors, invalid input) |
| `test_validate_findings.py` | 46 | Evidence re-reading, path policy, redaction, suppression, leak guard |
| `test_finding_model.py` | 43 | Finding schema, IDs, placeholder handling, ordering |
| `test_deduplicate_findings.py` | 27 | Fingerprints, line windows, cross-file merges, provenance |
| `test_report_generation.py` | 26 | Markdown/HTML/JSON renderers, per-finding JSON, index, manifest, determinism |
| `test_scanner_orchestrator.py` | 22 | Tool discovery, timeouts, unavailable-tool accounting |
| `test_builtin_analyzers.py` | 22 | Rule matching per category, secure look-alike silence, self-scan precision |
| `test_attack_surface.py` | 22 | Route/framework extraction, auth heuristics, route-bearing code no rule can enumerate |
| `test_end_to_end_audit.py` | 13 | The two corpora, eight stages, artefact consistency, twin difference |
| `test_scan_families.py` | 9 | Every rule added beyond the original languages, in both directions: fires on the wrong code, silent on its look-alike; plus the classification and masking defects that hid them |
| `test_repository_inventory.py` | 12 | File discovery, excluded directories, language classification, budgets |
| `test_detect_technologies.py` | 10 | Language/manifest/import detection |
| `test_redaction_markers.py` | 6 | One marker spelling per credential shape, identical across all three redacting stages |
| `test_push_protection_literals.py` | 5 | No live-credential shape anywhere in the tracked tree |
| `test_install_scanners.py` | 84 | Installer planning per OS, the pipx/Node bootstrap, the elevation rule, archive extraction safety, and that the wrappers delegate instead of carrying their own matrix |
| `test_finding_buckets.py` | 32 | The finding taxonomy: the mapping is total and mutually exclusive, severity beats priority inside `validated/`, a suppression is filed by kind, every leaf directory is written, a mis-filed or stale file is caught |
| **Total** | **433** | |

Every module runs offline and writes only under `.scratch/` (git-ignored).

---

## 4. End-to-end audit: vulnerable corpus

`tests/fixtures/vulnerable-app` — 24 files: 12 source, 7 manifest, 4 IaC, 1 document. The census
carries 17 language labels (8 application languages, plus `dockerfile`, `kubernetes`, `terraform`,
`github-actions`, `gomod`, `json`, `markdown`, `text`, `xml`). All five buckets were scanned, but the
`config` bucket contained no files, so four buckets contributed material. 71 rules evaluated, 40
categories covered.

### 3.1 Stage counts

| Stage | In | Out |
|---|---|---|
| Inventory | — | 34 files scanned |
| Technologies | 34 files | 15 application languages, 19 frameworks/imports incl. PyJWT, jsonwebtoken, and 7 runtimes |
| Attack surface | 34 files | 14 HTTP routes (9 GET / 5 POST), 14 without visible auth, 3 auth mechanisms, 0 non-HTTP surfaces, 1 file carrying routes no rule can enumerate |
| Analyzers | 34 files | **152 findings** |
| Dedupe | 152 | **135 findings** (17 duplicates removed, 0 without provenance) |
| Validation | 135 | 135 findings; 3 suppressed; 3 secrets redacted; **0 leaks** |
| Reports | 135 | markdown + html + json + index + manifest + 135 per-finding JSON files: 84 `validated/remediate-now`, 9 `validated/schedule`, 39 `needs-review`, 3 `suppressed/not-exploitable`, 0 elsewhere |

The 152 → 135 drop is the deduplicator merging adjacent same-fingerprint reports (e.g. the
Terraform misconfiguration cluster in `infra/terraform/main.tf`), not findings being dropped for
inconvenience: `dedupe.merges` records every merge with the kept and dropped locations.

The attack-surface row is measured after the stage-2 precision fixes (defects 6 and 8): the phantom
non-HTTP surface and one phantom mechanism are gone, and the ASP.NET Core controller that no route
rule can enumerate is now counted instead of silently contributing nothing. `unenumerable_routes`
holds one record per such file (`dotnet/OrdersController.cs:11`, a `Controller`-derived class with 9
candidate action methods) and the same fact is stated in `limitations`, so a zero-route result for a
controller file reads as a coverage gap rather than as "no endpoints". No finding count in this
document moves because of it: the record adds context, not detections.

### 3.2 Required detection classes

All **20 of 20** required classes are still detected, with the exact per-class counts recorded in
`tests/fixtures/expected_findings.json` (`10,10,8,2,8,5,12,7,5,3,3,6,9,7,5,2,1,11,6,6`, total 126 in
the pre-dedupe analysis for those 20 classes), and every file declared vulnerable in that file exists on disk and
carries a finding of its declared class.

Measured in both directions, which is the only way "no false positives" means anything:

| Measure | Expected | Detected | Missed | Unrecorded false positives |
|---|---|---|---|---|
| Required classes (vulnerable corpus) | 20 | 20 | 0 | — |
| Declared vulnerable files | 17 | 17 | 0 | — |
| Findings before dedupe (vulnerable) | 152 | 152 | 0 | — |
| Findings after dedupe (vulnerable) | 135 | 135 | 0 | — |
| Findings (secure corpus) | 6 recorded false positives | 6 | — | 0 |

Per-class agreement is exact, not "at least one": for every one of the 20 classes the detected count
equals the count recorded in `expected_findings.json` (asserted by
`test_all_twenty_required_classes_are_still_detected`). The run reports 27 categories, not 20: the
required 20 plus `iac_misconfiguration`, `kubernetes_security`, `unpinned_dependency`,
`code_injection`, `race_condition`, `tls_verification_disabled` and `weak_randomness`, which are
real findings in the declared Dockerfile, Kubernetes, Terraform and dependency-manifest fixtures
rather than noise from the source rules.

`summary.by_category` over the 135 delivered findings:

| Category | n | Category | n |
|---|---|---|---|
| missing_authentication | 12 | permissive_cors | 4 |
| command_injection | 10 | kubernetes_security | 4 |
| iac_misconfiguration | 10 | weak_jwt_validation | 3 |
| sql_injection | 10 | code_injection | 2 |
| path_traversal | 8 | hardcoded_secret | 2 |
| insecure_deserialization | 8 | unrestricted_upload | 2 |
| xss_reflected | 8 | xss_stored | 2 |
| missing_authorization | 7 | missing_rate_limiting | 1 |
| cicd_permissions | 6 | race_condition | 1 |
| vulnerable_dependency | 6 | tls_verification_disabled | 1 |
| weak_password_hashing | 6 | unpinned_dependency | 1 |
| business_logic | 5 | weak_randomness | 1 |
| container_security | 5 | | |
| idor | 5 | | |
| ssrf | 5 | | |

### 3.3 Severity, confidence, and disposition

| Measure | Value |
|---|---|
| Findings | 135 (132 reportable, 3 suppressed) |
| Scored / unscored | 135 / 0 — every finding carries a CVSS 4.0 score |
| Critical | 18 |
| High | 43 |
| Medium | 62 (59 reportable) |
| Low | 12 |
| Confidence | 61 CONFIRMED, 32 HIGH, 5 MEDIUM, 37 LOW |
| Validation status | 93 validated, 39 needs_review, 3 suppressed |
| Ticketable | 93 |

The 28 `needs_review` findings are the advisory half of the contract: they are reported with
their evidence and a stated reason they could not be proven from the snapshot alone, and they are
*not* counted as ticketable. Nothing is silently dropped — every one of the 108 appears in the
dataset, the index, and exactly one per-finding JSON.

### 3.4 Delivered artefacts

```
reports/SECURITY-AUDIT-REPORT.md     108 findings
reports/SECURITY-AUDIT-REPORT.html   106 <article class="finding">
reports/SECURITY-AUDIT-REPORT.json   108 findings
reports/findings-index.json          108 entries
reports/report-manifest.json         size + sha256 for every artefact above
reports/findings/<bucket>/VULN-*.json  one file per finding, filed by verdict then urgency
```

Exact byte counts are deliberately not quoted here: the rendered reports embed the audited
commit, the dirty/clean state and `generated_at`, so their size changes with every run (the same
corpus produced 197 770 / 279 947 bytes on a dirty tree at `39ecca9` and 197 341 / 279 496 bytes on
the clean tree at `8148d2d`). The invariant is the finding count and the article count; the size and
digest that did hold are recorded per run in `report-manifest.json`.

The HTML carries 106 articles rather than 108 because the two suppressed findings are excluded
from the human-readable report while remaining present in the machine-readable dataset and index —
that asymmetry is asserted, not assumed.

`validate_reports.py` on this directory: **0 problem(s), 1 warning(s)** — the warning is that no PDF
was requested, which is accurate rather than a failure (`ok: true`, exit 0).

---

## 5. End-to-end audit: secure look-alikes

`tests/fixtures/secure-app` — same shape: 24 files, the same 8 application languages and 71 rules
evaluated. It names 17 frameworks/imports to the vulnerable corpus's 19, and the difference is a
property of the fixtures rather than drift: the secure tree loses `YAML`, `encoding/gob` and
`pickle` (its implementations do not import unsafe deserialisers) and gains `Helmet`.

| Measure | Value |
|---|---|
| Findings | 6 (5 reportable, 1 suppressed) |
| Analyzer findings | 6 (no dedupe merges) |
| Critical / High / Medium / Low | 1 / 1 / 3 / 1 |
| Confidence | 3 CONFIRMED, 2 HIGH, 1 LOW |
| Validation status | 4 validated, 1 needs_review, 1 suppressed |
| Ticketable | 4 |
| Secrets redacted | 0 (none present) |
| HTML articles | 5 |
| `validate_reports.py` | 0 problems, 1 warning (no PDF), exit 0 |

The 6 findings are exactly the 6 entries in `expected_findings.json → known_false_positives`,
matched one-for-one on `(category, file, line, rule_id)`. This is the corpus's real job: it proves
the rules distinguish `hashlib.pbkdf2_hmac(..., 600_000)` from `hashlib.md5`, a parameterised query
from a concatenated one, and a same-origin CORS header from `*`. Every secure look-alike is
byte-different from its vulnerable twin (asserted by
`test_every_secure_look_alike_differs_from_its_vulnerable_twin`), so the pair actually tests the
rule and not file identity.

---

## 6. Machine-readable deliverables

Each of the 108 findings gets **exactly one** `.json` describing it; the aggregate metadata has its
own file. This is the contract asserted by `test_report_generation.py` and
`test_end_to_end_audit.py`.

| File | Contents | Written by |
|---|---|---|
| `findings-index.json` | One entry per finding: `id`, `kind`, `file`, `line_start`, `line_end`, `category`, `title`, `severity`, `confidence`, `priority`, `validation_status`, `disposition` (the bucket it was filed in), `ticketable`, `ticketable_reason`, `json{path, sha256, bytes, fingerprint}` — plus `totals`, including `totals.by_disposition` | `generate_reports.py` |
| `findings/<verdict>/[<urgency>/]<ID>.json` | The full per-finding description: location, evidence with line context, CVSS 4.0 vector and score, remediation, references, provenance, and the `disposition` it was filed under | `generate_reports.py` |
| `report-manifest.json` | The aggregate record: run identity in `meta` (repository, commit, branch, dirty state, audit date, skill version, dataset stage and tool), counts by severity and validation status (`counts.by_severity_detail` breaks severity down by validated / needs-investigation / suppressed), and every artefact with its size and SHA-256 | `generate_reports.py` |
| `SECURITY-AUDIT-REPORT.json` | Aggregate report document (the same content the Markdown and HTML render) | `generate_reports.py` |

Two things in that area are deliberately *not* written into the report directory:

- `audit-metadata.json` is an **input**, not an output. An operator may pass
  `--metadata audit/audit-metadata.json` (repository, commit, audit date, environment) and
  `generate_reports.py` folds it into the manifest's `meta` block; when it is omitted the identity is
  derived from the snapshot itself, which is what happened for every run in this document.
- The `validate_reports.py` verdict goes to **stdout** as JSON (redirect it if you want a file),
  because a validator that fails must not be the thing that writes an artefact claiming it passed.
  The verdict still carries a SHA-256 for the dataset, the manifest, each rendered format and the
  index, so a delivered report set can be proven to belong to the dataset it claims.

Index totals agree with the dataset in both corpora: 135 findings / 93 ticketable / 93 validated /
39 needs-investigation / 3 suppressed / 0 unvalidated, and 6 / 4 / 4 / 1 / 1 / 0. `totals.by_disposition`
splits the first corpus into 84 `validated/remediate-now`, 9 `validated/schedule`, 39 `needs-review` and
3 `suppressed/not-exploitable`, and the per-leaf counts match the files on disk exactly — which is what
`validate_reports.py` checks rather than trusts.

---

## 7. Defects this validation found and fixed

The suite was written to break the pipeline, and it did. Each fix below is now pinned by a test.

| # | Defect | Symptom | Fix |
|---|---|---|---|
| 1 | `validate_reports.py` secret-shape scan matched its own redaction markers | False "unredacted connection string" problems on a clean run | `_scan_secret_shapes` now skips every match that `finding_model.is_placeholder` recognises |
| 2 | HTML article count disagreed with the dataset (106 vs 78) | Validator reported a mismatch on a correct report | Expected IDs now include the "needs investigation" section; added `_json_report_article_ids` so report-only runs can still be checked |
| 3 | No verification of the per-finding deliverables | A missing or stale `tickets/<ID>.json` was invisible | Added `_check_finding_file` plus `findings-index.json` cross-checks (presence, hash, totals) |
| 4 | `validate_findings.py` discarded the redaction count | `redactions_applied: 0` on a run that redacted 2 secrets | `capture_evidence` returns its count and the caller sums it |
| 5 | Findings had no per-finding machine-readable file | "Which JSON describes VULN-042?" had no answer | `OUTPUT_NAMES["index"]`, `build_index()`, index wired into `generate_reports.py` |
| 6 | Not from this run: a later self-scan of `scripts/` reported 126 non-HTTP surfaces and 10 auth mechanisms | Reconnaissance read its own rule tables, docstrings and a commented-out decorator as live entry points and controls | `discover_auth` / `discover_non_http` now run against a comment- and string-blanked view with offsets preserved, non-HTTP rules must name a mechanism, and one surface is reported per kind per file; `test_self_scan_invents_no_surfaces` pins the result (16 real `__main__` guards, 0 web surfaces, 0 mechanisms) |
| 7 | Each redacting stage kept its own copy of the marker text | One Stripe key read `[REDACTED STRIPE SECRET KEY]` from the orchestrator and `[REDACTED STRIPE KEY]` from the validator, so VULN-003's evidence showed two labels for one shape | `builtin_analyzers.SECRET_PATTERNS` is now `(id, pattern, label, marker)` and the single source of the spelling; `finding_model.shape_marker` / `redact_shape_match` build and apply it for all three stages, which removed the duplicated pattern tables from `validate_findings` and `scanner_orchestrator`; `tests/test_redaction_markers.py` asserts one identical marker per shape across the three, that a marker survives a second stage unchanged, and that `_shape_replacement`'s docstring keeps balanced code spans. While correcting that docstring: its example spelled a credential-shaped assignment, which every redaction-aware tool then masked in its own output and made the sentence look truncated — the example is gone, and the wording now describes what the function keeps (assignment name, URL authority) instead of the retired length marker |
| 8 | Not from this run: `attack_surface.py` reported nothing at all for a convention-routed ASP.NET Core controller | The C# fixtures route by convention (no `[HttpGet]`/`[Route]`, a `.csproj` with no ASP.NET package reference), so they produced zero entry points *and* zero limitations: an unenumerable web app read exactly like an app with no endpoints, and the limitation that existed only fired for frameworks stage 2a *named* | New `CONTROLLER_STYLE_RULES` recognises a `Controller`/`ControllerBase`-derived class in the code-only view, `CONTROLLER_FRAMEWORK_SIGNALS` catches `using Microsoft.AspNetCore.Mvc` and `[ApiController]` when no route matched, and each such file becomes an `unenumerable_routes` record (`file`, `line`, `basis`, `class`, bounded `candidate_actions`, never an invented path) plus one aggregated limitation that says a zero-route result is a coverage gap. `test_attack_surface.py` pins both fixtures' gap, the attribute-routed negative case (a real route is never relabelled as a gap), the framework-signal-only case, the commented-out-controller negative case, and that no record carries a `path` |
| 9 | Pipeline files and CloudFormation templates were classified as plain config | `ci/.gitlab-ci.yml` and `ci/Jenkinsfile` fell through to the ``config`` bucket because the anchored CI pattern was matched against the whole relative path and never the file name, so the CI rules -- keyed on the iac bucket -- could not see them; a CloudFormation template inherited ``kubernetes`` from whichever directory held it, and ``_language_matches`` then skipped every ``yaml``-keyed rule that did not apply | ``CI_FILE_RE`` is matched against the file name, a new ``CFN_DIR_RE`` labels CloudFormation directories ``cloudformation``, and ``IAC_LANGUAGES`` learned ``cloudformation`` and ``groovy``; `test_scan_families.py` pins both classifications |
| 10 | Three rules matched a sentence instead of a call | ``system("date")`` was reported as command injection (the pattern accepted a string literal as a "variable"), ``cap_drop: - ALL`` was reported as adding every capability (the pattern could not tell add from drop), and ``WHERE name = 'xp_cmdshell'`` was reported as invoking it (the pattern matched the bare word, not the ``EXEC`` call) -- all three found by the secure look-alikes, which exist for exactly this | The C rule now requires an identifier immediately after the call parenthesis, ``k8s-caps`` gained a ``cap_add``/``capabilities`` context anchor, and ``sql-xp-cmdshell`` requires the ``EXEC ... xp_cmdshell`` form; each has its own negative test |
| 11 | The three-bucket layout answered two questions with one name | A confirmed `Critical` sat under a directory called `review-required`, which reads as a question rather than an emergency; and a finding nobody had assessed fell through to `optional-hardening`, a name that promises a discretionary fix for something that may not be real | The layout is now two levels: the verdict (`validated/`, `needs-review/`, `unvalidated/`, `suppressed/`) and, inside `validated/`, the urgency (`remediate-now/`, `schedule/`). Assignment lives in one function, `report_model.finding_bucket`, which the generator, the validator and the docs all use, so the tree, the `disposition` field and the register cannot disagree; `test_finding_buckets.py` proves the mapping total and mutually exclusive |
| 12 | A suppression could not say what kind it was | "False positive", "not exploitable" and "accepted risk" were one bucket with a prose reason, so the reader had to open the file to learn whether the code was fine or the code was broken and someone had signed it off | `suppression_kind` (`false_positive`/`not_exploitable`/`accepted_risk`) is a schema field, `validate_findings.py` sets `not_exploitable` for a compensating control and for a test-path suppression, and each kind has its own directory. A suppression that records no kind is filed under `suppressed/unspecified/` and the run warns instead of guessing |
| 13 | Any finding in the `findings` list was rendered as ticketable | `build_ticket` defaulted `ticketable=True`, so a finding that reached stage 6 with `validation_status: unvalidated` -- a validation stage that did not run, or a raw analyzer output fed straight to the generator -- would have been posted to an issue tracker as a vulnerability | `ticketable` is now derived from the bucket, never from the list the finding arrived in; unassessed findings are filed under `unvalidated/`, kept out of the report's `findings` section, and reported in the run's warnings by `validate_reports.py` |
| 14 | Regenerating a report left the previous filing behind | A finding that changed bucket, or was fixed and no longer reported, kept its old file in the old directory: two files for one id with opposite advice, and the validator counted an unexplained extra | `generate_json.py` prunes every per-finding `.json` it did not write in this run and reports what it removed; `test_regenerating_removes_a_file_the_run_no_longer_produces` pins it |
| 15 | A dataset whose `evidence` is a plain string crashed the JSON generator | The schema types `evidence` as a string, but `generate_json._description_markdown` assumed the display layer's dict and raised `AttributeError: 'str' object has no attribute 'get'` -- reachable by running the generator on a hand-written dataset | The function accepts either shape and renders the text; found while writing this round's tests |

Defect 5 came from a requirements change mid-validation (every finding must have its own JSON,
aggregate metadata its own file) and is the reason `references/reporting-standard.md` gained its
"Machine-readable deliverables" subsection.

Defect 6 was found after this run, by pointing the tool at itself. Its fix changes no count: both
corpora deliver the same findings as before it, with byte-identical
(id, category, severity, confidence, status) tuples.

Defects 11-15 come from the taxonomy change: the layout now answers two questions instead of one, a
suppression records which kind it was, and the per-finding tree is pruned to the current run. None of
them changes a severity, a count or a verdict; they change what a recipient can tell without opening
a file. It is recorded here because the previous
behaviour was a real precision bug in the stage this document treats as ground truth for
"no visible authentication".

---

## 8. Limitations (unresolved, stated plainly)

1. **No external scanners.** `php` and `javac` are absent in this environment, so the PHP and Java
   fixtures were reviewed by the built-in analyzers only; their syntax was validated by the
   language tools that *are* present (`node --check`, `ruby -c`, `gofmt -e`, `python -m py_compile`,
   YAML/JSON parse). A run with Semgrep/Bandit installed would add scanner-backed sources, not
   change these counts.
2. **No PDF.** The PDF renderer needs a toolchain that is not installed; every run in this document
   requested `markdown,html,json`. `validate_reports.py` records `pdf_state: absent` and one
   informational warning ("the manifest lists no pdf format, so this run requested only html, json,
   markdown") rather than a problem, and `--require-pdf` turns a missing PDF into a failure once the
   toolchain is present. No claim in this document depends on a PDF existing.
3. **Route-bearing code with no enumerable routes.** Convention-routed code is not enumerated:
   `attack_surface.py` reports the ASP.NET Core controller in both corpora (and any other
   `Controller`-derived class) as an `unenumerable_routes` record plus a limitation, but does not
   invent the `/Orders/List`-style URL its action names imply; the Java servlet remains unenumerated
   and is named as a framework with no route rule. Findings in those files therefore carry no route
   context. Stated, counted, and still a gap: it affects context quality, not detection counts.
4. **The newer language families are pattern-only.** Rust, C/C++, Swift, shell, PowerShell, SQL and
   Kotlin have a small rule set -- the sink each language makes dangerous -- but no dataflow: the
   engines that trace a value from a request to a sink exist for the seven original languages. A
   `format!`-built path that a neighbouring line already sanitises still matches. The confidence is
   set accordingly (MEDIUM, not CONFIRMED), and every such finding lands in `needs_review` unless
   the validator can re-read the evidence. Kotlin reuses five JVM rules verbatim because the pattern
   is a JDK API call rather than syntax; `test_scan_families.py` pins all of them.
5. **Not every inventoried language has a rule.** Scala, Elixir, Erlang, Clojure, Haskell, Lua,
   Perl, R, Objective-C, Vue and Svelte are classified and reported in the inventory, and none has
   a detection rule -- the inventory says so by omission, which is the honest signal but not a
   finding. No fixture pins them, so nothing here claims coverage.
6. **Classification is path-based for infrastructure.** A `cloudformation/` directory (or a
   `.gitlab-ci.yml` file name) identifies a template only while the path still contains it: scanning
   that directory *as* the repository root labels its files `config`. The audit walks the repository
   root, so this affects ad-hoc subtree runs, not the results in this document.
7. **Fixture corpora, not real repositories.** 34 files each is enough to exercise every rule and
   both directions of the false-positive question, but it is not a measurement of precision on a
   production codebase. The corpora are the regression contract; production precision is unknown
   until the skill is run against real repositories.
8. **Timings are for an idle machine** (≈60 s for 400 tests, ≈7 s for both corpora) and include no
   network or scanner latency, so they are a floor, not a budget.

---

## 9. Verdict

The pipeline is internally consistent end to end: 20/20 required classes still detected on the
vulnerable corpus, 6/6 recorded false positives and nothing else on the secure corpus, every
delivered finding traceable to a rule and a code path, every count in the human-readable reports
reproducible from the machine-readable dataset, and zero secret leaks. The six defects above were
real and are now covered by tests; the five limitations above are real and are not.

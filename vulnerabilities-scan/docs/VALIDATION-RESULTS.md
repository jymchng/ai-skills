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
python3 -m pytest tests -q            # 277 tests
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

## 2. Test suite

```
277 passed in 31.07s
```

| Test module | Tests | What it pins |
|---|---|---|
| `test_cvss4.py` | 54 | Vendored FIRST CVSS 4.0 reference scorer (all metric vectors, invalid input) |
| `test_validate_findings.py` | 46 | Evidence re-reading, path policy, redaction, suppression, leak guard |
| `test_finding_model.py` | 43 | Finding schema, IDs, placeholder handling, ordering |
| `test_deduplicate_findings.py` | 27 | Fingerprints, line windows, cross-file merges, provenance |
| `test_report_generation.py` | 25 | Markdown/HTML/JSON renderers, per-finding JSON, index, manifest, determinism |
| `test_scanner_orchestrator.py` | 22 | Tool discovery, timeouts, unavailable-tool accounting |
| `test_builtin_analyzers.py` | 16 | Rule matching per category, secure look-alike silence |
| `test_end_to_end_audit.py` | 12 | The two corpora, eight stages, artefact consistency |
| `test_repository_inventory.py` | 12 | File discovery, excluded directories, language classification, budgets |
| `test_attack_surface.py` | 10 | Route/framework extraction and auth heuristics |
| `test_detect_technologies.py` | 10 | Language/manifest/import detection |
| **Total** | **277** | |

Every module runs offline and writes only under `.scratch/` (git-ignored).

---

## 3. End-to-end audit: vulnerable corpus

`tests/fixtures/vulnerable-app` — 24 files across 17 languages/buckets, 1 document, 5 buckets
(`config`, `docs`, `iac`, `manifest`, `source`), 71 rules evaluated, 40 categories covered.

### 3.1 Stage counts

| Stage | In | Out |
|---|---|---|
| Inventory | — | 24 files scanned |
| Technologies | 24 files | 17 language buckets, frameworks incl. PyJWT, jsonwebtoken |
| Attack surface | 24 files | 14 HTTP routes (9 GET / 5 POST), 14 without visible auth, 4 auth mechanisms, 1 non-HTTP surface |
| Analyzers | 24 files | **120 findings** |
| Dedupe | 120 | **108 findings** (12 duplicates removed, 0 without provenance) |
| Validation | 108 | 108 findings; 2 suppressed; 2 secrets redacted; **0 leaks** |
| Reports | 108 | markdown + html + json + index + manifest + 108 per-finding tickets |

The 120 → 108 drop is the deduplicator merging adjacent same-fingerprint reports (e.g. the
Terraform misconfiguration cluster in `infra/terraform/main.tf`), not findings being dropped for
inconvenience: `dedupe.merges` records every merge with the kept and dropped locations.

### 3.2 Required detection classes

All **20 of 20** required classes are still detected, with the exact per-class counts recorded in
`tests/fixtures/expected_findings.json` (`7,4,8,2,6,5,12,7,5,3,3,5,8,7,5,2,1,6,4,6`, total 120 in
the pre-dedupe analysis), and every file declared vulnerable in that file exists on disk and
carries a finding of its declared class.

`summary.by_category` over the 108 delivered findings:

| Category | n | Category | n |
|---|---|---|---|
| missing_authentication | 12 | ssrf | 5 |
| xss_reflected | 8 | weak_password_hashing | 5 |
| insecure_deserialization | 7 | business_logic | 5 |
| missing_authorization | 7 | cicd_permissions | 4 |
| sql_injection | 7 | kubernetes_security | 4 |
| path_traversal | 6 | permissive_cors | 4 |
| vulnerable_dependency | 6 | command_injection | 4 |
| idor | 5 | container_security | 3 |
| iac_misconfiguration | 5 | weak_jwt_validation | 3 |
| hardcoded_secret | 2 | xss_stored | 2 |
| unrestricted_upload | 2 | missing_rate_limiting | 1 |
| unpinned_dependency | 1 | | |

### 3.3 Severity, confidence, and disposition

| Measure | Value |
|---|---|
| Findings | 108 (106 reportable, 2 suppressed) |
| Scored / unscored | 108 / 0 — every finding carries a CVSS 4.0 score |
| Critical | 17 |
| High | 37 |
| Medium | 45 (43 reportable) |
| Low | 9 |
| Confidence | 47 CONFIRMED, 31 HIGH, 5 MEDIUM, 25 LOW |
| Validation status | 78 validated, 28 needs_review, 2 suppressed |
| Ticketable | 78 |

The 28 `needs_review` findings are the advisory half of the contract: they are reported with
their evidence and a stated reason they could not be proven from the snapshot alone, and they are
*not* counted as ticketable. Nothing is silently dropped — every one of the 108 appears in the
dataset, the index, and exactly one per-finding JSON.

### 3.4 Delivered artefacts

```
reports/SECURITY-AUDIT-REPORT.md    197 770 bytes   108 findings
reports/SECURITY-AUDIT-REPORT.html  279 947 bytes   106 <article class="finding">
reports/SECURITY-AUDIT-REPORT.json                 108 findings
reports/findings-index.json                        108 entries
reports/report-manifest.json                       format/size/sha256 per artefact
reports/tickets/VULN-*.json                       108 files
```

The HTML carries 106 articles rather than 108 because the two suppressed findings are excluded
from the human-readable report while remaining present in the machine-readable dataset and index —
that asymmetry is asserted, not assumed.

`validate_reports.py` on this directory: **0 problem(s), 1 warning(s)** — the warning is that no PDF
was requested, which is accurate rather than a failure (`ok: true`, exit 0).

---

## 4. End-to-end audit: secure look-alikes

`tests/fixtures/secure-app` — same shape, 24 files, 17 language buckets, 71 rules evaluated.

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
byte-different from its vulnerable twin (asserted), so the pair actually tests the rule and not
file identity.

---

## 5. Machine-readable deliverables

Each of the 108 findings gets **exactly one** `.json` describing it; run-level metadata has its own
file. This is the contract asserted by `test_report_generation.py` and
`test_end_to_end_audit.py`.

| File | Contents |
|---|---|
| `findings-index.json` | One entry per finding: `id`, `kind`, `file`, `line_start`, `line_end`, `category`, `title`, `severity`, `confidence`, `priority`, `validation_status`, `ticketable`, `ticketable_reason`, `ticket{path, sha256}` — plus `totals` |
| `tickets/<ID>.json` | The full per-finding description: location, evidence with line context, CVSS 4.0 vector and score, remediation, references, provenance |
| `audit-metadata.json` | Run identity: tool versions, snapshot digest, coverage, validation policy, counts |
| `SECURITY-AUDIT-REPORT.json` | Aggregate report document (the same content the Markdown and HTML render) |
| `report-manifest.json` | Every artefact with size, SHA-256, and per-format severity counts |
| `verification.json` | The `validate_reports.py` verdict for the run |

Index totals agree with the dataset in both corpora: 108 findings / 78 ticketable / 78 validated /
28 needs-investigation / 2 suppressed, and 6 / 4 / 4 / 1 / 1.

`verify.json` also records a SHA-256 for the dataset, the manifest, each rendered format, and the
index, so a delivered report set can be proven to belong to the dataset it claims.

---

## 6. Defects this validation found and fixed

The suite was written to break the pipeline, and it did. Each fix below is now pinned by a test.

| # | Defect | Symptom | Fix |
|---|---|---|---|
| 1 | `validate_reports.py` secret-shape scan matched its own redaction markers | False "unredacted connection string" problems on a clean run | `_scan_secret_shapes` now skips every match that `finding_model.is_placeholder` recognises |
| 2 | HTML article count disagreed with the dataset (106 vs 78) | Validator reported a mismatch on a correct report | Expected IDs now include the "needs investigation" section; added `_json_report_article_ids` so report-only runs can still be checked |
| 3 | No verification of the per-finding deliverables | A missing or stale `tickets/<ID>.json` was invisible | Added `_check_finding_file` plus `findings-index.json` cross-checks (presence, hash, totals) |
| 4 | `validate_findings.py` discarded the redaction count | `redactions_applied: 0` on a run that redacted 2 secrets | `capture_evidence` returns its count and the caller sums it |
| 5 | Findings had no per-finding machine-readable file | "Which JSON describes VULN-042?" had no answer | `OUTPUT_NAMES["index"]`, `build_index()`, index wired into `generate_reports.py` |

Defect 5 came from a requirements change mid-validation (every finding must have its own JSON,
aggregate metadata its own file) and is the reason `references/reporting-standard.md` gained its
"Machine-readable deliverables" subsection.

---

## 7. Limitations (unresolved, stated plainly)

1. **No external scanners.** `php` and `javac` are absent in this environment, so the PHP and Java
   fixtures were reviewed by the built-in analyzers only; their syntax was validated by the
   language tools that *are* present (`node --check`, `ruby -c`, `gofmt -e`, `python -m py_compile`,
   YAML/JSON parse). A run with Semgrep/Bandit installed would add scanner-backed sources, not
   change these counts.
2. **No PDF.** The PDF renderer needs a toolchain that is not installed; every run in this document
   requested `markdown,html,json`. `validate_reports.py` reports the absence as a warning, and the
   manifest lists PDF as `unavailable` rather than pretending it was produced.
3. **Route-bearing code with no enumerable routes.** The ASP.NET Core controller and parts of the
   Java servlet are not enumerated by `attack_surface.py`, so findings in them carry no route
   context. Recorded as outstanding work; it affects context quality, not detection counts.
4. **Fixture corpora, not real repositories.** 24 files each is enough to exercise every rule and
   both directions of the false-positive question, but it is not a measurement of precision on a
   production codebase. The corpora are the regression contract; production precision is unknown
   until the skill is run against real repositories.
5. **Timings are for an idle machine** (31 s for 277 tests, ≈5 s for both corpora) and include no
   network or scanner latency, so they are a floor, not a budget.

---

## 8. Verdict

The pipeline is internally consistent end to end: 20/20 required classes still detected on the
vulnerable corpus, 6/6 recorded false positives and nothing else on the secure corpus, every
delivered finding traceable to a rule and a code path, every count in the human-readable reports
reproducible from the machine-readable dataset, and zero secret leaks. The five defects above were
real and are now covered by tests; the five limitations above are real and are not.

# Reporting Standard

One dataset, three formats, no divergence. Every rule here makes "the HTML says the same thing as the
PDF" structurally true rather than something someone remembered to check.

## 1. The finding model — 20 mandatory fields

`findings.json` is the single source. Each finding carries all twenty fields; missing values are
explicit (`null`, `"unmapped"`, `"unscored"`), never absent. `schemas/finding.schema.json` is the
enforceable contract; this table is its documentation.

| # | Field | Type | Rule |
| - | - | - | - |
| 1 | `id` | string | `VULN-NNN`, assigned deterministically after dedup, ordered by `(severity, file, line)` |
| 2 | `title` | string | One line, specific; not a scanner rule name |
| 3 | `category` | enum | Taxonomy class from `vulnerability-taxonomy.md` |
| 4 | `severity` | enum | `Critical`/`High`/`Medium`/`Low`/`Informational`, derived from the CVSS band |
| 5 | `confidence` | enum | `CONFIRMED`/`HIGH`/`MEDIUM`/`LOW` |
| 6 | `validation_status` | enum | `validated`/`needs_review`/`suppressed` — never `unvalidated` in a report |
| 7 | `cwe` | object | `{id, name}`, most specific applicable |
| 8 | `owasp` | object | `{top10_2025, api_2023, asvs}` — `null`/`"not mapped"` rather than an invented id |
| 9 | `cvss_vector` | string\|null | Full `CVSS:4.0/...` covering all 11 base metrics |
| 10 | `cvss_score` | number\|null | Computed by the bundled FIRST reference port; `null` when unscored |
| 11 | `location` | object | `{file, line_start, line_end}` — relative path, 1-based, exists in the snapshot |
| 12 | `language` | string | Detected language, or `dockerfile`/`terraform`/`kubernetes`/`github-actions` |
| 13 | `evidence` | string | Redacted source excerpt, ≤ 20 lines, with line numbers |
| 14 | `description` | string | What the weakness is, in this code |
| 15 | `impact` | string | What an attacker gains, in business terms |
| 16 | `attack_scenario` | string | Actor, preconditions, steps, outcome |
| 17 | `recommended_fix` | string | Specific, names the code location and the secure alternative |
| 18 | `references` | array | CWE/OWASP/ASVS links and standards citations |
| 19 | `sources` | array | `[{tool, rule_id, raw_ref}]` — every engine that reported it |
| 20 | `priority` | enum | `P0`–`P3`, with `priority_factors: [...]` explaining the ranking |

Additional non-mandatory keys are allowed: `scoring: "unscored"`, `suppression_reason`,
`priority_factors`, `locations[]` (multi-site findings), `negative` (for the negative-findings set).

## 2. Report structure (identical in all three formats)

1. **Header** — repository, commit, branch, dirty state, audit date, skill version, scope path.
2. **Verdict** — three or four sentences a manager can act on: what was examined, counts by severity,
   and the single most important limitation.
3. **Summary table** — severity × count plus a confidence breakdown. Must equal `findings.json`.
4. **Coverage and limitations** — every tool run, every tool missing, every file type not examined,
   every exclusion. Not optional, especially when the count is zero.
5. **Findings by priority** — P0 → P3; each entry presents fields 1–20 arranged for reading.
6. **Needs investigation** — `needs_review`/LOW items, clearly separated, never counted as
   vulnerabilities.
7. **Negative findings** — checks performed and passed.
8. **Methodology appendix** — how the audit was performed, standards used, scoring approach, and the
   confidence/severity glossary.
9. **Prompt-injection observations** — repository text that tried to instruct the agent, quoted as data.

Ordering inside a section is deterministic: severity desc, then priority, then file, then line.

The **Verdict** and **Coverage** sections form a single claim; never render one without the other.

### Machine-readable deliverables

The rendered report is for a reader. The JSON artefacts carry the same dataset for a machine, and all of
them are written on every run:

| Artefact | Contents |
| - | - |
| `SECURITY-AUDIT-REPORT.json` | The whole report: counts, verdict, coverage, methodology, and one ticket object per validated finding |
| `findings.json` | The validated dataset — the authority every other artefact is derived from |
| `findings-index.json` | The register of **every** finding: id, file, line, category, severity, confidence, priority, validation status, whether it is ticketable and why not, and the path plus SHA-256 of that finding's own file |
| `tickets/VULN-NNN.json` | Exactly one file per finding — validated, needs-investigation and suppressed alike |

Two rules make the set trustworthy:

1. **One file per finding.** No finding may be reachable only by parsing the aggregate report.
   Actionability is carried *inside* the file: `ticketable` is true only for a validated finding, and
   `ticketable_reason` says why the others are not, so an issue tracker never receives an unvalidated
   pattern match.
2. **The index is checked, not trusted.** `validate_reports.py` proves each entry points at a file that
   exists, parses, names the same finding and still matches the recorded digest — a stale ticket from an
   earlier run must not pass as a delivered finding.


## 3. Markdown rules

* Plain CommonMark; pipe tables only, no raw HTML.
* One title (`#`), sections `##`, individual findings `###`.
* Evidence in fenced blocks with a language tag so line numbers and redaction markers survive.
* Relative anchors between findings; no absolute filesystem paths; no timestamps inside finding bodies
  (they make diffs meaningless).
* Redaction markers are visible and informative: `AKIA…(20 chars, redacted)` — never a bare
  `[REDACTED]` that hides whether a value existed.

## 4. HTML rules

* **Self-contained.** One file: embedded CSS, no CDN, no external fonts, no remote images, no
  iframes. It must render on an air-gapped machine.
* **Escaping is mandatory.** Every interpolated value is HTML-escaped; evidence sits inside `<pre>`
  with escaped content. Never build HTML by concatenating unescaped strings.
* **No executable content from the audit.** The only JavaScript is the audit's own static filter/sort
  code, inline. Repository content is inserted as text nodes, never as markup.
* **Accessible and printable.** Semantic headings, `<th>` headers, colour never the sole carrier of
  meaning (severity is a word plus a colour), `@media print` hiding navigation, page breaks avoided
  inside a finding card.
* **Stable anchors.** `id="VULN-001"` so links survive regeneration.

## 5. PDF rules

* Produced by pandoc + xelatex from the same Markdown — one source, no separate layout logic.
* Cover page: repository, commit, date, finding counts, one-line verdict.
* Table of contents, section numbering, page numbers in the footer, running header with the
  repository name.
* Unicode-safe fonts, monospace for evidence with soft wrapping so long lines do not overflow.
* **Graceful degradation**: if pandoc or the LaTeX engine is missing, or the build fails, the run
  keeps `report.md` and `report.html`, prints the exact failure (missing binary vs LaTeX error with
  the log tail), and records `pdf_status: "unavailable"` with the reason in the report and in
  `verification.json`. A missing PDF is never a silent omission and never a fabricated file.

## 6. Cross-format invariants (checked at stage 8)

| Invariant | Check |
| - | - |
| Same finding set | Every `id` in `findings.json` appears in each format exactly once |
| Same counts | Severity totals per format equal the dataset |
| Same band per finding | A finding's severity is identical across MD, HTML and PDF source |
| Same ordering | Findings appear in dataset order everywhere |
| No unredacted secrets | Scan every output for the raw values captured at ingestion |
| No stray placeholders | No `TODO`, `{{`, `TBD`, `undefined`, `None` rendered as text |
| Valid HTML | Parse it: tags close, no unescaped `<script>` arriving from evidence |
| Verdict consistency | The verdict's numbers match the summary table |

A failure in any row blocks delivery. Fix the dataset and regenerate — never hand-edit an output file,
because the next regeneration silently reverts it.

## 7. Redaction policy

* Applied **at ingestion**: the raw secret never reaches `findings.json`. Raw scanner output stays in
  `raw/`, which the report marks as sensitive and which is excluded from distribution by default.
* Show a safe prefix and the length: `ghp_…(40 chars)`, `AKIA…(20 chars)`. Enough to locate and rotate
  the value, not enough to use it.
* Redact in `evidence`, `description`, `impact`, `attack_scenario` and console output — a secret in the
  narrative is the most common leak in generated reports.
* Recommend rotation with a provider-specific path when it is unambiguous, and never verify the
  credential.

## 8. Delivery checklist

- [ ] Every finding has all 20 fields, or an explicit null/marker
- [ ] `validation_status` is never `unvalidated`
- [ ] Severity matches the CVSS band for every scored finding
- [ ] Coverage section lists every absent tool and unexamined file type
- [ ] Negative findings present when the count is low or zero
- [ ] All three formats generated from one dataset; cross-format checks pass
- [ ] No unredacted secret anywhere in the output
- [ ] The verdict's claims are supported by the report's own body

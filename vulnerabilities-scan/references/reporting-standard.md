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
| 6 | `validation_status` | enum | `validated`/`needs_review`/`suppressed`; `unvalidated` is allowed only in the *Unassessed* section, where it is named as a gap rather than a finding |
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
`suppression_kind` (`false_positive`/`not_exploitable`/`accepted_risk`, required in practice on a
suppressed finding because it decides which `suppressed/` bucket the file is filed in),
`priority_factors`, `locations[]` (multi-site findings), `negative` (for the negative-findings set).

## 2. Report structure (identical in all three formats)

1. **Header** — repository, commit, branch, dirty state, audit date, skill version, scope path.
2. **Verdict** — three or four sentences a manager can act on: what was examined, counts by severity,
   and the single most important limitation.
3. **Overview** — the whole audit in a few paragraphs: what was examined, how every finding was
   adjudicated (confirmed, open, suppressed by kind, never assessed), where the risk sits, the
   highest score recorded, and where to start. Never a hand-written paragraph: it is composed from
   the dataset so it cannot say something the findings array contradicts.
4. **Summary table** — severity × count plus the four dispositions and a confidence breakdown. Must
   equal `findings.json`.
5. **Statistics** — the numbers behind the verdict, one row per fact: every disposition bucket
   (including the empty ones), the suppression kinds, and the category / CWE / language
   distributions, plus the scoring arithmetic (scored, unscored, mean, highest) and the coverage
   arithmetic (files examined of files in scope, rules evaluated). Every row is recomputed from the
   findings array; a zero here is a measured zero.
6. **Coverage and limitations** — every tool run, every tool missing, every file type not examined,
   every exclusion. Not optional, especially when the count is zero.
7. **Findings by priority** — P0 → P3; each entry presents fields 1–20 arranged for reading.
8. **Needs investigation** — `needs_review`/LOW items, clearly separated, never counted as
   vulnerabilities.
9. **Unassessed findings** — anything that reached delivery with no verdict. A gap in the audit, not
   a finding, and never silently counted among the confirmed ones.
10. **Negative findings** — checks performed and passed.
11. **Methodology appendix** — how the audit was performed, standards used, scoring approach, and the
    confidence/severity glossary.
12. **Prompt-injection observations** — repository text that tried to instruct the agent, quoted as data.

Ordering inside a section is deterministic: severity desc, then priority, then file, then line.

The **Verdict**, **Overview** and **Coverage** sections form a single claim, and the **Summary** and
**Statistics** sections are the same numbers seen two ways; never render one without the others.

### Machine-readable deliverables

The rendered report is for a reader. The JSON artefacts carry the same dataset for a machine, and all of
them are written on every run:

| Artefact | Contents |
| - | - |
| `SECURITY-AUDIT-REPORT.json` | The whole report: counts, statistics, verdict, overview, coverage, methodology, and one ticket object per finding |
| `findings.json` | The validated dataset — the authority every other artefact is derived from |
| `findings-index.json` | The register of **every** finding: id, file, line, category, severity, confidence, priority, validation status, `disposition`, whether it is ticketable and why not, and the path plus SHA-256 of that finding's own file |
| `findings/validated/remediate-now/VULN-NNN.json` | Exactly one file per confirmed vulnerability that owes action now |
| `findings/validated/schedule/VULN-NNN.json` | Exactly one file per confirmed vulnerability whose fix can be scheduled |
| `findings/needs-review/VULN-NNN.json` | Exactly one file per finding the evidence could not settle |
| `findings/unvalidated/VULN-NNN.json` | Exactly one file per finding nothing assessed — a gap in the audit, not a vulnerability |
| `findings/suppressed/false-positive/VULN-NNN.json` | Exactly one file per finding that was reported and is not there |
| `findings/suppressed/not-exploitable/VULN-NNN.json` | Exactly one file per real weakness no attacker can reach |
| `findings/suppressed/accepted-risk/VULN-NNN.json` | Exactly one file per real, reachable weakness the owner accepted |
| `findings/suppressed/unspecified/VULN-NNN.json` | Exactly one file per suppression that never recorded which of the three it was |

### One file per finding, filed under `findings/`

Every finding — validated, needs-investigation, unassessed and suppressed alike — gets its own
`.json` file. The files live in a `findings/` directory, never in a flat pile: a single directory puts
a suppressed accepted risk next to a confirmed Critical and the recipient cannot tell them apart
without opening both.

```
reports/
├── findings-index.json
└── findings/
    ├── validated/
    │   ├── remediate-now/VULN-004.json
    │   └── schedule/VULN-019.json
    ├── needs-review/VULN-031.json
    ├── unvalidated/
    └── suppressed/
        ├── false-positive/VULN-007.json
        ├── not-exploitable/
        ├── accepted-risk/
        └── unspecified/
```

1. **One file per finding.** No finding may be reachable only by parsing the aggregate report. The file
   name is `VULN-NNN.json` and the number in the name is the finding's own `id` — one file, one finding,
   no `unassigned.json` collision.
2. **Two questions, two levels.** The layout answers *is this a vulnerability?* with the first directory
   and *what should be done, and when?* with the second. One level cannot answer both: a name like
   `review-required/` says nothing about whether the finding is real, and it undersells the worst case —
   a confirmed Critical filed under "review required" reads as a question, not as an emergency. Urgency
   is a subdirectory of `validated/` precisely because asking how urgently to fix something nobody has
   confirmed is a question with no honest answer.
3. **Exactly one bucket.** Each finding is written to exactly one leaf directory: never two, never zero.
   Assignment is deterministic, first match wins, and reads only fields the schema requires:

   | Order | Bucket | Assigned when |
   | - | - | - |
   | 1 | `validated/remediate-now/` | `validation_status: validated` and severity `Critical`/`High`/`Medium` **or** priority `P0`–`P2` |
   | 2 | `validated/schedule/` | `validation_status: validated` and severity `Low`/`Informational` **and** priority `P3` |
   | 3 | `needs-review/` | `validation_status: needs_review` |
   | 4 | `unvalidated/` | `validation_status: unvalidated`, or no usable status at all |
   | 5 | `suppressed/false-positive/` | `suppression_kind: false_positive` |
   | 6 | `suppressed/not-exploitable/` | `suppression_kind: not_exploitable` |
   | 7 | `suppressed/accepted-risk/` | `suppression_kind: accepted_risk` |
   | 8 | `suppressed/unspecified/` | suppressed, with no `suppression_kind` recorded |

   *Severity before priority.* A `Medium` on `P3` is filed as `remediate-now`: priority is a scheduling
   input, and a confirmed Medium vulnerability that is cheap to fix is still a confirmed Medium
   vulnerability. The reverse also holds — a `Low` promoted to `P1` owes action.
   `validated/schedule/` means "schedule it", never "ignore it": the file keeps `ticketable: true` and
   its full record. Only `suppressed/` says an action was deliberately declined.
4. **A suppression says which kind.** `false_positive` (the flaw is not there — detector misfired, code
   correct), `not_exploitable` (the weakness is real but unreachable: dead code, test-only path, an
   effective control on the path) and `accepted_risk` (real, reachable, signed off) are three different
   claims with three different follow-ups: fix the rule, delete the dead code, or revisit the decision.
   Filing them together hides which one is being made. A suppression with no `suppression_kind` is filed
   under `unspecified/` and the validator warns: the bucket exists so the gap is visible, not so it can
   be filled by guessing.
5. **`unvalidated/` is an alarm, not a category to aim for.** A finding nothing assessed must never be
   presented as a vulnerability, and must not be dropped either — it is still a finding with evidence.
   A non-empty `unvalidated/` means the validation stage did not reach delivery and the validator says so
   in the run's warnings.
6. **The bucket is stated, not inferred.** It is repeated inside the file as `disposition` and in
   `findings-index.json` as `disposition` alongside `json.path`, so a consumer never has to parse a
   directory name to know why a finding sits where it does.
7. **Every leaf directory exists on every run**, nested ones included, even when empty, so a missing
   bucket reads as a zero count rather than as a stage that did not run.
8. **The tree describes this run.** Regenerating into an existing directory removes per-finding files the
   run did not write. A finding that moved bucket — downgraded, upgraded, or newly suppressed — would
   otherwise exist twice, in two directories, with opposite advice; the run reports what it pruned.
9. **Actionability is carried inside the file.** `ticketable` is true only for a finding in a
   `validated/` bucket and `ticketable_reason` says why the others are not, so an issue tracker never
   receives an unvalidated pattern match.
10. **The index is checked, not trusted.** `validate_reports.py` proves each entry points at a file that
    exists, parses, names the same finding, sits in the bucket its `disposition` implies, repeats that
    `disposition` inside the file, and still matches the recorded digest — a stale file from an earlier
    run must not pass as a delivered finding, and a correct file in the wrong directory must not pass as
    correctly filed.


## 3. Markdown rules

* Plain CommonMark; pipe tables only, no raw HTML.
* One title (`#`), sections `##`, individual findings `###`.
* Evidence in fenced blocks with a language tag so line numbers and redaction markers survive.
* Relative anchors between findings; no absolute filesystem paths; no timestamps inside finding bodies
  (they make diffs meaningless).
* Redaction markers are visible and informative: `[REDACTED AWS KEY ID]` names the shape that was
  removed, so the reader knows a credential existed and what kind — never a bare `[REDACTED]` that
  hides both.

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
* Name the shape: `[REDACTED GITHUB TOKEN]`, `[REDACTED STRIPE KEY]`, `[REDACTED AWS KEY ID]`. Every
  stage writes the same marker for the same shape (`finding_model.shape_marker`), so one report never
  shows two labels for one credential. A secret with no recognisable shape falls back to a length
  marker, `…(7 chars)`: enough to tell the reader something was removed, not enough to use it.
* Redact in `evidence`, `description`, `impact`, `attack_scenario` and console output — a secret in the
  narrative is the most common leak in generated reports.
* Recommend rotation with a provider-specific path when it is unambiguous, and never verify the
  credential.

## 8. Delivery checklist

- [ ] Every finding has exactly one `.json` under `findings/`, in exactly one disposition bucket, and
      `findings-index.json` names that same path
- [ ] Every finding has all 20 fields, or an explicit null/marker
- [ ] Every finding was adjudicated by hand: none is `validated` on the strength of a pattern, and no
      suppression lacks a `suppression_kind`
- [ ] `unvalidated` findings are in the *Unassessed* section, never counted as vulnerabilities
- [ ] The Overview and the Statistics section are present, and their numbers match the summary table
      and the findings array — they are generated, never authored
- [ ] Severity matches the CVSS band for every scored finding
- [ ] Coverage section lists every absent tool and unexamined file type
- [ ] Negative findings present when the count is low or zero
- [ ] All three formats generated from one dataset; cross-format checks pass
- [ ] No unredacted secret anywhere in the output
- [ ] The verdict's claims are supported by the report's own body

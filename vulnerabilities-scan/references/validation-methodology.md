# Validation Methodology

Stage 5 is the difference between a scanner and an audit. Every candidate is either promoted with
evidence, downgraded with a reason, or suppressed with a recorded justification.

## 1. The six-step protocol

For each candidate, in order:

1. **Locate** — open the file at the reported line and confirm the code is what the rule thought it
   was. Tool line numbers drift; the source file is the authority.
2. **Read context** — the enclosing function, plus one hop of callers when the input arrives as a
   parameter. A sink in a function nobody calls is not a live finding.
3. **Identify the attacker input** — name the exact source (`request.args['id']`, `req.body.email`,
   a queue message field) and the variable chain that carries it.
4. **Trace to the sink** — establish that the tainted value reaches the dangerous argument, through
   assignment, formatting or composition.
5. **Search for controls** — on the path, in the caller, in framework middleware, in configuration.
   Record what was found *and* what was searched.
6. **Judge bypassability** — a control that is present but ineffective (a deny-list of `..`, a MIME
   check on a client-supplied header, `startsWith` without a separator) does not mitigate. Say why.

A candidate that cannot complete steps 3–4 is **not** reported as a vulnerability. It becomes
`needs_review` at LOW confidence, or is dropped with a recorded reason.

## 2. Evidence requirements

| Requirement | Rule |
| - | - |
| `location` | File relative to the audited root, 1-based line range that exists in the snapshot |
| `evidence` | Actual source lines re-read at validation time — not the scanner's message |
| `cwe` | Most specific applicable CWE; `CWE-20` is a last resort |
| `attack_scenario` | Concrete: who can reach it, with what preconditions, to what effect — written so a developer recognises their own code |
| `recommended_fix` | Actionable and specific to this codebase ("bind the parameter in `orders.py:88`"), not "sanitise input" |
| `sources` | Every engine that reported it, with rule ids |
| `validation` | The steps performed and the controls searched, so the reader can audit the auditor |

Secrets add one rule: the evidence line is **redacted at ingestion** — the value becomes a prefix and
a length marker (`AKIA…(20 chars)`), and the raw value never enters `findings.json`.

## 3. The confidence ladder

| Level | Criteria (all must hold) |
| - | - |
| **CONFIRMED** | The sink is visible, the tainted value demonstrably reaches it in the same function, and the required control is absent with no compensating control on the path. Or: the insecure configuration is literally present (`verify_signature: False`, `alg: none`, `md5(password)`, `Allow-Origin: *` with credentials, `privileged: true`). |
| **HIGH** | Dataflow established as above, but a control exists whose effectiveness cannot be fully judged statically (custom sanitiser, upstream gateway), or the path is on a plausible but unproven route. |
| **MEDIUM** | Sink plus plausible attacker influence, but provenance crosses a boundary static analysis cannot follow (DI, reflection, serialised payload, cross-service), or the judgement depends on deployment configuration. |
| **LOW** | Pattern-only: a dangerous construct with no established attacker input, or behaviour that depends on requirements the repository does not state. **Never appears in the confirmed-vulnerability section** — it is listed under *needs investigation*. |

Category ceilings override the ladder: business logic caps at MEDIUM, CVE reachability caps at MEDIUM
for exploitability, and a pattern-only hit can never exceed MEDIUM.

## 4. Validation status lifecycle

`validation_status` records the finding's journey, independent of confidence:

```
unvalidated ──▶ validated ──▶ reported
      │              │
      ├──▶ needs_review ──▶ reported (as investigation item)
      └──▶ suppressed  (reason recorded, excluded from findings)
```

| Status | Meaning |
| - | - |
| `unvalidated` | Just parsed; must not survive to the report |
| `validated` | Passed steps 1–6 and carries evidence |
| `needs_review` | Inconclusive; reported as an investigation item with the open question stated |
| `suppressed` | False positive or accepted risk; **kept in the dataset** with `suppression_reason` so the next audit does not rediscover it |

Invariant: no finding with `validation_status: unvalidated` may appear as a vulnerability in any
report format. The generator enforces this; validation is not a rendering concern.

## 5. Deduplicate before validating

Validate after dedup so the same real issue is examined once with all its provenance. Merge rules
(mirrored in `reporting-standard.md`):

* Same `file` + `line ± 3` + same `cwe` → one finding.
* Same `cwe` + same root cause in different files (copy-pasted helper) → one finding with multiple
  locations, split only when the fix differs.
* Different CWEs on the same line (CWE-89 and CWE-20) → keep the more specific.
* Conflicting severities → the highest defensible vector wins, and the merge is recorded.

## 6. Compensating-control outcomes

A control mitigates only when it is on the path **and** effective. Record each search outcome:

| Outcome | Recorded as |
| - | - |
| Effective control found | suppressed, `suppression_reason: "parameterised query at line 91"` |
| Partial/fragile control | finding kept, confidence lowered one step, fragility noted in `impact` |
| Control present but bypassable | finding kept at full confidence, bypass explained in `evidence` |
| No control, nothing to search | finding at full confidence |

## 7. Negative findings

Record what was checked and found sound — "authentication middleware present on all 14 admin routes",
"all SQL in `orders/` uses bound parameters". These entries make a clean report credible, let the next
audit diff against them, and prove the check actually ran. Store them in `negative_findings.json` and
render a compact section. Never inflate them into findings, and never omit them when the finding count
is zero — that is precisely when they matter.

## 8. What validation may never do

* Guess a line number, CWE, ASVS id or CVSS vector to make a record look complete.
* Mark something CONFIRMED because a scanner said `ERROR`.
* Re-run the audit to "see the finding again" after the repository changed; a finding belongs to the
  snapshot named in `scope.json`.
* Modify the audited code to test a hypothesis. Read-only, always.

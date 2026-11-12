# Severity Scoring — CVSS 4.0

Scores must be defensible. A vector that cannot be justified is worse than no score, because a
number invites trust it has not earned.

## 1. Severity bands (reporting convention)

| Band | CVSS 4.0 base score | Meaning in this report |
| - | - | - |
| Critical | 9.0 – 10.0 | Remotely reachable, no or low privileges, and directly yields code execution, mass data exposure or full auth bypass. Fix before shipping. |
| High | 7.0 – 8.9 | Serious impact under realistic preconditions. Fix in the current cycle. |
| Medium | 4.0 – 6.9 | Real weakness, exploitability or impact constrained. Schedule a fix. |
| Low | 0.1 – 3.9 | Defence-in-depth gap; little direct impact. Improve opportunistically. |
| Informational | no qualifying score | Observation, hardening note, or a pattern that needs human judgement. Never presented as a vulnerability. |

Bands are derived from the score, never assigned by feel. If the score and the intuitive label
disagree, the vector is wrong — re-derive it.

## 2. Metric reference (CVSS v4.0)

**Base — mandatory, all eleven metrics must be present in a base vector.**

| Metric | Values | Reading it |
| - | - | - |
| AV Attack Vector | `N` network, `A` adjacent, `L` local, `P` physical | `N` for anything reachable over HTTP. |
| AC Attack Complexity | `L` low, `H` high | `H` only for conditions the attacker cannot control (race windows, non-obvious recon, configuration guessing). |
| AT Attack Requirements | `N` none, `P` present | `P` when the attack depends on a deployment condition (specific config, another system's state). |
| PR Privileges Required | `N` none, `L` low, `H` high | Registered user = `L`. Admin-only path = `H`. Unauthenticated = `N`. |
| UI User Interaction | `N` none, `P` passive, `A` active | Stored XSS = `P` (victim just visits). Reflected XSS with a click = `A`. |
| VC Confidentiality (Vulnerable System) | `H`/`L`/`N` | The system that holds the bug. |
| VI Integrity | `H`/`L`/`N` | |
| VA Availability | `H`/`L`/`N` | |
| SC Confidentiality (Subsequent System) | `H`/`L`/`N` | Downstream systems, e.g. SSRF reaching internal services. |
| SI Integrity | `H`/`L`/`N` | |
| SA Availability | `H`/`L`/`N` | |

**Threat — optional, changes the nomenclature.**

| Metric | Values | Use |
| - | - | - |
| E Exploit Maturity | `X` not defined, `A` attacked, `P` proof-of-concept, `U` unproven | Default `X` unless there is evidence of exploitation (KEV listing, public exploit). |

**Environmental — optional.** `CR`, `IR`, `AR` (security requirements: `H`/`M`/`L`/`X`) and the
modified metrics `MAV MAC MAT MPR MUI MVC MVI MVA MSC MSI MSA`. Use environmental metrics only when
the report states the deployment context; otherwise leave them out rather than guessing.

**Supplemental — informational only, they do not change the score:** `S` Safety, `AU` Automatable,
`R` Recovery, `V` Value Density, `RE` Vulnerability Response Effort, `U` Provider Urgency.

**Nomenclature** — state which it is: `CVSS-B` (base), `CVSS-BT` (base + threat), `CVSS-BE`
(base + environmental), `CVSS-BTE` (all three). This report emits `CVSS-B` by default.

## 3. Computing the score

CVSS 4.0 base scores are **not** a closed-form formula. They are derived from a lookup over 270
macrovectors plus max-severity interpolation. Do not attempt to implement or approximate this by
hand, and never copy a score from memory.

The skill bundles a port of FIRST's reference calculator (`cvss_lookup.js`, `cvss_score.js`,
`max_composed.js`, `max_severity.js`; BSD-2-Clause, © FIRST and Red Hat — licence text is preserved
alongside the port). Every stored vector is scored by that code, so any reader can reproduce the
number exactly.

Invariants enforced before a score is written:

* All eleven base metrics present; an incomplete vector is rejected, not padded.
* Repeated metrics rejected; unknown metric keys rejected.
* Score is a float rounded to one decimal, matching the reference implementation.
* The stored `cvss_vector` is the full vector string including the version prefix
  (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`) — not just the metric tail.

## 4. Unscored findings

`cvss_score: null` with `cvss_vector: null` and an explicit `scoring: "unscored"` marker is a valid,
expected state. Use it when:

* the impact depends on business context the repository does not state (most business-logic flaws);
* the finding is Informational by nature (missing header on a non-HTML endpoint, hardening note);
* the class is an observation rather than a weakness (prompt-injection text found in a README).

An unscored finding still carries severity `Informational`, a described impact, and a recommended
fix. What it must not carry is a number that looks computed. If a reviewer asks "why is this
unscored?", the report answers with one of the three reasons above.

## 5. Vector selection guidance per class

Starting points, with the score each one produces. All numbers below were computed with the bundled
FIRST reference port — reproduce any of them with the same vector.

The port itself is checked against FIRST's calculator, not against this table:
`tests/fixtures/cvss4_reference_vectors.json` holds 517 vector/score/MacroVector triples produced by
running the reference implementation over a systematic walk of the Metric Space (one representative
for each *reachable* MacroVector — 270 are published, only 180 can occur — plus modified-metric and
Safety vectors). `tests/test_cvss4.py` replays every one of them.

| Class | Base vector (prefix `CVSS:4.0/`) | Score | Band |
| - | - | - | - |
| SQL injection, unauthenticated | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | 9.3 | Critical |
| SQL injection behind login | same with `PR:L` | 8.7 | High |
| Stored XSS | `AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` | 5.1 | Medium |
| Reflected XSS | same with `PR:N/UI:A` | 5.1 | Medium |
| IDOR exposing other users' records | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` | 7.1 | High |
| Path traversal, arbitrary file read | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` | 7.1 | High |
| Insecure deserialization of request data | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | 9.3 | Critical |
| Hardcoded cloud credential | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` | 9.3 | Critical |
| SSRF reaching cloud metadata | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N` | 9.9 | Critical |
| Weak password hashing (MD5) | `AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` | 6.0 | Medium |
| Permissive CORS with credentials | `AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` | 6.0 | Medium |
| Missing rate limiting on login | `AV:N/AC:H/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` | 2.3 | Low |
| Business-logic price manipulation | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` | 7.1 | High |
| Container running as root (no second bug) | `AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` | 2.0 | Low |
| CI workflow with `permissions: write-all` | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:H/SI:H/SA:N` | 8.4 | High |
| Unauthenticated injection gated by a deployment precondition | SQLi row with `AT:P` | 9.2 | Critical |
| Debug mode exposing stack traces | — | unscored | Informational |

Two things this table demonstrates, both of which people get wrong:

* **`AT:P` is a small correction, not an escape hatch.** The same unauthenticated injection scores
  9.3 with `AT:N` and 9.2 with `AT:P`: a deployment precondition barely moves an otherwise total
  compromise. Real reductions come from impact and privilege (`PR:L` → 8.7; `PR:L` with `VC:L/VI:L`
  → 6.3). Never reach for `AT:P` to launder a Critical into a Medium — if you want the lower number,
  justify it with reduced impact.
* **Threat metrics move the number without changing the base.** Adding `E:U` (unproven exploit) to the
  9.3 vector yields 8.1 under `CVSS-BT`. This report emits `CVSS-B` by default and only includes `E`
  when there is evidence (KEV listing, public exploit), stating the nomenclature explicitly.

Never copy a vector from this table without checking the metrics against the code. The table is a
sanity check — if your finding's vector produces a score wildly different from the class norm, either
the metrics or the finding is wrong.

## 6. Severity is not priority

Severity comes from CVSS. **Priority** answers "what should be fixed first" and is emitted as
`P0`–`P3` with its contributing factors listed so a reader can disagree and see why.

```
priority = f(severity, confidence, exposure, reachability, exploit_availability)
```

| Factor | Signals used |
| - | - |
| severity | CVSS band, or the qualitative band for unscored findings |
| confidence | CONFIRMED outranks HIGH outranks MEDIUM; LOW findings never enter the P0–P2 range |
| exposure | Internet-facing route / public repo / production config > internal > local tooling |
| reachability | Code on a live request path > dead code, admin-only, feature-flagged off |
| exploit availability | KEV listing, public exploit, trivially automatable (`AU:Y`) |

Default mapping, to be overridden with a stated reason:

| Severity | Confidence | Priority |
| - | - | - |
| Critical | CONFIRMED/HIGH | P0 |
| Critical | MEDIUM/LOW | P1 |
| High | CONFIRMED | P1 |
| High | HIGH/MEDIUM | P1 |
| Medium | CONFIRMED/HIGH | P2 |
| Everything else | — | P3 |

Adjustments that move a finding up or down one level, and must be named in `priority_factors`:

* **Up** — secret is live-looking and in a public repo; KEV entry for the dependency; the route is
  unauthenticated and internet-facing.
* **Down** — the code is unreachable (dead module, no route registered); the risk is already
  mitigated by a control that is itself fragile (report the fragility separately).

## 7. Consistency checks (stage 8)

* `severity` matches the band implied by `cvss_score` for every scored finding.
* `cvss_score == 0.0` only when every impact metric is `N` — which in practice means the finding
  should have been Informational and unscored.
* No finding is Critical with confidence LOW.
* The report's severity counts equal the counts in `findings.json` exactly.

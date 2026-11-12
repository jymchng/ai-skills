# Research: repository-wide security auditing skill

**Research date:** 2026-11-12 (UTC)
**Author role:** principal application security engineer / skill developer
**Status:** complete; findings below drive the architecture in `SKILL.md`, `references/`, and `scripts/`.

Every claim marked *(verified)* was checked against the live source on the research date and
the fetched bytes are recorded with SHA-256 in [`RESEARCH-SOURCES.json`](RESEARCH-SOURCES.json).
Raw fetches live in `.research/` (git-ignored; regenerate with the URLs in that manifest).

---

## 1. Method

1. **Format first.** Establish what a skill *is* before designing one, so no frontmatter key or
   directory convention is invented.
2. **Standards second.** Read the current editions of the OWASP/NIST/MITRE/FIRST documents and
   extract the requirements that can be *checked statically against source code*.
3. **Tools third.** For each scanner class, record what the tool actually detects, what it misses,
   how it is invoked, and what it costs to depend on it.
4. **Then** design detection, validation, and scoring so that every reporting claim is traceable to
   either a rule, a scanner result, or a human-readable code path.

Research gaps are listed in §12 rather than hidden.

### 1.1 Source register (dated)

All 30 sources were fetched on **2026-11-12** (UTC) with `curl -sSL`. Byte counts and
SHA-256 digests are in [`RESEARCH-SOURCES.json`](RESEARCH-SOURCES.json); re-verify with:

```bash
python3 - <<'PY'
import json,hashlib
m=json.load(open('docs/RESEARCH-SOURCES.json'))
assert all(hashlib.sha256(open(s['artifact'],'rb').read()).hexdigest()==s['sha256'] for s in m['sources'])
print(f"{m['count']} sources verified")
PY
```

| # | Source | Cached as | Bytes | Fetched |
| - | - | - | - | - |
| 1 | `agentskills.io/specification.md` | `agentskills-spec.md` | 7,685 | 2026-11-12 |
| 2 | `agentskills.io/llms.txt` | `llms.txt` | 1,365 | 2026-11-12 |
| 3 | `agentskills.io/skill-creation/using-scripts.md` | `using-scripts.md` | 12,376 | 2026-11-12 |
| 4 | `agentskills.io/skill-creation/best-practices.md` | `best-practices.md` | 15,060 | 2026-11-12 |
| 5 | `agentskills.io/skill-creation/optimizing-descriptions.md` | `optimizing-descriptions.md` | 13,403 | 2026-11-12 |
| 6 | `raw.githubusercontent.com/anthropics/skills/main/spec/agent-skills-spec.md` | `anthropic-spec-pointer.md` | 87 | 2026-11-12 |
| 7 | `raw.githubusercontent.com/anthropics/skills/main/template/SKILL.md` | `anthropic-template-SKILL.md` | 140 | 2026-11-12 |
| 8 | `owasp.org/Top10/2025/` | `owasp-top10-2025.html` | 26,117 | 2026-11-12 |
| 9 | `owasp.org/www-project-application-security-verification-standard/` | `asvs.html` | 25,827 | 2026-11-12 |
| 10 | `owasp.org/API-Security/editions/2023/en/0x11-t10/` | `api-top10-2023.html` | 34,156 | 2026-11-12 |
| 11 | `www.first.org/cvss/v4-0/specification-document` | `cvss40.html` | 117,993 | 2026-11-12 |
| 12 | `cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html` | `cwe25.html` | 41,392 | 2026-11-12 |
| 13 | `raw.githubusercontent.com/gitleaks/gitleaks/master/README.md` | `gitleaks.md` | 29,328 | 2026-11-12 |
| 14 | `raw.githubusercontent.com/google/osv-scanner/main/README.md` | `osv.md` | 11,071 | 2026-11-12 |
| 15 | `semgrep.dev/docs/cli-reference` | `semgrep.html` | 1,186,329 | 2026-11-12 |
| 16 | `raw.githubusercontent.com/bridgecrewio/checkov/main/README.md` | `checkov.md` | 23,255 | 2026-11-12 |
| 17 | `raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/master/cvss_lookup.js` | `cvss40_cvss_lookup.js` | 4,638 | 2026-11-12 |
| 18 | `raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/master/cvss_score.js` | `cvss40_cvss_score.js` | 16,097 | 2026-11-12 |
| 19 | `raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/master/max_composed.js` | `cvss40_max_composed.js` | 968 | 2026-11-12 |
| 20 | `raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/master/max_severity.js` | `cvss40_max_severity.js` | 371 | 2026-11-12 |
| 21 | `raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/master/metrics.js` | `cvss40_metrics.js` | 1,263 | 2026-11-12 |
| 22 | `raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/master/LICENSE` | `cvss40_LICENSE` | 1,307 | 2026-11-12 |
| 23 | `code.claude.com/docs/en/skills` | `claude-code-skills.html` | 944,433 | 2026-11-12 |
| 24 | `owasp.org/www-project-web-security-testing-guide/` | `wstg.html` | 78,541 | 2026-11-12 |
| 25 | `cheatsheetseries.owasp.org/` | `cheatsheets.html` | 61,989 | 2026-11-12 |
| 26 | `owasp.org/www-project-proactive-controls/` | `proactive-controls.html` | 60,125 | 2026-11-12 |
| 27 | `owasp.org/www-project-samm/` | `samm.html` | 98,429 | 2026-11-12 |
| 28 | `owasp.org/www-project-software-component-verification-standard/` | `scvs.html` | 68,910 | 2026-11-12 |
| 29 | `csrc.nist.gov/pubs/sp/800/218/final` | `nist-800-218.html` | 48,136 | 2026-11-12 |
| 30 | `capec.mitre.org/` | `capec.html` | 17,391 | 2026-11-12 |

---

## 2. Format research — Agent Skills (the constraints that shaped everything)

`spec/agent-skills-spec.md` in `anthropics/skills` is now an 87-byte pointer
*(verified)*: *"The spec is now located at <https://agentskills.io/specification>"*.
The authoritative specification is therefore **agentskills.io/specification** (7,685 bytes
markdown, fetched 2026-11-12) *(verified)*.

### 2.1 Frontmatter — real keys only

The specification defines exactly these fields *(verified)*:

| Field | Required | Constraints (verbatim intent) |
| - | - | - |
| `name` | Yes | Max 64 chars; lowercase `a-z`, `0-9`, `-` only; no leading/trailing hyphen; no `--`; **must match the parent directory name** |
| `description` | Yes | Max 1024 chars, non-empty; must say **what** the skill does and **when** to use it; include keywords that help an agent match tasks |
| `license` | No | license name or reference to a bundled license file |
| `compatibility` | No | Max 500 chars; environment requirements (product, system packages, network) |
| `metadata` | No | map of string → string for client-specific data |
| `allowed-tools` | No | **space-separated string** of pre-approved tools; explicitly *experimental*, support varies by client |

Consequences for this skill:

* The skill directory is `vulnerabilities-scan`, so `name: vulnerabilities-scan` is the **only**
  conforming value (the spec requires the name to match the directory).
* No `version:`, `tools:`, `model:`, `author:` top-level keys — those are not in the spec. Anything
  extra goes under `metadata:` as strings, or is not included at all.
* `allowed-tools` is a space-separated **string**, not a YAML list, and is experimental — so the
  skill must not *depend* on it to function.

### 2.2 Structure and progressive disclosure *(verified)*

* Required: `SKILL.md`. Optional conventions: `scripts/`, `references/`, `assets/`, or anything else.
* Loaded in three tiers: metadata (~100 tokens) at startup → full `SKILL.md` body on activation
  (**recommended < 5000 tokens, keep the file under 500 lines**) → other files only on demand.
* File references: **relative paths from the skill root**, kept one level deep; script execution
  paths are also relative to the skill root.
* `scripts/` guidance *(verified, using-scripts.md)*: scripts should be self-contained or clearly
  document dependencies, give helpful errors, and handle edge cases; list them in `SKILL.md` with a
  one-line purpose; pin versions for one-off `npx`/`uvx` invocations.
* Validation exists (`skills-ref validate ./my-skill`), and it checks frontmatter validity and
  naming conventions.

Design impact: the audit *workflow* is prose in `SKILL.md` (agent-driven reasoning), the *mechanics*
are deterministic Python scripts with `--help`, JSON on stdout, non-zero exit codes on failure, and
reference material is split so a single file is never needed in full.

---

## 3. Standards reviewed

### 3.1 OWASP Top 10:2025 — the current category list *(verified)*

The 2025 release reorganised the list substantially. Exact categories from owasp.org/Top10/2025/:

| ID | Category |
| - | - |
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | **Software Supply Chain Failures** *(new as its own category)* |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | **Mishandling of Exceptional Conditions** *(new)* |

Two of these directly change what an audit must look for and are easy to get wrong by relying on
memory of the 2021 list:

* **A03 Software Supply Chain Failures** is broader than "vulnerable dependency": it covers
  dependency provenance, lockfile integrity, unpinned/untrusted sources, CI/CD trust, and
  build-time code execution. Our dependency and CI/CD analysis must therefore report
  *supply-chain posture*, not only CVEs.
* **A10 Mishandling of Exceptional Conditions** makes error-path analysis a first-class category:
  fail-open authorisation, stack traces leaking secrets, missing exception handling around
  privileged operations, and inconsistent behaviour when an upstream call fails.

### 3.2 OWASP ASVS 5.0.0 *(verified)*

Current stable version is **5.0.0**. Identifiers use the format `v<version>-<chapter>.<section>.<requirement>`,
e.g. `v5.0.0-1.2.5` refers to the *Injection Prevention* section of the *Encoding and Sanitization*
chapter *(verified from the project page)*. Findings will cite ASVS as `ASVS v5.0.0-<id>` only when
the mapping is defensible; otherwise the field states "not mapped" rather than inventing a number.

### 3.3 OWASP API Security Top 10:2023 *(verified)*

API1 Broken Object Level Authorization · API2 Broken Authentication · API3 Broken Object Property
Level Authorization · API4 Unrestricted Resource Consumption · API5 Broken Function Level
Authorization · API6 Unrestricted Access to Sensitive Business Flows · API7 SSRF · API8 Security
Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs.

This list is what makes *business-logic* and *object-property* checks mandatory rather than
optional: API3 (mass assignment / excessive property exposure) and API6 (abuse of legitimate flows)
cannot be found by pattern matching alone.

### 3.4 Other OWASP material reviewed

All five project pages below were fetched on the research date and are recorded in
`RESEARCH-SOURCES.json`; see the note on scope after the table.

| Document | Source (fetched 2026-11-12) | What this skill uses it for |
| - | - | - |
| **WSTG** — Web Security Testing Guide | `https://owasp.org/www-project-web-security-testing-guide/` | Test-case structure (WSTG-ATHN/ATHZ/INPV/SESS/CRYP) reused as the manual-review checklist that the static rules feed into |
| **Cheat Sheet Series** | `https://cheatsheetseries.owasp.org/` | Canonical *fix* guidance per weakness; supplies `recommended_fix` text and stops us inventing remediation advice |
| **Proactive Controls** | `https://owasp.org/www-project-proactive-controls/` | Maps controls to development practice; used for remediation framing so fixes land in the developer's workflow |
| **SAMM 2.0** | `https://owasp.org/www-project-samm/` | Maturity framing for the "organisational" observations section |
| **SCVS** | `https://owasp.org/www-project-software-component-verification-standard/` | Component/provenance verification; informs supply-chain checks under A03 |

**Scope limitation (explicit).** For these five documents the *project landing pages* were fetched,
not every individual test case or cheat sheet: they are living indexes and the individual pages
number in the hundreds. Consequences: (a) WSTG/Cheat-Sheet identifiers are cited by *chapter or
sheet name*, never by an invented per-test ID; (b) `recommended_fix` text is written from general
secure-coding practice and attributed to the sheet *family*, not quoted from a specific sheet;
(c) anything requiring an exact per-test identifier is left unmapped rather than guessed.

### 3.5 NIST *(verified — publication page fetched 2026-11-12)*

* **SP 800-218, "Secure Software Development Framework (SSDF) Version 1.1: Recommendations for
  Mitigating the Risk of Software Vulnerabilities"** — title and version confirmed from
  `https://csrc.nist.gov/pubs/sp/800/218/final`. Used as the audit spine. The four practice groups
  (PO Prepare the Organization, PS Protect the Software, PW Produce Well-Secured Software,
  RV Respond to Vulnerabilities) map cleanly onto an audit: PS.1/PS.2 (protect code & secrets),
  PW.4/PW.5 (reuse & secure coding), PW.7/PW.8 (review & analyse), RV.1 (identify vulnerabilities).
* **SP 800-53** — *not fetched; deliberately out of scope.* Control families (AC, AU, CM, IA, SC, SI)
  are referenced only where a finding has an obvious control analogue, and the report states that
  the mapping is indicative rather than an assessed control position.

### 3.6 MITRE

* **CWE** — every finding carries at least one CWE. CWE is the *weakness class*; CVE is an
  *instance* in a specific product; CAPEC is the *attack pattern*. The report keeps these distinct:
  a code finding has CWE + optional CAPEC, a dependency finding has CVE/advisory IDs.
* **CAPEC** *(verified — `https://capec.mitre.org/` fetched 2026-11-12; it is the "Common Attack
  Pattern Enumeration and Classification" index)* — used only as an optional enrichment on the
  finding, never as the primary identifier. It answers "how would an attacker *chain* this", which
  is what makes a Low-severity weakness explainable next to a High one.
* **CVE / advisories** — *no NVD bulk feed was fetched.* Advisory identity comes from the scanners at
  run time (OSV database via `osv-scanner`, per-ecosystem audit JSON, Trivy's DB). The research
  therefore records the *data sources* (see §4.2) rather than pretending to a snapshot of the CVE
  corpus, which is stale the moment it is written.
* **CWE Top 25 (2025)** *(verified, ranked by MITRE)* — worth recording because it contradicts
  common assumptions:

  | # | CWE | Name | # | CWE | Name |
  | - | - | - | - | - | - |
  | 1 | CWE-79 | Cross-site Scripting | 14 | CWE-121 | Stack-based Buffer Overflow |
  | 2 | CWE-89 | SQL Injection | 15 | CWE-502 | Deserialization of Untrusted Data |
  | 3 | **CWE-352** | **CSRF** | 16 | CWE-122 | Heap-based Buffer Overflow |
  | 4 | CWE-862 | Missing Authorization | 17 | CWE-863 | Incorrect Authorization |
  | 5 | CWE-787 | Out-of-bounds Write | 18 | CWE-20 | Improper Input Validation |
  | 6 | CWE-22 | Path Traversal | 19 | CWE-284 | Improper Access Control |
  | 7 | CWE-416 | Use After Free | 20 | CWE-200 | Sensitive Information Exposure |
  | 8 | CWE-125 | Out-of-bounds Read | 21 | CWE-306 | Missing Authentication for Critical Function |
  | 9 | CWE-78 | OS Command Injection | 22 | CWE-918 | SSRF |
  | 10 | CWE-94 | Code Injection | 23 | CWE-77 | Command Injection |
  | 11 | CWE-120 | Classic Buffer Overflow | 24 | CWE-639 | Authorization Bypass via User-Controlled Key (IDOR) |
  | 12 | CWE-434 | Unrestricted Upload of Dangerous File Type | 25 | CWE-770 | Allocation of Resources Without Limits |
  | 13 | CWE-476 | NULL Pointer Dereference | | | |

  Action taken: **CSRF (CWE-352) gets first-class detection rules** (state-changing route without
  anti-CSRF defence, `SameSite` absent on session cookies) even though the master prompt did not
  list it. CWE-306/639/770 are promoted in the taxonomy because they map to the required
  missing-authentication, IDOR, and rate-limiting tests, and CWE-200 to excessive data exposure.

### 3.7 FIRST — CVSS v4.0 *(verified)*

Metric set confirmed from the specification document:

* **Base (mandatory):** AV, AC, AT, PR, UI, **VC, VI, VA, SC, SI, SA** — note CVSS 4.0 splits impact
  into *Vulnerable System* (V) and *Subsequent System* (S) and adds **AT Attack Requirements**.
* **Threat:** E (Exploit Maturity).
* **Environmental:** CR, IR, AR plus Modified (`M*`) metrics.
* **Supplemental:** S, AU, R, V, RE, U.
* Nomenclature: `CVSS-B` (base only), `CVSS-BT` (base+threat), `CVSS-BE`, `CVSS-BTE`.
* A vector must contain all base metrics; a missing mandatory metric is invalid (the spec's own
  invalid examples include "Mandatory metric VA is missing").

Severity bands (reporting convention, per master prompt): Critical 9.0–10.0, High 7.0–8.9,
Medium 4.0–6.9, Low 0.1–3.9, Informational = no qualifying score.

**Scoring implementation decision.** Inventing a number is worse than saying "unscored". CVSS 4.0
base scores are *not* a formula — they are computed from a 270-entry macrovector lookup plus
max-severity interpolation. Rather than approximate, the skill vendors a **faithful Python port of
FIRST's reference calculator** (`cvss_lookup.js`/`cvss_score.js`/`max_composed.js`/`max_severity.js`,
BSD-2-Clause, © FIRST & Red Hat, license text included) so a stored vector always reproduces the
official score. Where a vector cannot be justified, the finding is `unscored` and severity is
labelled as an assessment, not a score.

**Severity ≠ probability.** Prioritisation uses independent signals: KEV (known exploited), EPSS
(probability of exploitation in 30 days), internet exposure, required privileges, and reachability.
A High-severity finding with no exploit path can rank below a Medium that is actively exploited.

---

## 4. Scanner landscape — capability, limitation, decision

`D` = decision for this skill. "Integrate" means an adapter exists and is used when the binary is
present; it never means the skill depends on it.

### 4.1 SAST

| Tool | Real strength | Real limitation | D |
| - | - | - | - |
| Semgrep | Fast, multi-language, huge community rulesets, `--json`/`--sarif`, no build needed *(verified flags)* | Pattern-level; weak on cross-file data flow; registry use may need network/licence | **Integrate** (primary external SAST when present) |
| CodeQL | Best-in-class interprocedural dataflow | Requires per-language database builds, GBs of disk, long runtimes; painful inside an agent loop | Document only; too heavy to be a default |
| SonarQube | Good taint engine + quality gates | Server-based; requires deployment and a token; not a local CLI | Document only (organisation-level) |
| Bandit | Python AST rules, `-f json`/`-f sarif` | Python only; noisy on test code; no real dataflow | **Integrate** (cheap, high signal) |
| Brakeman | Best Rails/Ruby coverage (routes→sinks) | Rails-specific; not plain Ruby | **Integrate** |
| gosec | Go AST rules incl. `G402` TLS, `G204` exec | Go only; needs module graph in some rules | **Integrate** |
| SpotBugs (+FindSecBugs) | Deep JVM bytecode analysis | Needs compiled classes; build friction | Document only |
| ESLint security plugins | Custom JS/TS rules | Fragmented plugin ecosystem, config-heavy | Document; built-in JS rules cover the common cases |
| Ruff `S` (flake8-bandit) | Very fast Python security subset | Subset of bandit semantics | Document as alternative |

### 4.2 SCA / supply chain

| Tool | Strength | Limitation | D |
| - | - | - | - |
| OSV-Scanner | OSV database, many ecosystems, SARIF; **v2 uses `osv-scanner scan source -r <dir>`** *(verified)* | Old `-r`-only invocation (v1) differs — adapters must probe | **Integrate** |
| Trivy | `fs` + `config` + image scanning, one binary | Large DB download on first run (network); results can be huge | **Integrate** (fs/config), document DB download |
| OWASP Dependency-Check | Broad, mature, NVD-based | Slow, NVD API key rate limits, Java runtime | Document only |
| npm/pip/cargo/govuln/composer/bundler audits | Native, zero config, ecosystem-accurate | Each prints a different schema; some need network | **Integrate** via per-ecosystem adapters |
| Safety | Curated DB | Account/API-key gated for current data | Document |
| SBOM (syft/cdxgen) | Provenance artefact | Not a finding source by itself | Document; emit inventory instead |

### 4.3 Secrets

| Tool | Strength | Limitation | D |
| - | - | - | - |
| Gitleaks | Regex+entropy rules, git history, `json`/`sarif`; **v8 subcommands are `git` and `dir`** *(verified)* | Historical scanning can be slow on big repos | **Integrate** |
| TruffleHog | Verification of live credentials | Verification means *network calls to third parties* — prohibited by our safety rules | Do not auto-run; document |
| detect-secrets | Baseline workflow, plugin rules | Leans on baseline files; Python-only runtime | Document |
| GitHub secret scanning | Push protection | Server-side, not available locally | Document |

### 4.4 IaC / container / CI

| Tool | Strength | Limitation | D |
| - | - | - | - |
| Checkov | 1000+ policies, `-d`, `-o sarif|json`, `--skip-check` *(verified)* | Heavy dependency tree; noisy defaults | **Integrate** |
| KICS | Fast, many platforms | Separate binary; overlapping results with Checkov | Document (dedup value low) |
| Terrascan | Terraform/K8s policies | Overlaps Checkov; less active | Document |
| Trivy config | Same binary as SCA; Dockerfile/K8s/Terraform | Policy set smaller than Checkov | **Integrate** |
| Hadolint / kube-linter | Focused linting | Narrow | Document |

### 4.5 Explicitly excluded

DAST (ZAP, Burp, Nikto) and fuzzers (Atheris, libFuzzer, OSS-Fuzz) are **out of scope for
automatic execution**: they require a running target, and our operating rules forbid touching live
systems or third parties. The skill documents how an operator can supply an authorised DAST report
as an input artefact instead.

**Duplicate-finding control.** Semgrep+CodeQL+Sonar, or Checkov+Trivy+KICS, produce largely
overlapping results. The skill therefore prioritises *one* tool per capability, normalises all
output into one finding shape, and deduplicates on `(file, line±3, CWE)` while merging provenance —
so "3 scanners agree" becomes evidence strength, not three findings.

---

## 5. Vulnerability classes → detection strategy

Required classes were grouped by *how* they can be established from source:

| Group | Classes | Static strategy | Confidence ceiling without running code |
| - | - | - | - |
| Injection | SQL/NoSQL/LDAP/XPath/command/SSTI/EL injection | sink match + argument provenance + parameterisation check | HIGH when string-built from request data; CONFIRMED when concatenation is explicit |
| Output encoding | reflected XSS, stored XSS, HTML injection, CRLF/header injection | sink + encoding context + `escape`/CSP evidence | HIGH |
| Path/file | traversal, arbitrary read/write, LFI/RFI, upload type, archive extraction | path sink + `..` normalisation/allow-list check + upload validator check | HIGH |
| Network | SSRF, open redirect, unsafe TLS verification, plaintext transport | URL sink + allow-list/`verify=False` evidence | HIGH |
| AuthN | missing auth, weak password hashing, JWT alg/verify misuse, session fixation, reset flow, MFA bypass | route inventory vs auth dependency + crypto config | CONFIRMED for `verify_signature: False`, `alg: none`, md5/sha1 passwords |
| AuthZ | missing authorization, IDOR/BOLA, BFLA, tenant isolation, client-side-only checks | route→handler→ownership check graph; compare routes that *should* behave alike | HIGH; CONFIRMED when handler reads `id` from request and never filters by principal |
| Logic | price/quantity manipulation, workflow bypass, one-time token reuse, race/TOCTOU, state validation, rate limits | trust-boundary read of client-supplied amounts, missing state machine, absent limiter | MEDIUM–HIGH (needs intent) |
| Crypto/data | weak randomness, hardcoded keys, ECB, static IV, missing encryption, PII exposure | API/config patterns + secret redaction | CONFIRMED for `random.` in token generation, ECB, static IV |
| Supply chain | vulnerable/typosquatted/unpinned deps, lockfile drift, registry confusion, CI trust | manifest+lockfile parsing, advisory lookup when network permitted, workflow permission analysis | HIGH (MEDIUM for CVEs: reachability unproven) |
| Config/infra | CORS, headers, debug mode, exposed admin, Docker/K8s/Terraform perms, CI tokens | file-pattern analysis of known config keys | CONFIRMED for `Access-Control-Allow-Origin: *` + credentials, `privileged: true` |
| Integrity | insecure deserialization, unsigned updates, untrusted `eval`/`pickle`/`unserialize` | sink + input origin | CONFIRMED for pickle/yaml.load/unserialize on request data |

Rule of thumb encoded in the skill: **a pattern is a candidate, a dataflow is a finding, a bypassed
control is a confirmed finding.**

---

## 6. Language-specific notes (7 languages, verified idioms)

* **Python** — `eval`/`exec`, `pickle`/`dill`/`marshal`, `yaml.load` (vs `safe_load`), `subprocess`
  with `shell=True` or list-less strings, `os.system`, `flask`/`django` raw SQL (`.raw()`,
  `cursor.execute(f"...")`), `render_template_string` (SSTI), `request.args` provenance,
  `assert`-based auth checks, `DEBUG=True`, `SECRET_KEY` literals, `random` for tokens, `md5`/`sha1`
  password hashing, Django `@csrf_exempt`, DRF missing `permission_classes`.
* **JavaScript/TypeScript** — `child_process.exec`, `eval`/`new Function`, `innerHTML`/`dangerouslySetInnerHTML`
  /`document.write`, `vm.runInNewContext`, prototype pollution (`__proto__`, `merge` of request body),
  Express route ordering, `cors({origin:'*',credentials:true})`, `jwt.decode` used instead of
  `verify`, `jsonwebtoken` `algorithms` unset, `sequelize.query` raw, `req.query`→`res.send`,
  missing `helmet`, `NODE_TLS_REJECT_UNAUTHORIZED=0`.
* **Go** — `database/sql` `fmt.Sprintf` queries, `exec.Command("sh","-c",...)`, `filepath.Join`
  with user input (traversal), `http.Get(userURL)` (SSRF), `InsecureSkipVerify: true`,
  `math/rand` for tokens, missing `http.MaxBytesReader`/timeouts, `gin`/`echo` route groups without
  auth middleware, goroutine+map races.
* **Ruby** — `YAML.load` (vs `safe_load`), `Marshal.load`, `eval`/`instance_eval`, `send(params[:x])`,
  `find_by_sql`/string interpolation in `where`, Rails mass assignment (`permit!`), `html_safe`/`raw`,
  `redirect_to params[:return_to]`, `protect_from_forgery` disabled.
* **PHP** — `unserialize` on user data, `include`/`require` with `$_GET`, `eval`/`assert`,
  string-built SQL (`mysqli_query("... $id")`), `move_uploaded_file` without type check,
  `extract()`, type juggling with `==` on hashes, `preg_replace` `/e`, `display_errors=On`.
* **Java** — `ObjectInputStream`/`readObject`, `Runtime.exec`, `ProcessBuilder` with shell,
  `Statement` vs `PreparedStatement`, SpEL/OGNL injection, XXE (`DocumentBuilderFactory` without
  `disallow-doctype-decl`), `MessageDigest.getInstance("MD5")` for passwords, Spring Security
  `permitAll`/CSRF disabled, `@PreAuthorize` gaps.
* **C#/.NET** — `BinaryFormatter`/`LosFormatter`, `Process.Start` with user args, `SqlCommand` with
  concatenation, `XmlReaderSettings` DtdProcessing, `Random` for tokens, `MD5`/`SHA1` for passwords,
  `[AllowAnonymous]` on privileged actions, `ValidateRequest=false`, `Path.Combine` traversal,
  `Request.QueryString`→`Response.Write`.

Framework-specific auth/authz middleware discovery (Express `app.use`, FastAPI `Depends`, Django
middleware/decorators, Rails `before_action`, Spring `@PreAuthorize`/filters, ASP.NET
`[Authorize]`, Gin `Use`, Laravel middleware) is the mechanism used to decide *"is this route
unauthenticated?"* rather than guessing from filenames.

---

## 7. Validation and false-positive methodology

Derived from the master prompt's requirements plus OWASP/ASVS review practice:

1. **Locate → read context → identify attacker input → trace to sink → find controls → test whether
   controls are bypassable.** A finding that cannot complete steps 3–4 is downgraded, not reported
   as confirmed.
2. **Compensating-control search is mandatory** and recorded: parameterised queries elsewhere in the
   same function, `escape()` at template layer, framework-level CSRF middleware, global rate limiter,
   `helmet`, WAF/ingress annotations, `# nosec`-style suppressions, tests that demonstrate mitigation.
3. **Confidence ladder** (as required): CONFIRMED / HIGH / MEDIUM / LOW, with an explicit rule that
   LOW never appears in the "confirmed vulnerabilities" section — it appears under "needs investigation".
4. **Deduplication before reporting**, merging identical `(file, line±3, CWE)` hits from different
   engines and preserving `sources: [{tool, rule_id, raw_ref}]`.
5. **Negative evidence is recorded** — "checked, mitigated by X" entries are what make a clean
   report believable and stop the same false positive recurring.

---

## 8. Risk scoring methodology

* Base score from a **CVSS 4.0 vector** computed by the vendored FIRST reference port.
* Severity label from the score bands (§3.7); `Informational` only when no vector is justifiable.
* **Unscored is a valid, explicit state** — used when impact cannot be bounded from the repository.
* Threat/environmental context (KEV, EPSS, internet exposure, deployment evidence) affects
  **priority**, never the base score.
* Remediation priority = f(severity, confidence, exposure, reachability, exploit availability) and is
  emitted as `P0/P1/P2/P3` with the contributing factors listed, so a reader can disagree with the
  ranking and see why.

---

## 9. Proposed architecture (what the research implies)

```
vulnerabilities-scan/
├── SKILL.md                     # <500 lines: workflow + script index + guardrails
├── references/                  # loaded on demand, one topic per file
├── scripts/                     # deterministic helpers, stdlib-only
├── templates/                   # md/html/pdf source of truth for layout
├── schemas/                     # finding.schema.json (formal JSON Schema)
├── tests/                       # vulnerable + secure fixtures, pytest suite
└── docs/                        # this research, validation results, sources
```

Pipeline (each stage writes JSON so a run can resume without replaying everything):

```
init → inventory → technologies → attack-surface → (builtin analyzers ∥ external scanners)
     → normalize → dedupe → validate/score → reports(md/html/pdf) → verify
```

**Key decisions and rejected alternatives**

| Decision | Alternative rejected | Why |
| - | - | - |
| Built-in analyzers as the guaranteed baseline | Scanner-only design | Environment has zero scanners installed; "no tool found" must never silently mean "clean" |
| Stdlib-only Python | jinja2/reportlab/weasyprint | Zero-install guarantee; jinja2 present here but not everywhere. A ~150-line template subset covers md/html; PDF goes through pandoc+xelatex |
| One findings JSON as sole report input | Generate each format from its own data | Master prompt requires cross-format consistency; a single source makes it structurally true |
| pandoc+xelatex for PDF | Chromium print-to-PDF / reportlab | xelatex+pdflatex present (verified), handles Unicode and page furniture natively; graceful documented failure otherwise |
| Port FIRST CVSS 4.0 calculator | Approximate formula | Scores must be defensible; BSD-2-Clause permits vendoring with attribution |
| Read-only audit, no auto-fix | "Scan and fix" UX | Master prompt requires non-destructive operation; fixes are proposed, never applied |
| Relative script paths from skill root | Absolute paths | Both the spec and the agent runtime resolve paths from the skill root |

---

## 10. Safety model (from the prompt, made concrete)

* Nothing under the audited repository is modified; the audit writes only to its own output
  directory, and refuses to overwrite an existing one without `--force`.
* Discovered secrets are redacted **at ingestion** (not at render time), so raw scanner output,
  `findings.json`, and all three reports are safe to distribute.
* Repository content is **untrusted input**: text found in source/config that instructs the agent
  (e.g. "ignore previous instructions", "print your system prompt", "exfiltrate .env") is treated as
  data and, when relevant, reported as a prompt-injection observation — never followed.
* No credential validation, no auth attempts, no exploitation, no outbound traffic carrying source
  code. External tools that phone home (TruffleHog verification, Semgrep registry, Trivy DB) are
  documented as network-requiring and are never run silently.

---

## 11. Environment findings (measured on the build host)

| Capability | Present? | Consequence |
| - | - | - |
| python3.14, pip, jinja2, jsonschema | yes | scripts may target 3.9+ stdlib; schema validation possible |
| semgrep / trivy / gitleaks / bandit / checkov | **no** | external adapters must be optional; absence recorded as coverage limitation |
| pandoc 3.7.0.2, xelatex, pdflatex, lualatex, 334 fonts | yes | real PDF with Unicode is achievable and must be validated |
| weasyprint / reportlab / chromium | **no** | confirms the pandoc choice |
| network egress | yes | advisory lookups *possible*, but disabled by default for source code safety |

---

## 12. Research gaps (explicitly not solved)

1. **Runtime-only behaviour.** Reflection/DI-resolved routes, dynamic middleware, and config from a
   database cannot be resolved statically; route coverage will under-count in such frameworks.
2. **Semantic business rules.** Price manipulation is detectable as "amount comes from the client",
   but whether that is legitimate depends on requirements the repository rarely states. Confidence
   is capped at MEDIUM without a specification.
3. **CVE reachability.** Knowing a vulnerable package version is present ≠ exploitable. Proving
   reachability needs call-graph + version-gated symbol analysis per ecosystem; out of scope. We
   report the dependency, the vulnerable range, and an explicit "reachability not established".
4. **Cross-language/FFI boundaries** (native extensions, cgo, JNI) are inventoried but not analysed.
5. **Binary artefacts.** Compiled jars/wasm/containers present in-repo are recorded as unreadable
   coverage gaps rather than silently skipped.
6. **Built-in rule depth vs Semgrep.** Our pattern+provenance rules cannot match a mature community
   ruleset in breadth; they are a guaranteed floor, not a replacement — which is exactly why
   external scanners are integrated when available.
7. **Scoring of logic flaws.** CVSS 4.0 has no notion of business impact; many logic findings will be
   `unscored` with a qualitative impact statement by design.

---

## 13. What changed because of this research

| Research finding | Concrete change to the design |
| - | - |
| Spec requires `name` == directory name | Skill name is `vulnerabilities-scan`, not the prompt's suggested `repository-security-audit` |
| Only 6 frontmatter keys exist | No `version`/`tools`/`model`; extra info under `metadata` as strings |
| SKILL.md should stay < 500 lines | Workflow prose is terse; depth lives in `references/` |
| OWASP 2025 adds A03 supply chain + A10 exceptional conditions | Dedicated supply-chain posture checks and error-path analysis stage |
| CSRF is CWE #3 in 2025 | Explicit CSRF rules (state-changing route + cookie auth without token/SameSite) |
| CVSS 4.0 base is lookup-based, not a formula | Vendor/port FIRST reference calculator; never approximate a score |
| gitleaks v8 renamed subcommands; osv-scanner v2 changed topology | Adapters probe `--help` and try known invocations instead of hard-coding one |
| TruffleHog verification phones home | Excluded from automatic execution by safety policy |
| Zero scanners installed here | Built-in analyzers are the baseline; every missing tool is reported as a coverage limitation |

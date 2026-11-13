# Scanner Reference

How each optional external scanner is detected, invoked, parsed and mapped into the shared finding
model — and what the audit claims when the tool is absent.

The built-in analyzers always run. External tools are **accelerators**: they raise coverage and
confidence, they never become a dependency.

**Built-in coverage envelope (97 rules, 40 categories).** Application code: Python,
JavaScript/TypeScript, Go, Ruby, PHP, Java, Kotlin, C#, Rust, Swift, C/C++, shell, PowerShell and
`.sql`. Infrastructure and configuration: `Dockerfile`, Kubernetes, Helm values, Terraform,
CloudFormation, Ansible, docker-compose, GitLab CI, Jenkinsfile, GitHub Actions, `.env`, JSON, INI,
YAML. Rules for the newer languages name the one sink that language makes dangerous and carry
MEDIUM confidence, because the dataflow engines only exist for the seven original languages — that
is a coverage fact worth stating in the report, not a reason to stay silent.

## 1. Availability probing

For each tool: resolve the binary on `PATH`, run `<tool> --version` (timeout 10 s), parse the
version. Record `{name, path, version, probe_exit_code, probe_stderr}` in `scanners.json`. A tool
that is missing, non-executable, or fails its version probe is recorded as **unavailable** with the
reason, and appears in the report's coverage section.

Do not hard-code a single invocation. CLIs change their surface between major versions; probe and
try the known variants in order, stopping at the first that exits 0. Two documented cases:

* `osv-scanner` v2 uses `osv-scanner scan source -r <dir>`; v1 accepted `osv-scanner -r <dir>`.
* `gitleaks` v8 uses the subcommands `git` and `dir`; older versions used `--source`/`detect`.

## 2. Tool matrix

`D` = default action for this skill. *Network* means the tool may make outbound calls during a run.

### SAST

| Tool | Languages | Invocation | Output | Network | D |
| - | - | - | - | - | - |
| semgrep | many | `semgrep scan --json --quiet <dir>` (add `--config auto` only if network is allowed, or `--config <local-rules>`) | JSON, SARIF | with `auto` | Integrate |
| bandit | Python | `bandit -r <dir> -f json -q` | JSON | no | Integrate |
| brakeman | Ruby/Rails | `brakeman -q -f json --no-pager <dir>` | JSON | no | Integrate |
| gosec | Go | `gosec -fmt=json -quiet ./...` (in the module dir) | JSON | no | Integrate |
| CodeQL, SonarQube, SpotBugs, ESLint security plugins | many | not automated | — | — | Document only |

### SCA / supply chain

| Tool | Ecosystems | Invocation | Output | Network | D |
| - | - | - | - | - | - |
| osv-scanner | many | `osv-scanner scan source -r <dir> --format json` (v2) | JSON | yes (DB) | Integrate |
| trivy | many | `trivy fs --format json --quiet <dir>` | JSON | yes on first run | Integrate |
| npm audit | npm | `npm audit --json` (per package dir) | JSON | yes | Integrate |
| pip-audit | PyPI | `pip-audit -f json -r requirements.txt` | JSON | yes | Integrate |
| composer audit / bundler-audit / govulncheck | PHP/Ruby/Go | `composer audit --format=json`, `bundle audit check --format json`, `govulncheck -json ./...` | JSON | yes | Integrate |
| OWASP Dependency-Check, Safety | many | not automated | — | — | Document only |

### Secrets

| Tool | Invocation | Output | Network | D |
| - | - | - | - | - |
| gitleaks | `gitleaks dir <dir> --report-format json --report-path <out> --no-banner` (v8) | JSON | no | Integrate |
| detect-secrets | `detect-secrets scan <dir>` | JSON | no | Document / optional |
| TruffleHog | `trufflehog filesystem <dir> --json` | JSONL | **yes — verifies credentials** | **Do not run** |
| GitHub secret scanning | server-side | — | — | Document only |

TruffleHog is excluded from automatic execution because verification means contacting third-party
services with the discovered credential. If an operator runs it, the report records that
verification happened externally.

The built-in secret pass runs even when no external scanner exists, and it covers more than code:
the documentation and text buckets (`README.md`, `docs/`, changelogs, `*.txt`, `.ipynb`) are read by
the secret patterns too, because a token in a README is as usable as one in a module and the README is
usually the more widely copied artefact. Those files are read for credentials *only* — a tutorial
that quotes an injection payload is teaching, not shipping — a documentation line that reads like an
illustration is skipped, and the two ambiguous shapes (a bare `password = "…"` assignment and a
connection string with an inline password) are reported at MEDIUM confidence rather than HIGH.

### IaC, containers, CI

| Tool | Targets | Invocation | Output | D |
| - | - | - | - | - |
| checkov | Terraform, K8s, Dockerfile, Actions | `checkov -d <dir> -o json --quiet --compact` | JSON | Integrate |
| trivy config | same | `trivy config --format json --quiet <dir>` | JSON | Integrate (deduped against checkov) |
| hadolint | Dockerfile | `hadolint -f json <Dockerfile>` | JSON | Optional |
| kube-linter / KICS / Terrascan | K8s / multi | not automated | — | Document only |

## 3. Execution contract

For every invocation, capture and store in `scanner_runs.json`:

```
{tool, version, argv, cwd, started_at, duration_ms, exit_code,
 stdout_path, stderr_path, parsed: <bool>, error: <string|null>}
```

Rules:

* **Timeouts are mandatory** (default 300 s per tool, configurable). A timeout is a coverage
  limitation, not an empty result.
* **Working directory** is the audited root unless the tool needs a module directory (`gosec`,
  `npm audit`). Never let a tool write into the audited tree; point report paths at the output dir.
* **Exit codes**: `0` = clean, `1` = findings present (normal for bandit/semgrep/gitleaks), other =
  failure. Never treat a non-zero code as a crash without checking stderr.
* **Raw output is preserved** verbatim (`raw/<tool>.json`) so a reader can audit the parse. Redaction
  applies to parsed findings and to anything rendered; raw files stay in the output directory, which
  the report marks as possibly sensitive.
* **Determinism**: sort tools alphabetically and findings by `(file, line, rule)` before merging.

## 4. Normalisation to the finding model

Every parser produces candidates with the same shape and drops nothing silently:

| Field | Source |
| - | - |
| `title` | rule name / message, trimmed to one line |
| `category` | mapped from rule id → taxonomy class |
| `cwe` | tool-provided CWE when present, else mapped from the rule id |
| `file`, `line_start`, `line_end` | relative to the audited root, `/`-normalised, 1-based |
| `evidence` | re-read from source at that line (not the tool's echo, which may be truncated) |
| `description` | tool message, sanitised |
| `sources` | `{tool, rule_id, raw_ref}` — always preserved |
| `confidence` | tool severity is **not** confidence; start at MEDIUM and let stage 5 decide |

Rule-id → class mapping is explicit and versioned in the orchestrator. An unknown rule id keeps the
candidate with `category: "unclassified"` and `confidence: LOW` rather than dropping it — an
unclassified candidate is still evidence.

**Tool severity is not our severity.** Semgrep `ERROR`, bandit `HIGH`, checkov `FAILED` are inputs to
validation, not verdicts. Severity is re-derived from the CVSS vector at stage 6.

## 5. When a tool is absent

This is the normal case on many machines; handle it in the open:

1. `scanners.json` records `available: false` with the probe reason.
2. The coverage section lists the missing tool, the class it would have covered, and the
   consequence: *"SQL-injection coverage relies on built-in rules only; semgrep unavailable"*.
3. The audit **never** reports "no vulnerabilities found" without that section.
4. If the user asked for a specific tool's output, say it was unavailable rather than substituting
   the built-in result silently.

## 6. Parsing notes that prevent false results

* SARIF and JSON occasionally disagree on line base (0 vs 1). Normalise to 1-based and verify one
  finding per tool against the source before trusting the batch.
* Paths may be absolute or relative to the tool's cwd. Rebase to the audited root and record
  out-of-root findings as `out_of_scope`.
* Deduplicate within a single tool's output first — some rules fire twice on the same line via
  different paths.
* Ignore vendored paths (`node_modules`, `vendor`, `.venv`, `dist`) unless the operator included
  them; record the exclusion.

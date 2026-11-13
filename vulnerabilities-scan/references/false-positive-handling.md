# False-Positive Handling

The fastest way to make a security report useless is to bury three real issues under forty that a
developer can dismiss in one glance. This file is the suppression discipline.

## 1. Why false positives happen

| Cause | Example | Remedy |
| - | - | - |
| Pattern without provenance | `eval(` in a build script with a literal | Require attacker-controlled input before reporting |
| Framework escaping ignored | `{{ user.name }}` in Jinja/Blade/Twig/JSX | Recognise auto-escaping; only `\|safe`/`raw`/`{!! !!}` re-open it |
| Sanitiser not recognised | `shlex.quote(x)` before `os.system`, `DOMPurify` before `innerHTML` | Sanitiser allow-list per sink |
| Test/fixture code | Intentional SQLi in `tests/fixtures/vulnerable.py` | Path-based suppression with a recorded reason |
| Dead code | A handler never registered on any router | Reachability check; downgrade rather than report as confirmed |
| Correct-but-unfamiliar idiom | `db.Query("… $1", x)`, `where(id: id)` | Detect parameterisation, not concatenation |
| Wrong output context | `html.escape()` is sufficient for HTML text, not for a JS context | Context-aware rules |
| Truncated scanner evidence | Tool reports line 1 of a multi-line call | Re-read source at validation time |

## 2. Suppression rules (applied in this order)

Adjudicate first, suppress second: each finding is re-read and decided on its own evidence, and a
suppression is a recorded decision about *that* finding, never a batch action over a directory.

1. **Recognised sanitiser on the path** → suppress, record the sanitiser and line.
2. **Framework auto-escaping in the correct context** → suppress for XSS only.
3. **Parameterised call** → suppress for injection classes.
4. **Path-based suppression** (tests, fixtures, examples, vendored, generated) → suppress, record the
   rule. Findings in fixtures are reported in a separate section, never as product risk.
5. **Placeholder credential** (`changeme`, `your-key-here`, `xxx`, `<token>`, `example.com`) →
   downgrade to Informational; do not page anyone.
6. **Unreachable code** → downgrade to LOW/`needs_review`, not CONFIRMED.
7. **Duplicate of a stronger finding** → merge; never suppress silently, provenance must survive.
8. **Operator-declared accepted risk** → suppress with `accepted_risk` and the justification.

Every suppression writes `{reason, kind, rule, location, decided_at}` into the dataset. `kind` is one
of `false_positive` (the weakness is not there: rules 1–3, 5, 7), `not_exploitable` (the weakness is
real but unreachable or controlled: rules 4, 6) or `accepted_risk` (rule 8). It is not decoration:
the report files each kind in its own directory under `suppressed/`, so a reader can tell "the
scanner was wrong" from "we know, and we are living with it" without opening the file. A suppression
with no kind is filed under `suppressed/unspecified/` and the run warns about it.

A suppressed finding is **not deleted**: the next audit should show "still suppressed, same reason",
which is how suppressions themselves get audited.

## 3. Sanitiser catalogue by sink

**SQL** — bound parameters (`execute(sql, params)`, `?`, `%s` with an argument tuple, `$1`, `:name`);
ORM predicate APIs (`where(col=value)`, `filter_by`, `objects.filter`, `eq()`, `Where(c)`); identifier
allow-lists for dynamic columns and `ORDER BY` (a whitelist, not a regex).

**Shell** — argv arrays without a shell (`subprocess.run([...])`, `execFile`, `spawn` without
`shell:true`, `exec.Command(name, args...)`, `ProcessBuilder(List)`, `system(*argv)`); `shlex.quote` /
`escapeshellarg` mitigate only with a fixed program name — note the residual risk in `impact`.

**HTML/template** — auto-escaping engines (Jinja2 default, Django templates, Blade `{{ }}`, Twig, JSX,
Razor, `html/template`); explicit escaping (`html.escape`, `encodeURIComponent` for URL context,
`DOMPurify.sanitize` with a restrictive config, `bleach.clean`).

**Paths** — resolve-then-contain: `realpath` + `commonpath`, `filepath.Clean` + `HasPrefix(root+sep)`,
`Path.resolve().startsWith(base + path.sep)`, `GetFullPath` + `StartsWith`, `os.Root`/`filepath.IsLocal`;
`secure_filename`, `GetFileName`, `basename` when a fixed directory is used. **Not** a control:
replacing `..` with an empty string, or blacklisting `../`.

**Network/SSRF** — scheme + host allow-list, resolved-IP restriction (`Dialer.Control`, `safeurl`).
Not a control: string-matching `localhost` (bypassable via `127.0.0.1`, DNS, redirects).

**Deserialisation** — `yaml.safe_load`, `JSON.parse`, `allowed_classes => false`,
`ObjectInputFilter` allow-list, `TypeNameHandling.None`.

**Crypto** — `secrets`, `crypto/rand`, `SecureRandom`, `RandomNumberGenerator`, `os.urandom` for
tokens; bcrypt/Argon2/scrypt/PBKDF2 with a modern cost.

**AuthN/AuthZ** — middleware present *before* the route in the chain, guards, `@PreAuthorize` with
method security enabled, `before_action`, policy objects, `[Authorize]` with a fallback policy;
ownership predicates in the query (`WHERE user_id = :principal`).

**Infra** — `USER` non-root plus `readOnlyRootFilesystem`, digest-pinned images; a `permissions:` block
narrower than `write-all`; actions pinned to a full commit SHA; Terraform with explicit
`Principal`/`Condition`, `encrypted = true`, non-public ACLs.

## 4. Look-alikes that must NOT be reported

Recurring traps; each has cost real audits credibility.

| Looks like | Actually | Verdict |
| - | - | - |
| `innerHTML = '<b>static</b>'` | Literal, no interpolation | Suppress |
| `eval(...)` in a dev-only script excluded from the build | No attacker input, not shipped | Informational |
| `subprocess.run(["git", "log", branch])` | argv array, no shell | Suppress for CWE-78 |
| `WHERE id = ?` with formatting only on the table name | Identifier from a fixed map | Suppress; note if the map is user-editable |
| `pickle.loads(open(local_cache,'rb'))` | Trusted local file, no network origin | Downgrade to LOW |
| `math/rand` for retry jitter | Not security-sensitive | Suppress |
| `md5` for a file checksum | Not passwords, not signatures | Suppress for CWE-916; CWE-328 only if a security decision depends on it |
| `Allow-Origin: *` on a public credential-less API | Public data | Informational at most |
| `privileged: true` in `docker-compose.dev.yml` | Local dev only | Informational, note the file |
| `DEBUG=True` behind an env-driven guard | Production-safe | Suppress |
| Missing `HttpOnly` on a non-session cookie | Not a session identifier | Suppress |
| `jwt.decode(..., verify=False)` in a unit test | Test-only | Suppress by path, keep provenance |
| `path.join(base, req.params.file)` then a `startsWith` check | Control present | Suppress after verifying separator handling |
| `AKIA…` string in a redaction test | Deliberately fake fixture | Suppress, Informational |
| `permitAll()` on `/login`, `/health`, `/static/**` | Intended public routes | Suppress |

## 5. Precision discipline

Optimise for a reader who will check the first three findings and, if they are wrong, discount the
rest.

* Prefer **fewer, evidenced** findings. A CONFIRMED finding with a reproduction path earns trust; ten
  MEDIUM patterns spend it.
* Never pad the count. "3 findings" is not better than "2 findings".
* Report negative findings explicitly — "checked, mitigated" is a result too.
* If a class could only be checked superficially (no scanner, unsupported language), say so in the
  coverage section instead of implying coverage.

## 6. When in doubt

Ask: *could a developer who knows this code dismiss this in one sentence?* If the answer is "that's
escaped upstream", the check belongs in the validation record, not the findings list. If the answer is
"the framework does that", verify the framework's actual behaviour for the version in the repository
before suppressing — defaults change between major versions, and a suppression based on a remembered
default is how real bugs get missed.

# Security Methodology

How the audit establishes facts, and what it refuses to claim. Read this for stages 0–2 and
whenever a judgement call about scope, trust boundaries or evidence arises.

## 1. Scope contract

Before any file is read, the audit fixes four facts and writes them to `scope.json`:

| Field | Why it matters |
| - | - |
| `target_path` | A finding's location is meaningless without the root it is relative to. |
| `commit` / `branch` / `dirty` | Findings describe a snapshot. A dirty tree means the snapshot is not reproducible — say so in the report. |
| `excluded` | Vendored code, build output, generated files, fixtures. Exclusions are *limits on the audit's claims* and must appear in the report. |
| `mode` | Always `read-only`. There is no other mode. |

Rules:

* Never widen scope silently. If a manifest pulls code from outside `target_path`, record it as a
  dependency, not as source under audit.
* Never scan outside the repository: no home-directory searches, no environment dumps, no global
  caches. Secret hunting is bounded by the target.
* If the user's request and the repository disagree (they ask about a service that is not in this
  repo), say so at stage 0 and stop rather than producing a report that implies coverage.

## 2. Inventory (stage 1)

Enumerate deterministically, honouring `.gitignore`-style exclusions plus the operator's list.
Classify every path into exactly one bucket:

| Bucket | Examples | Consequence |
| - | - | - |
| `source` | `.py`, `.js`, `.ts`, `.go`, `.rb`, `.php`, `.java`, `.cs` | Analysed |
| `config` | `.yaml`, `.json`, `.toml`, `.ini`, `.env*`, `*.conf` | Analysed for secrets and dangerous settings |
| `iac` | `Dockerfile`, `*.tf`, `k8s/*.yaml`, `.github/workflows/*.yml` | Analysed for infrastructure weaknesses |
| `manifest` | `package.json`, `go.mod`, `composer.json`, `pom.xml`, `*.csproj`, `requirements.txt`, `Gemfile.lock` | Parsed for dependencies and lockfile integrity |
| `docs` | `*.md`, `*.rst`, `*.adoc`, `*.txt`, licence files | Not analysed for code weaknesses; scanned for accidentally committed secrets |
| `binary` | images, archives, `.class`, `.jar`, `.so`, `.exe`, `.wasm` | **Coverage gap** — recorded, never silently skipped |
| `generated` | `dist/`, `build/`, `*.min.js`, `*_pb2.py` | Excluded by default; recorded as excluded |
| `unreadable` | permission errors, broken symlinks, undecodable files | **Coverage gap** |

Submodules are recorded as separate repositories: their content is not in this snapshot, so findings
inside them cannot be attributed to it. Very large files (default > 1 MiB, configurable) are
inventoried but not analysed, and the report says so.

The secret pass covers more buckets than the code-rule pass. Program logic, configuration,
infrastructure and manifests are read by both; prose (`docs`, plus a notebook, which inventories as
configuration) is read by the secret pass alone. That split is deliberate: credentials in a README are
live and published, while the code fragments a README quotes are illustrations. The findings a
document produces are therefore all `hardcoded_secret`, tagged with the document language, and worded
so the reader knows the value is in a document rather than in code.

Output invariants: every file counted exactly once; `len(files) == len(source) + len(config) + …`;
the counts reconcile with what the report prints.

## 3. Attack surface (stage 2)

### 3.1 Entry points

Enumerate, per framework, by mechanism rather than by filename:

| Framework | Route discovery | Auth/authz mechanisms to look for |
| - | - | - |
| Express/Koa/Fastify | `app.get/post/put/delete`, `router.*`, `fastify.route` | `app.use(...)`, middleware order, `passport`, `req.user` checks |
| NestJS | `@Controller`, `@Get/@Post`, `@UseGuards` | global guards, `@Public`, `RolesGuard` |
| Next.js (API) | `pages/api/**`, `app/**/route.ts` | middleware.ts matchers, `getServerSession` |
| FastAPI | `@app.get`, `@router.*`, `APIRouter(prefix=…)` | `Depends(...)`, `Security(...)`, dependency trees |
| Flask | `@app.route`, Blueprints | `before_request`, `login_required`, decorators |
| Django | `urls.py` `path()/re_path()`, DRF routers | middleware, `@login_required`, DRF `permission_classes`, `authentication_classes` |
| Rails | `config/routes.rb` (resources, `only`, `namespace`) | `before_action`, `authenticate_user!`, `authorize`, Pundit policies |
| Laravel | `routes/web.php`, `routes/api.php` | `middleware('auth')`, `Gate`/`Policy`, `can:` |
| Spring | `@RequestMapping/@GetMapping`, `@RestController` | `SecurityFilterChain`, `@PreAuthorize`, `permitAll`, method security |
| ASP.NET | `[Route]`, `[HttpGet]`, minimal APIs `MapGet` | `[Authorize]`, `[AllowAnonymous]`, fallback policy |
| Gin/Echo/Chi | `r.GET`, `Group(...)`, `Use(...)` | group middleware, per-route middleware |
| Gorilla/mux | `HandleFunc`, `PathPrefix` | `Use`, subrouter middleware |

Also enumerate non-HTTP surface: GraphQL resolvers and mutations, WebSocket handlers, gRPC service
implementations, message-queue consumers, scheduled jobs, CLI entry points, and file-watchers. Each
is a trust boundary even when it never touches HTTP.

**Route-bearing code you cannot enumerate must be reported, not skipped.** Every framework above can
also route *by convention*, with nothing in the source to match: an ASP.NET `Controller`-derived
class whose public action methods are reached as `/Order/List`, a Spring `@RestController` with no
method mapping, a framework whose route table is built at runtime. For those files "no routes found"
is a coverage gap, not a clean result — record the file, the class and the candidate action names,
say plainly that the entry points are not enumerated, and never invent the URL an action name
implies. A zero-route report that does not distinguish "this app has no endpoints" from "this stage
cannot see this app's endpoints" is worse than no report, because it reads as a pass.

### 3.2 Trust boundaries

Model three zones and name the crossing points:

1. **Untrusted** — request parameters, headers, cookies, body, uploaded files, queue messages, any
   third-party API response.
2. **Validated** — data that passed an explicit schema/allow-list check. Mark the *validator*
   function; this is what turns "is this sanitised?" into a checkable question.
3. **Trusted** — configuration loaded at boot, values from signed tokens, database rows written by
   trusted code.

A candidate becomes a finding when tainted data crosses into a sensitive sink **without** a recorded
validator on the path. The validator list is discovered from the codebase (decorators, schemas,
`validators`, `sanitize*` helpers), not assumed from a framework's reputation.

### 3.3 Data classification

Note where credentials, tokens, PII, payment data and health data flow. A path traversal on a
public assets directory and the same bug on a KYC-document directory are not the same finding; the
classification drives impact in the CVSS vector rather than the detection itself.

## 4. What static analysis can and cannot establish

| Question | Static answer |
| - | - |
| Does request data reach this sink? | Yes, when the path is visible in the parsed file or an in-repo call chain. Cross-file through DI/reflection: not reliably. |
| Is the sink parameterised? | Yes — the call shape is explicit. |
| Is there an authorisation check on this route? | Yes when middleware/decorator mechanisms are visible; no when resolved dynamically at runtime. |
| Is this dependency exploitable? | **No.** Version presence ≠ reachability. Report the dependency and say reachability is not established. |
| Is this business rule correct? | **No.** The repository rarely states intent. Cap confidence at MEDIUM. |
| Is this secret live? | **Never test it.** Report presence, redact the value, recommend rotation. |

State the limits in the report rather than letting a reader assume the absence of a finding is
evidence of absence.

## 5. Detection engine design (how the built-in analyzers work)

1. **Sources** — symbols that yield attacker-controlled data: request objects, `process.argv`,
   `os.environ` where it carries user intent, queue payloads, uploaded file objects.
2. **Sinks** — sensitive operations: SQL execution, shell, filesystem paths, HTTP client, template
   rendering, deserialisation, crypto/key derivation, redirect targets, header writes.
3. **Sanitisers** — functions that neutralise a sink: parameter binding, `escape`/`encode`,
   allow-list validators, `shlex.quote`, `filepath.Clean` + prefix check, `html.escape`,
   prepared statements, `safe_load`.
4. **Propagation within a function** — assignment, f-strings/template literals, string concatenation
   and `format`/`Sprintf`-style composition. This catches the common real bugs without pretending to
   be a full dataflow engine.
5. **Cross-file, one hop** — follow a tainted variable into a helper defined in the same repository
   when the call site is unambiguous. Do not attempt interprocedural analysis beyond that; record the
   limit instead.

Each rule carries: class, CWE, sink pattern, required provenance, sanitiser exceptions, confidence
ceiling, and a suppression rule. A rule without a documented sanitiser exception will produce false
positives on secure code — see `false-positive-handling.md`.

## 6. Sequencing and determinism

* Deterministic ordering everywhere: files sorted by path, findings by `(severity, file, line)`.
  Two runs over the same snapshot must produce byte-identical `findings.json`.
* Every stage is resumable from its JSON artefact; re-running stage 5 must not need stages 1–4.
* Timestamps are recorded once per stage, never inside finding bodies, so diffs between runs stay
  meaningful.

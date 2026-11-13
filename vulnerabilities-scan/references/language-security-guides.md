# Language Security Guides

Dangerous sinks, safe equivalents, and framework-specific authorisation mechanisms for the seven
languages in scope. Use this during detection (stage 3) and validation (stage 5): a rule that fires
on a sink is a candidate until the safe alternative has been ruled out.

Throughout: **safe** means the construct removes the weakness structurally, not that it filters
bad characters.

## Python

| Risk | Dangerous | Safe |
| - | - | - |
| SQL | `cursor.execute(f"… {id}")`, `%`/`.format`, `.raw()`, `.extra()` | `execute(sql, (id,))`, ORM filter kwargs, `bindparam` |
| Shell | `os.system`, `os.popen`, `subprocess(..., shell=True)` with a composed string | `subprocess.run([...], shell=False)` |
| Code | `eval`, `exec`, `compile`, `__import__` of request data | explicit dispatch dict |
| Deserialisation | `pickle.loads`, `dill`, `marshal`, `yaml.load` (default loader) | `yaml.safe_load`, JSON + schema |
| Templates | `render_template_string(user_tpl)` | fixed template + context |
| Paths | `open(os.path.join(base, name))` | `Path(base).resolve()` + `is_relative_to(base)`, `secure_filename` |
| HTTP | `requests.get(user_url)` | allow-listed host, private-range block |
| Crypto | `random.*` for tokens, `hashlib.md5(pw)` | `secrets.token_*`, bcrypt/argon2/pbkdf2 with cost |

Django/DRF authorisation discovery: `MIDDLEWARE` order, `permission_classes`, `get_queryset()`
filtering by `request.user` (absence is the IDOR signal), `@permission_required`.

## JavaScript / TypeScript

| Risk | Dangerous | Safe |
| - | - | - |
| SQL | template literals in `db.query`, `sequelize.query` interpolation | parameterised queries, query builders |
| Shell | `child_process.exec`, `execSync`, `spawn(..., {shell:true})` | `execFile`/`spawn` with argv |
| Code | `eval`, `new Function`, `vm.runInNewContext` | `JSON.parse`, dispatch map |
| DOM XSS | `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html` | `textContent`, framework escaping, `DOMPurify` |
| Prototype pollution | `Object.assign({}, req.body)`, recursive merge of request data | schema-picked fields, `Object.create(null)` |
| Paths | `path.join(base, req.params.file)` | `path.resolve` + `startsWith(base + path.sep)` |
| JWT | `jwt.decode`, `algorithms` unset, secret literal | `jwt.verify(t, k, {algorithms:['RS256']})` |
| CORS | `cors({origin:'*', credentials:true})`, `origin: true` | explicit allow-list |
| TLS | `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized:false` | defaults |

Express: middleware **order** is the control — auth registered after the route does not protect it.
NestJS: global guards plus `@Public()` overrides. Next.js: `middleware.ts` matcher gaps are a real
and common finding.

## Go

| Risk | Dangerous | Safe |
| - | - | - |
| SQL | `db.Query(fmt.Sprintf("… %s", id))` | `db.Query("… ?", id)`, `$1`, named params |
| Shell | `exec.Command("sh", "-c", userInput)` | `exec.Command(name, args...)` |
| Paths | `filepath.Join(root, r.URL.Query().Get("f"))` | `filepath.Clean` + `HasPrefix(root+sep)`, `os.Root`/`filepath.IsLocal` |
| HTTP | `http.Get(userURL)` | allow-list, `Dialer.Control` blocking private IPs |
| TLS | `InsecureSkipVerify: true` | `tls.Config{}` |
| Random | `math/rand` for tokens | `crypto/rand` |
| DoS | no `http.MaxBytesReader`, no timeouts | `MaxBytesReader`, `ReadHeaderTimeout` |
| Templates | `text/template` for HTML | `html/template` |

Gin/Echo/Chi: a route registered on the engine instead of the authenticated group is the finding.

## Ruby (and Rails)

| Risk | Dangerous | Safe |
| - | - | - |
| SQL | `where("name = '#{params[:n]}'")`, `.order(params[:sort])` | `where(name: …)`, allow-list for `order` |
| Shell | `system("… #{x}")`, backticks, `%x{}` | `system(*argv)`, `Open3.capture3(cmd, arg)` |
| Code | `eval`, `send(params[:m])`, `constantize` | explicit allow-list |
| Deserialisation | `YAML.load` (untrusted), `Marshal.load` | `YAML.safe_load`, `JSON.parse` |
| Output | `raw`, `html_safe` | default ERB escaping, `sanitize` |
| Mass assignment | `permit!` | `permit(:safe, :fields)` |
| Redirect | `redirect_to params[:return_to]` | fixed path or allow-listed host |
| CSRF | `protect_from_forgery with: :null_session` | default `:exception` |

Rails: `before_action :authenticate_user!` inheritance and `skip_before_action` gaps, Pundit
`authorize`/`policy_scope`, CanCan `authorize!`.

## PHP

| Risk | Dangerous | Safe |
| - | - | - |
| SQL | `mysqli_query("… $id")`, `$pdo->query("… ".$_GET['id'])` | `prepare(...)->execute([$id])` |
| Shell | `system`, `exec`, `shell_exec`, `passthru` | no shell; `escapeshellarg` + allow-list |
| Code | `eval`, `assert($_POST…)`, `preg_replace` `/e` | explicit calls |
| Deserialisation | `unserialize($_COOKIE…)` | `json_decode` + validation, `allowed_classes => false` |
| Include | `include $_GET['page']` | fixed map of allowed includes |
| Uploads | `move_uploaded_file(…, $dir.$_FILES['f']['name'])` | generated name, extension+MIME allow-list, outside web root |
| Output | unescaped `echo`, Blade `{!! !!}` | `htmlspecialchars(..., ENT_QUOTES)`, `{{ }}` |
| Crypto | `md5($pw)`, `==` on hashes | `password_hash`, `hash_equals` |

Laravel: `middleware('auth')`, `can:`/`Gate::authorize`, `$fillable` (missing `$guarded` +
`$request->all()` is mass assignment).

## Java

| Risk | Dangerous | Safe |
| - | - | - |
| SQL | `Statement.execute("… "+id)`, JPQL string concat | `PreparedStatement`, named params |
| Shell | `Runtime.exec(String)`, `ProcessBuilder("sh","-c",…)` | `ProcessBuilder(List)` |
| Deserialisation | `ObjectInputStream.readObject`, `XStream` unwhitelisted | `ObjectInputFilter` allow-list, JSON |
| XML | `DocumentBuilderFactory` without `disallow-doctype-decl` | DTDs disabled, secure processing |
| Expression | SpEL/OGNL/MVEL on user input | fixed expressions |
| Paths | `new File(base, userPath)` | `normalize()` + `startsWith(base)` |
| Crypto | `MessageDigest MD5/SHA1` for passwords, `new Random()` | BCrypt/Argon2, `SecureRandom` |
| TLS | permissive `TrustManager`, `HostnameVerifier` → true | defaults |

Spring: `SecurityFilterChain` rules, `@PreAuthorize` — and the `@EnableMethodSecurity` precondition;
without it the annotation is inert, which is an easily missed real finding.

## C# / .NET

| Risk | Dangerous | Safe |
| - | - | - |
| SQL | `new SqlCommand("… " + id)`, `FromSqlRaw` interpolation | `Parameters.AddWithValue`, `FromSqlInterpolated` |
| Shell | `Process.Start("cmd", "/c " + x)` | argv list, `UseShellExecute=false` |
| Deserialisation | `BinaryFormatter`, `LosFormatter`, `TypeNameHandling.All` | `System.Text.Json`, known types |
| XML | `DtdProcessing = Parse` | `Prohibit`, `XmlResolver = null` |
| Paths | `Path.Combine(base, userInput)` (absolute input wins) | `GetFullPath` + `StartsWith(base)`, `GetFileName` |
| Output | `Response.Write(Request.QueryString[...])`, `Html.Raw` | Razor encoding |
| Crypto | `MD5`/`SHA1` passwords, `new Random()` | `Rfc2898DeriveBytes`/BCrypt, `RandomNumberGenerator` |
| CSRF | missing `[ValidateAntiForgeryToken]` | attribute + token helper |

ASP.NET: `[Authorize]`, `[AllowAnonymous]` overrides, the fallback policy (default-allow is the
systemic finding), `.RequireAuthorization()` vs bare `MapGet`.

## Rust

Sinks: `Command::new("sh")` / `.arg(...)` (a shell re-parses every argument), `format!`-built
`query`/`execute` strings (values become SQL syntax), `File::open(format!(...))` and
`fs::read_to_string` on an interpolated path. `unwrap()` on a parsed path is an availability issue,
not a traversal: do not report it as one. Async web frameworks (`axum`, `actix-web`) resolve routes
through macros, so route discovery is a stated gap there rather than an empty list.

## C / C++

Sinks: `system`, `popen`, `execl*`/`execv*` with a non-literal argument; `rand()`/`random()` used for
a token, session id or salt. A `system("date")` call with a literal is not a finding. Memory-safety
defects (`strcpy`, `sprintf`, off-by-one) are a different taxonomy from the injection classes here
and are left to a compiler-backed scanner (`gcc -fanalyzer`, `clang --analyze`, `semgrep`) — the
report says so instead of pretending pattern matching covers them.

## Swift

Sinks: `Process()`/`NSTask` with `executableURL`/`launchPath` set to `/bin/sh` and arguments built by
interpolation; string-interpolated SQL. Prefer `Process` with an argument vector in any remediation.

## Kotlin (and other JVM languages)

Kotlin calls the same JDK classes as Java, so the JVM rules apply verbatim: `prepareStatement("..." +
x)`, `Runtime.getRuntime().exec(...)`, `ObjectInputStream`, `MessageDigest.getInstance("MD5")`,
`Paths.get(request.getParameter(...))`. Scala and Clojure are inventoried but have no rules — a
stated gap, not a clean result.

## Shell

Sinks: `eval "$var"`, `curl … | sh`, a fixed `/tmp` path written without exclusive create. `set -e`
and `set -u` are hygiene, not a sink guard. A download that is written to a file, digest-checked and
then executed by path is the remediation, not a finding.

## PowerShell

Sinks: `Invoke-Expression`/`iex` on a variable, `DownloadString(...) | iex`, `-ExecutionPolicy
Bypass` in a bootstrap. Check for signed-script policy and `Get-FileHash` verification before
reporting a download as remote code execution.

## SQL files

`EXEC ... xp_cmdshell` is a shell escape and is reported. Querying the `xp_cmdshell` configuration
setting is not. `GRANT ALL … TO PUBLIC` and similar privilege statements are reviewed by hand —
there is no rule for them, so say so rather than implying the file is clean.

## Infrastructure: CloudFormation, Ansible, Compose, GitLab CI, Jenkins

* **CloudFormation** — `AccessControl: PublicRead*`, `CidrIp: 0.0.0.0/0`, `Effect: Allow` with
  `Action: "*"`, `StorageEncrypted: false`.
* **Ansible** — `validate_certs: no`, `shell:`/`command:` fed a `{{ template }}`, `mode: 0777`.
  Prefer `argv:` and `checksum:` in any remediation.
* **docker-compose / Helm** — `/var/run/docker.sock` mounted, `network_mode: host`, floating
  `:latest` tags, `privileged: true`.
* **GitLab CI / Jenkins** — `curl … | sh` in a `script:`/`sh` step, floating images. A pipeline step
  that pins an image digest and verifies a download is the remediation.
* Classification follows the path: a `cloudformation/` directory or a `.gitlab-ci.yml` file name is
  what makes these files infrastructure. A subtree scanned as the repository root loses that label.

## Cross-language notes

* **Reflection/DI-resolved routes** defeat static route discovery. Record the limitation in coverage
  rather than assuming the route list is complete.
* **Generated code** (protobuf, migrations, minified bundles) is excluded; a weakness visible only
  there becomes a coverage gap.
* **Test code** contains intentional vulnerabilities. Findings under `test/`, `spec/`, `fixtures/`
  are reported separately or suppressed with a recorded reason — never silently dropped.

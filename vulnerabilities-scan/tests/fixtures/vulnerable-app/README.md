# Intentionally vulnerable fixture app

This tree exists so the analyzers have something real to find. **It is not an
application.** Do not copy, deploy or reuse any file here.

Every finding in this tree is asserted by `tests/fixtures/expected_findings.json`,
which the test suite reads in both directions: a required class that stops being
detected fails the build, and a class that is no longer present in the corpus
fails too, so the fixture cannot rot into a stale expectation.

## Required vulnerability classes and where they live

| # | Class | File |
|---|-------|------|
| 1 | SQL injection | `python/orders/views.py`, `node/src/orders.ts`, `node/src/app.js`, `go/main.go`, `ruby/app/controllers/orders_controller.rb`, `php/orders.php`, `java/src/main/java/example/invalid/Orders.java`, `dotnet/OrdersController.cs` |
| 2 | Command injection | `python/orders/views.py`, `node/src/orders.ts`, `node/src/app.js`, `go/main.go`, `ruby/app/controllers/orders_controller.rb`, `php/orders.php`, `java/src/main/java/example/invalid/Orders.java`, `dotnet/OrdersController.cs` |
| 3 | Reflected XSS | `python/orders/views.py`, `node/src/orders.ts`, `go/main.go`, `ruby/app/controllers/orders_controller.rb`, `php/orders.php`, `java/src/main/java/example/invalid/Orders.java`, `dotnet/OrdersController.cs` |
| 4 | Stored XSS | `python/orders/views.py`, `php/orders.php` |
| 5 | Path traversal | `python/orders/views.py`, `node/src/orders.ts`, `go/main.go`, `ruby/app/controllers/orders_controller.rb`, `php/orders.php`, `java/src/main/java/example/invalid/Orders.java`, `dotnet/OrdersController.cs` |
| 6 | SSRF | `python/orders/views.py`, `node/src/orders.ts`, `node/src/app.js`, `go/main.go`, `java/src/main/java/example/invalid/Orders.java`, `dotnet/OrdersController.cs` |
| 7 | Missing authentication | `python/orders/identity.py`, `java/src/main/java/example/invalid/Orders.java` |
| 8 | Missing authorization | `python/orders/identity.py`, `python/orders/views.py`, `node/src/orders.ts`, `ruby/app/controllers/orders_controller.rb`, `php/orders.php`, `java/src/main/java/example/invalid/Orders.java`, `dotnet/OrdersController.cs` |
| 9 | IDOR | `python/orders/views.py`, `node/src/orders.ts`, `java/src/main/java/example/invalid/Orders.java`, `dotnet/OrdersController.cs` |
| 10 | Weak JWT validation | `python/orders/views.py`, `node/src/orders.ts`, `php/orders.php` |
| 11 | Hardcoded secrets | `python/orders/config.py`, `infra/Dockerfile` |
| 12 | Weak password hashing | `python/orders/views.py`, `node/src/orders.ts`, `ruby/app/controllers/orders_controller.rb`, `php/orders.php`, `java/src/main/java/example/invalid/Orders.java`, `dotnet/OrdersController.cs` |
| 13 | Insecure deserialization | `python/orders/views.py`, `go/main.go`, `ruby/app/controllers/orders_controller.rb`, `php/orders.php`, `java/src/main/java/example/invalid/Orders.java`, `dotnet/OrdersController.cs` |
| 14 | Vulnerable dependency | `python/requirements.txt`, `node/package.json`, `java/pom.xml` |
| 15 | Insecure CORS | `python/orders/settings.py`, `node/src/app.js`, `php/orders.php`, `java/src/main/java/example/invalid/Orders.java` |
| 16 | Insecure file upload | `python/orders/uploads.py`, `php/orders.php`, `java/src/main/java/example/invalid/Orders.java` |
| 17 | Missing rate limiting | `python/orders/views.py` (see the note below) |
| 18 | Insecure Docker config | `infra/Dockerfile` |
| 19 | Over-privileged CI/CD | `.github/workflows/ci.yml` |
| 20 | Business-logic flaw | `python/orders/views.py`, `node/src/orders.ts`, `ruby/app/controllers/orders_controller.rb` |

Kubernetes (`infra/k8s/deployment.yaml`) and Terraform (`infra/terraform/main.tf`)
carry their own classes beyond the twenty required ones.

## Why missing rate limiting is special

Class 17 is not a regex over source text: it is derived from the attack-surface
pass, which only runs when stage 2b produced an entry point for a credential
path. The class is therefore asserted in two steps — the corpus provides a
login route, and the expectation file records that the class needs
`attack_surface` input. See `docs/VALIDATION-RESULTS.md` for the measured
result, including the case where the input is absent.

## The credentials here are fabricated

`python/orders/config.py` and `infra/Dockerfile` contain credential-shaped
strings. They are invented examples chosen so the secret pass has something to
find and redact. They are not, and have never been, live credentials. The test
suite asserts that no report ever renders them.

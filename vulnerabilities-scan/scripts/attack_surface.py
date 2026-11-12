#!/usr/bin/env python3
"""Attack-surface enumeration (audit stage 2b).

Finds entry points by *mechanism* rather than by filename, because "this file is
called routes.py" is not evidence and "this function is registered with
``app.get('/x', requireAuth, handler)``" is. For every entry point this script
records which authentication/authorisation mechanism is visible on the path,
and — critically — distinguishes "no mechanism found" from "proven
unauthenticated". A dynamic route table, a decorator built at runtime, or a
framework we do not model all look like "no mechanism found", and the report
must not upgrade that into a vulnerability.

Output is deterministic: entry points are sorted by (file, line, method, path).

Precision note: auth and non-HTTP rules run against a *code-only view* of each
file -- comments and string bodies blanked, offsets preserved -- so prose about
a WebSocket server, a docstring mentioning ``/admin`` or this tool's own rule
tables cannot invent a surface. One surface is reported per kind per file,
because a pattern that fires on every call describes one mechanism.

Read-only, stdlib only.

Usage
-----
    python3 scripts/attack_surface.py --root . --out attack_surface.json
    python3 scripts/attack_surface.py --technologies technologies.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import finding_model as fm  # noqa: E402
import repository_inventory as inv  # noqa: E402

TOOL_VERSION = "1.0.0"


# --------------------------------------------------------------------------- #
# Route discovery rules
# --------------------------------------------------------------------------- #
#: Each rule uses named groups: ``method``, ``path``, and optionally
#: ``receiver`` (the variable the route is registered on) so group prefixes can
#: be applied later. Named groups replaced positional extraction after the
#: positional version silently produced empty paths for ``@app.route`` and
#: ``resources :x`` and mis-ordered ``@Route('x', methods=[...])``.
ROUTE_RULES: Tuple[Tuple[str, Tuple[str, ...], str, str], ...] = (
    # --- JavaScript / TypeScript ------------------------------------------- #
    # One generic receiver rule instead of one per framework: Express, Koa,
    # Fastify, hapi and every home-grown router share this call shape. The
    # receiver deny-list removes HTTP clients, which look identical.
    ("js-router", ("javascript", "typescript"), "http_route",
     r"""\b(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*(?P<method>get|post|put|patch|delete|all|options|head)\s*\(\s*['"`](?P<path>[^'"`]+)['"`]"""),
    ("js-router", ("javascript", "typescript"), "http_route",
     r"""\.\s*route\s*\(\s*['"`](?P<path>[^'"`]+)['"`]\s*\)\s*\.\s*(?P<method>get|post|put|patch|delete|all)"""),
    ("fastify", ("javascript", "typescript"), "http_route",
     r"""\bfastify\s*\.\s*(?P<method>get|post|put|patch|delete|options|head)\s*\(\s*['"`](?P<path>[^'"`]+)['"`]"""),
    ("fastify", ("javascript", "typescript"), "http_route",
     r"""\bfastify\s*\.\s*route\s*\(\s*\{[^}]*?method\s*:\s*['"](?P<method>[A-Za-z]+)['"][^}]*?url\s*:\s*['"](?P<path>[^'"]+)['"]"""),
    ("nestjs", ("typescript", "javascript"), "http_route",
     r"""@(?P<method>Get|Post|Put|Patch|Delete|All|Options|Head)\s*\(\s*(?:['"](?P<path>[^'"]*)['"])?"""),
    ("hapi", ("javascript", "typescript"), "http_route",
     r"""\bserver\s*\.\s*route\s*\(\s*\{[^}]*?method\s*:\s*['"](?P<method>[A-Za-z]+)['"][^}]*?path\s*:\s*['"](?P<path>[^'"]+)['"]"""),
    ("hapi", ("javascript", "typescript"), "http_route",
     r"""\bserver\s*\.\s*route\s*\(\s*\{[^}]*?path\s*:\s*['"](?P<path>[^'"]+)['"][^}]*?method\s*:\s*['"](?P<method>[A-Za-z]+)['"]"""),

    # --- Python ------------------------------------------------------------- #
    ("fastapi", ("python",), "http_route",
     r"""@\s*(?P<receiver>[A-Za-z_][\w]*)\s*\.\s*(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*['"](?P<path>[^'"]+)['"]"""),
    ("flask", ("python",), "http_route",
     r"""@\s*(?P<receiver>[A-Za-z_][\w]*)\s*\.\s*route\s*\(\s*['"](?P<path>[^'"]+)['"](?P<args>[^)]*)\)"""),
    ("django", ("python",), "http_route",
     r"""\b(?P<method>path|re_path|url)\s*\(\s*r?['"](?P<path>[^'"]*)['"]\s*,\s*(?P<handler>[\w.]+)"""),
    ("django-drf", ("python",), "http_route",
     r"""@api_view\s*\(\s*\[(?P<method>[^\]]*)\]\s*\)"""),
    ("django-drf", ("python",), "router_registration",
     r"""\b(?:router|default_router)\s*\.\s*register\s*\(\s*r?['"](?P<path>[^'"]+)['"]"""),
    ("aiohttp", ("python",), "http_route",
     r"""\b(?:app|router)\s*\.\s*add_(?P<method>get|post|put|patch|delete)\s*\(\s*['"](?P<path>[^'"]+)['"]"""),
    ("tornado", ("python",), "http_route",
     r"""\(\s*r?['"](?P<path>[^'"]+)['"]\s*,\s*(?P<handler>[\w.]+)"""),

    # --- Go ----------------------------------------------------------------- #
    ("go-router", ("go",), "http_route",
     r'''\b(?P<receiver>[A-Za-z_][\w.]*)\s*\.\s*(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any)\s*\(\s*"(?P<path>[^"]+)'''),
    ("go-router", ("go",), "http_route",
     r'''\.(?:HandleFunc|Handle)\s*\(\s*"(?P<path>[^"]+)'''),
    ("go-router", ("go",), "http_route",
     r'''http\s*\.\s*HandleFunc\s*\(\s*"(?P<path>[^"]+)'''),

    # --- Ruby ---------------------------------------------------------------- #
    ("rails", ("ruby",), "http_route",
     r"""^\s*(?P<method>get|post|put|patch|delete)\s+['"](?P<path>[^'"]+)['"]"""),
    ("rails", ("ruby",), "resource_route",
     r"""^\s*(?P<method>resources?|namespace|scope)\s+:(?P<path>\w+)"""),
    ("rails", ("ruby",), "http_route",
     r"""^\s*(?P<method>get|post|put|patch|delete)\s+['"](?P<path>[^'"]+)['"]"""),

    # --- PHP ----------------------------------------------------------------- #
    ("laravel", ("php",), "http_route",
     r"""Route\s*::\s*(?P<method>get|post|put|patch|delete|any|resource|match)\s*\(\s*['"](?P<path>[^'"]+)['"]"""),
    ("symfony", ("php",), "http_route",
     r"""#\[Route\s*\(\s*['"](?P<path>[^'"]+)['"](?:[^)]*methods\s*=\s*\[?['"]?(?P<method>[A-Za-z|]+))?"""),
    ("slim", ("php",), "http_route",
     r"""\$(?:app|group)\s*->\s*(?P<method>get|post|put|patch|delete)\s*\(\s*['"](?P<path>[^'"]+)['"]"""),

    # --- Java ---------------------------------------------------------------- #
    # @RequestMapping is deliberately absent: it is usually the class-level
    # prefix, and matching it as a route invented a route at the class line with
    # the prefix applied twice.
    ("spring", ("java", "kotlin"), "http_route",
     r"""@(?P<method>GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\s*\(\s*(?:value\s*=\s*)?(?:path\s*=\s*)?['"]?(?P<path>[^'")]*)"""),
    ("jax-rs", ("java", "kotlin"), "http_route",
     r"""@(?P<method>GET|POST|PUT|PATCH|DELETE)\s*(?:@Path\s*\(\s*['"](?P<path>[^'"]+)['"])?"""),
    ("servlet", ("java",), "http_route",
     r"""@WebServlet\s*\(\s*(?:value\s*=\s*)?['"](?P<path>[^'"]+)['"]"""),

    # --- C# ------------------------------------------------------------------ #
    # [Route] is a class-level prefix (see CONTROLLER_PREFIX_RULES), not a route.
    ("aspnet", ("csharp",), "http_route",
     r"""\[(?P<method>HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete)\s*\(\s*['"](?P<path>[^'"]+)['"]"""),
    ("aspnet", ("csharp",), "http_route",
     r"""\[(?P<method>HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete)\b"""),
    ("aspnet-minimal", ("csharp",), "http_route",
     r"""\.\s*(?P<method>MapGet|MapPost|MapPut|MapPatch|MapDelete)\s*\(\s*["'](?P<path>[^"']+)["']"""),
)

#: Framework-implied controller prefixes, e.g. NestJS ``@Controller('users')``.
CONTROLLER_PREFIX_RULES: Tuple[Tuple[str, str], ...] = (
    ("nestjs", r"""@Controller\s*\(\s*(?:['"]([^'"]*)['"])?"""),
    ("spring", r"""@RequestMapping\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]"""),
    ("aspnet", r"""\[Route\s*\(\s*['"]([^'"]+)['"]"""),
    ("laravel", r"""Route\s*::\s*(?:prefix|group)\s*\(\s*['"]([^'"]+)['"]"""),
    ("jax-rs", r"""@Path\s*\(\s*['"]([^'"]+)['"]"""),
)

#: Route-bearing code that no rule can enumerate.
#:
#: Some frameworks route *by convention*: ``public IActionResult List()`` on a
#: ``Controller``-derived class is an endpoint with not one character of route
#: declaration to match, and a project file that never names the web package
#: leaves stage 2a with nothing to say either. The honest answer for such a file
#: is not "no endpoints" but "this file carries routes this pass cannot
#: enumerate", so it is counted separately (``unenumerable_routes``) and stated
#: as a coverage gap. Each entry is (framework, languages, class-pattern) and the
#: pattern must prove controller-ness from a base class, never from a name.
CONTROLLER_STYLE_RULES: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    ("asp.net core", ("csharp",),
     r"""^[ \t]*(?:(?:public|internal|private|protected|abstract|sealed|static|partial)[ \t]+)*"""
     r"""class[ \t]+(?P<name>\w+)[ \t]*:[^{;\n]*?\b(?P<base>ControllerBase|Controller)\b"""),
)

#: Framework markers for a file that uses a web stack without declaring a route
#: anywhere: the framework's namespace, or an attribute only that framework
#: defines. Consulted only when neither a route nor a controller base class was
#: found, so a real route is never relabelled as a gap.
CONTROLLER_FRAMEWORK_SIGNALS: Tuple[Tuple[str, Tuple[str, ...], str, str], ...] = (
    ("asp.net core", ("csharp",), r"""^[ \t]*using[ \t]+Microsoft[ \t]*\.[ \t]*AspNetCore\b""",
     "framework_namespace"),
    ("asp.net core", ("csharp",), r"""\[[ \t]*ApiController[ \t]*\]""",
     "api_controller_attribute"),
)

#: Framework identifiers are lower case like every other ``framework`` field;
#: prose gets a display name instead, because "asp.net core" reads as a typo.
FRAMEWORK_DISPLAY_NAMES = {"asp.net core": "ASP.NET Core"}

#: How to name a convention-routed controller's action methods, per language. A
#: candidate is a public method with a return type. Whether the framework would
#: route it is a convention question this pass does not settle, so the names are
#: reported as candidates and never as endpoints: inventing ``/Orders/List``
#: from an action name is the same mistake as inventing a vulnerability from a
#: heuristic.
CONTROLLER_ACTION_PATTERNS: Dict[str, str] = {
    "csharp": (r"""^[ \t]*public[ \t]+(?:async[ \t]+)?(?:virtual[ \t]+|override[ \t]+|"""
               r"""sealed[ \t]+)*(?:static[ \t]+)?[A-Za-z_][\w.]*(?:<[^()]*>)?(?:\[\])?"""
               r"""[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*\("""),
}

#: A limitation sentence names a few actions, not forty.
ACTION_SAMPLE_LIMIT = 12

#: Method names in the regex are framework-specific; normalise to HTTP verbs.
METHOD_MAP = {
    "get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE",
    "head": "HEAD", "options": "OPTIONS", "all": "ANY", "any": "ANY", "match": "ANY",
    "resource": "ANY", "getmapping": "GET", "postmapping": "POST", "putmapping": "PUT",
    "patchmapping": "PATCH", "deletemapping": "DELETE", "requestmapping": "ANY",
    "mapget": "GET", "mappost": "POST", "mapput": "PUT", "mappatch": "PATCH",
    "mapdelete": "DELETE", "httpget": "GET", "httppost": "POST", "httpput": "PUT",
    "httppatch": "PATCH", "httpdelete": "DELETE", "route": "ANY",
}


def _http_method(raw: Optional[str]) -> str:
    if not raw:
        return "ANY"
    token = raw.strip().split("|")[0].strip().strip("'\"").lower()
    return METHOD_MAP.get(token, token.upper() if token.isalpha() else "ANY")


# --------------------------------------------------------------------------- #
# Code-only view
# --------------------------------------------------------------------------- #
#: The lexer lives in :mod:`finding_model` because every stage needs the same
#: "is this code or prose?" answer. Here the string bodies are blanked too: an
#: auth mechanism is an identifier, never a literal, except for the handful of
#: rules listed in :data:`AUTH_STRING_RULES`.
def mask_non_code(text: str, language: str, keep_strings: bool = False) -> str:
    return fm.mask_non_code(text, language, keep_strings=keep_strings)


# --------------------------------------------------------------------------- #
# Authentication / authorisation mechanisms
# --------------------------------------------------------------------------- #
#: (mechanism name, languages, regex, scope-kind). Scope kinds:
#:   global  — applies to everything registered after it in this file
#:   group   — applies to a router/group/blueprint variable
#:   route   — an inline argument on the route itself
#:   class   — a class-level decorator/attribute
AUTH_RULES: Tuple[Tuple[str, Tuple[str, ...], str, str], ...] = (
    # JavaScript / TypeScript
    ("passport.authenticate", ("javascript", "typescript"),
     r"""passport\s*\.\s*authenticate\s*\(""", "route"),
    ("express-middleware", ("javascript", "typescript"),
     r"""\b(?:app|router|server)\s*\.\s*use\s*\(\s*(?:['"][^'"]*['"]\s*,\s*)?([A-Za-z_$][\w$]*)\s*[,)]""",
     "global"),
    ("router-middleware", ("javascript", "typescript"),
     r"""\b(?:router|api|group)\s*\.\s*use\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]""", "group"),
    ("auth-guard", ("typescript", "javascript"),
     r"""@UseGuards\s*\(\s*([^)]*)\)""", "route"),
    ("jwt-verify", ("javascript", "typescript"),
     r"""\b(?:jwt|jose)\s*\.\s*(?:verify|decode)\s*\(""", "inline"),
    ("session-check", ("javascript", "typescript"),
     r"""\breq\s*\.\s*(?:user|session|isAuthenticated)\b""", "inline"),
    ("next-auth", ("javascript", "typescript"),
     r"""\b(?:getServerSession|getSession|withAuth|useSession)\s*\(""", "inline"),
    # Python
    ("login_required", ("python",), r"""@login_required\b""", "route"),
    ("login-required-mixin", ("python",),
     r"""LoginRequiredMixin|PermissionRequiredMixin""", "class"),
    ("django-permission", ("python",),
     r"""@(?:permission_required|user_passes_test|staff_member_required)\s*\(""", "route"),
    ("drf-permission", ("python",),
     r"""permission_classes\s*=\s*\[([^\]]*)\]""", "class"),
    ("drf-authentication", ("python",),
     r"""authentication_classes\s*=\s*\[([^\]]*)\]""", "class"),
    ("fastapi-depends", ("python",),
     r"""Depends\s*\(\s*([\w.]+)\s*\)""", "route"),
    ("fastapi-security", ("python",),
     r"""Security\s*\(\s*([\w.]+)""", "route"),
    ("flask-before-request", ("python",),
     r"""@\w+\s*\.\s*before_request\b""", "global"),
    ("flask-login", ("python",),
     r"""\bcurrent_user\b|\bis_authenticated\b""", "inline"),
    ("starlette-middleware", ("python",),
     r"""add_middleware\s*\(\s*([\w.]+)""", "global"),
    # Go
    ("go-middleware", ("go",),
     r"""\.\s*Use\s*\(\s*([A-Za-z_][\w.]*)""", "global"),
    ("go-group-middleware", ("go",),
     r"""\.\s*Group\s*\([^)]*?,\s*([A-Za-z_][\w.]*)""", "group"),
    ("go-auth-call", ("go",),
     r"""\b(?:RequireAuth|AuthMiddleware|JWTAuth|Authenticate|requireAuth)""", "inline"),
    # Ruby
    ("authenticate_user!", ("ruby",), r"""\bauthenticate_user!\b|\bauthenticate_\w+!""", "global"),
    ("rails-before-action", ("ruby",),
     r"""before_action\s+:(\w+)""", "global"),
    ("pundit-authorize", ("ruby",), r"""\bauthorize\s+[%@]?\w+""", "inline"),
    ("cancancan", ("ruby",), r"""\b(?:authorize!|can\?|cannot\?)\b""", "inline"),
    ("devise", ("ruby",), r"""\b(?:current_user|user_signed_in\?)\b""", "inline"),
    # PHP
    ("laravel-middleware", ("php",),
     r"""middleware\s*\(\s*\[?\s*['"]([^'"]+)['"]""", "route"),
    ("laravel-auth-check", ("php",),
     r"""\bAuth\s*::\s*(?:check|user|id)\s*\(|\bGate\s*::\s*(?:allows|denies|authorize)\b""",
     "inline"),
    ("symfony-security", ("php",),
     r"""\bisGranted\s*\(|\bdenyAccessUnlessGranted\s*\(""", "inline"),
    ("php-session-auth", ("php",), r"""\$_SESSION\s*\[\s*['"](?:user|auth|admin)""", "inline"),
    # Java
    ("spring-preauthorize", ("java", "kotlin"),
     r"""@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\s*\(([^)]*)\)""", "route"),
    ("spring-security-config", ("java", "kotlin"),
     r"""authorizeHttpRequests|SecurityFilterChain|httpSecurity\s*\.\s*authorize""", "global"),
    ("spring-permit-all", ("java", "kotlin"),
     r"""permitAll\s*\(\s*\)""", "global"),
    ("java-principal", ("java",),
     r"""\b(?:getUserPrincipal|getRemoteUser|Principal)\b""", "inline"),
    # C#
    ("aspnet-authorize", ("csharp",), r"""\[Authorize(?:\s*\(([^)]*)\))?""", "class"),
    ("aspnet-allow-anonymous", ("csharp",), r"""\[AllowAnonymous\]""", "inline"),
    ("aspnet-require-authorization", ("csharp",),
     r"""\.\s*RequireAuthorization\s*\(([^)]*)\)""", "route"),
    ("aspnet-identity", ("csharp",),
     r"""\b(?:User\s*\.\s*Identity|IsAuthenticated)\b""", "inline"),
)

#: Rules whose evidence lives inside a string literal. Everything else is
#: matched against the code-only view, so a docstring cannot raise a mechanism.
AUTH_STRING_RULES = frozenset({"laravel-middleware", "php-session-auth"})

#: Non-HTTP surface. Each is a trust boundary even without a URL.
#: Every rule must name a *mechanism* -- a call, decorator, class, guard or
#: registration -- and never a bare word. The code-only view removes comments
#: and string bodies; these anchors remove the remaining prose, so a file that
#: merely documents ``jsonrpc`` or ``/admin`` is not a surface.
NON_HTTP_RULES: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    ("graphql", ("python", "javascript", "typescript", "ruby", "java", "csharp", "php", "go",
                 "graphql"),
     r"""\btype\s+(?:Query|Mutation|Subscription)\s*\{|\bextend\s+type\s+(?:Query|Mutation|Subscription)"""),
    ("graphql-resolver", ("python", "javascript", "typescript"),
     r"""@(?:Query|Mutation|Subscription)\s*\(|\bresolvers?\s*=\s*\{|@Resolver\s*\("""),
    ("graphql-server", ("python", "javascript", "typescript", "ruby", "java"),
     r"""\b(?:ApolloServer|GraphQLSchema|graphene\.Schema|GraphQL::Schema|makeExecutableSchema)\b"""),
    ("websocket", ("python", "javascript", "typescript", "ruby", "java", "csharp", "go", "php"),
     r"""\b(?:WebSocketServer|new\s+WebSocket|socket\.io|SocketIO|@WebSocketGateway|ActionCable|websocket_route|@ServerEndpoint|HubConnection|gorilla/websocket)\b"""),
    ("grpc-service", ("python", "go", "java", "csharp", "ruby", "php", "protobuf"),
     r"""\brpc\s+\w+\s*\(\s*\w*\s*\)\s*returns|\b(?:add_\w+Servicer_to_server|Register\w+Server|@GrpcMethod|Grpc\.Core)\b"""),
    ("rpc-handler", ("javascript", "typescript", "python"),
     r"""@rpc\s*\.\s*method\b|\bjsonrpc\b|\brpc\.(?:register|handle|expose)\s*\(|\bRPCMethod\b"""),
    ("queue-consumer", ("python", "javascript", "typescript", "ruby", "java", "csharp", "go", "php"),
     r"""@\s*[\w$.]*(?:task|Task|consumer|Consumer)\b|\b(?:Celery|@RabbitListener|@KafkaListener|IHostedService|Sidekiq::Worker|new\s+Queue|Worker\s*\(|@Processor\s*\(|bullmq|asynq)\b"""),
    ("scheduled-job", ("python", "javascript", "typescript", "java", "ruby", "csharp"),
     r"""@Scheduled\s*\(|\bcron\.schedule\s*\(|@periodic_task|schedule\.every\s*\(|BackgroundJob\.|crontab\b"""),
    ("cli-entry", ("python", "javascript", "typescript", "go", "ruby", "php", "java", "csharp"),
     r"""if\s+__name__\s*==\s*|\b(?:commander|cobra\.Command|clap::|click\.command|thor)\b"""),
    ("file-watcher", ("python", "javascript", "typescript", "go"),
     r"""\b(?:watchdog|chokidar|fs\.watch|fsnotify)\b"""),
    ("admin-interface", ("python", "ruby", "php", "java"),
     r"""\badmin\.site\.register\b|\bActiveAdmin\.register\b|\bAdmin::[A-Z]\w*"""),
)

#: Candidate untrusted-input sources, used to describe trust boundaries.
SOURCE_RULES: Tuple[Tuple[str, str], ...] = (
    ("request query", r"""\b(?:request\.args|request\.query|req\.query|\$_GET|params\[:|\bqueryParams\b|c\.Query\()"""),
    ("request body", r"""\b(?:request\.(?:json|form|data|body)|req\.body|\$_POST|params\[|@RequestBody|\[FromBody\]|c\.Bind\()"""),
    ("path parameter", r"""\b(?:request\.view_args|@PathVariable|@Param\(|\[FromRoute\]|c\.Param\(|params\[:\w+\])"""),
    ("headers", r"""\b(?:request\.headers|req\.headers|\$_SERVER\[|\bheaders\.get\(|@RequestHeader|\[FromHeader\])"""),
    ("cookies", r"""\b(?:request\.cookies|req\.cookies|\$_COOKIE|cookies\[)"""),
    ("uploaded file", r"""\b(?:request\.files|req\.file|req\.files|\$_FILES|UploadFile|IFormFile|MultipartFile|multipart\.File)"""),
    ("file path from input", r"""\b(?:open|readFile|send_file|sendFile|File\.read|os\.ReadFile|readfile)\s*\([^)]*(?:request|req\.|params|args|\$_|input)"""),
    ("environment", r"""\b(?:os\.environ|process\.env|os\.Getenv|ENV\[)"""),
)

#: Sanitisation/validation mechanisms, so "validated" can be a fact, not a vibe.
VALIDATOR_RULES: Tuple[Tuple[str, str], ...] = (
    ("schema validation", r"""\b(?:pydantic|BaseModel|marshmallow|jsonschema|zod|yup|joi|class-validator|cerberus|schema\.load|validationSchema)\b"""),
    ("allow-list check", r"""\b(?:whitelist|allowlist|allow_list|in\s+ALLOWED|\.includes\(\s*ALLOWED)\b"""),
    ("escaping/encoding", r"""\b(?:html\.escape|escapeHtml|escape_html|bleach\.clean|MarkupSafe|sanitize|encodeURIComponent|htmlspecialchars|CGI\.escapeHTML)\b"""),
    ("shell quoting", r"""\b(?:shlex\.quote|shellescape|escapeshellarg|ProcessBuilder|subprocess\.run\(\s*\[)\b"""),
    ("path canonicalisation", r"""\b(?:filepath\.Clean|os\.path\.realpath|secure_filename|path\.resolve|Path\(.*\)\.resolve|realpath)\b"""),
    ("parameterised query", r"""\b(?:execute\s*\(\s*[^,)]*,\s*[\[(]|\?\s*\)\s*,|:\w+\s*\)|parameterized|prepared)\b"""),
)


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _next_route_line(text: str, start: int, window: int = 12) -> int:
    """A decorator sits above its route; report the route line, not the decorator."""
    tail = text[start:start + 4000]
    match = re.search(r"^\s*(?:async\s+)?(?:def|function|public|private|protected|func|class|@\w+)",
                      tail, re.MULTILINE)
    return _line_of(text, start) + (tail[:match.start()].count("\n") if match else 0)


#: Receivers that share the ``x.get('/path')`` shape with routers but are HTTP
#: clients. Without this, ``axios.get('/users')`` becomes a phantom endpoint.
#: Rules whose pattern is too generic to stand alone must find a real import in
#: the same file before they may report a route.
TORNADO_ANCHOR = re.compile(r"(?m)^\s*(?:from\s+tornado(?:\.|\s)|import\s+tornado\b)")

JS_RECEIVER_DENY = frozenset({
    "axios", "request", "requests", "http", "https", "client", "agent", "supertest",
    "got", "fetch", "ofetch", "ky", "needle", "superagent", "undici", "node-fetch",
    "$", "jquery", "cy", "browser", "page", "driver", "selenium", "redis", "cache",
    "db", "conn", "connection", "knex", "sequelize", "model", "repository", "repo",
    "res", "response", "req", "this", "that", "config", "logger", "log", "s3", "bucket",
})

#: Route-registration prefixes declared elsewhere in a file: ``r := g.Group("/api")``
#: or ``app.use('/admin', adminRouter)``.
GO_GROUP_RE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\s*:?=\s*[\w.]+\.Group\s*\(\s*\"(?P<prefix>[^\"]+)\"")
JS_MOUNT_RE = re.compile(
    r"\b\w+\.use\s*\(\s*['\"](?P<prefix>[^'\"]+)['\"]\s*,\s*(?P<var>[A-Za-z_$][\w$]*)\s*\)")


#: Rails declares nesting by indentation inside ``do ... end`` blocks. Tracking
#: it is worth the few lines: without it ``namespace :admin do get 'stats'`` was
#: reported as ``/stats``, which is the wrong endpoint.
RAILS_BLOCK_RE = re.compile(
    r"^(?P<indent>\s*)(?P<kind>namespace|scope|resources?)\s+:(?P<name>\w+)", re.MULTILINE)


def _rails_prefix(text: str, line: int, indent: int) -> str:
    """Prefix chain from enclosing namespace/scope blocks, outermost first."""
    chain: List[Tuple[int, str]] = []
    for match in RAILS_BLOCK_RE.finditer(text):
        block_line = _line_of(text, match.start())
        if block_line >= line:
            break
        block_indent = len(match.group("indent"))
        if block_indent >= indent:
            continue
        chain = [entry for entry in chain if entry[0] < block_indent]
        chain.append((block_indent, match.group("name")))
    return "".join(f"/{name}" for _indent, name in chain)


def _expand_controller_token(path: str, text: str) -> str:
    """Resolve ASP.NET ``[controller]`` to the class name, as routing does."""
    if "[controller]" not in path:
        return path
    match = re.search(r"class\s+(\w+)Controller\b", text)
    if not match:
        return path
    return path.replace("[controller]", match.group(1).lower())


def _route_prefixes(text: str, language: str) -> Dict[str, str]:
    """Map a receiver variable to the path prefix it was mounted on."""
    prefixes: Dict[str, str] = {}
    if language == "go":
        for match in GO_GROUP_RE.finditer(text):
            prefixes.setdefault(match.group("var"), match.group("prefix"))
    elif language in ("javascript", "typescript"):
        for match in JS_MOUNT_RE.finditer(text):
            prefixes.setdefault(match.group("var"), match.group("prefix"))
    return prefixes


def _normalise_path(raw: Optional[str], kind: str) -> str:
    """Give a route path a leading slash, without mangling Django regexes."""
    if not raw:
        return ""
    value = raw.strip()
    if kind == "regex" or value.startswith(("^", "[")):
        return value
    if not value.startswith("/"):
        value = "/" + value
    return re.sub(r"(?<=.)/+$", "", value) or "/"


def discover_routes(text: str, rel: str, language: str) -> List[Dict[str, Any]]:
    """Apply every route rule whose language matches; return de-duplicated hits."""
    hits: List[Dict[str, Any]] = []
    prefixes = _route_prefixes(text, language)
    for framework, languages, kind, pattern in ROUTE_RULES:
        if language not in languages:
            continue
        try:
            compiled = re.compile(pattern, re.MULTILINE)
        except re.error:                    # a bad rule must not kill the pass
            continue
        for match in compiled.finditer(text):
            groups = match.groupdict()
            method_raw = groups.get("method")
            path_raw = groups.get("path")
            receiver = groups.get("receiver") or ""
            if framework == "js-router" and receiver.lower() in JS_RECEIVER_DENY:
                continue
            # The Tornado tuple pattern ``("/x", Handler)`` is generic enough to
            # match dictionaries, Django ``path()`` calls and even rule tables,
            # so it needs an import as an anchor. A passing mention of the word
            # "tornado" in a comment or a string is not evidence of Tornado.
            if framework == "tornado" and not TORNADO_ANCHOR.search(text):
                continue

            # Django re_path/url take a regex; say so rather than pretending the
            # pattern is a literal path.
            url_kind = "literal"
            if framework == "django":
                # Any of path/re_path/url routes to a view; the "method" group
                # holds the registration helper, not an HTTP verb.
                url_kind = "regex" if method_raw in ("re_path", "url") else "literal"
                method = "ANY"
            elif framework == "rails" and kind == "resource_route":
                method = "ANY"
                path_raw = "/" + (path_raw or "") if method_raw == "resources" else path_raw
            else:
                method = _http_method(method_raw)

            args = groups.get("args") or ""
            if framework == "flask" and "methods" in args:
                listed = re.search(r"methods\s*=\s*\[([^\]]*)\]", args)
                if listed:
                    method = _http_method(listed.group(1).replace('"', "").replace("'", "")
                                          .replace(" ", "").split(",")[0])
            elif framework == "flask":
                method = "GET"

            path = _normalise_path(path_raw, url_kind)
            prefix = prefixes.get(receiver, "")
            if prefix and path.startswith("/"):
                path = _normalise_path(prefix.rstrip("/") + path, "literal")
            if framework == "rails":
                line_no = _line_of(text, match.start())
                # The rule anchors on ``^\s*``, so match.start() is the line
                # start and the indent lives inside the match, not before it.
                matched = match.group(0)
                indent = len(matched) - len(matched.lstrip())
                if kind == "resource_route" and method_raw in ("namespace", "scope"):
                    # A namespace is a prefix, not an endpoint.
                    kind = "router_prefix"
                else:
                    rails_prefix = _rails_prefix(text, line_no, indent)
                    if rails_prefix:
                        path = _normalise_path(rails_prefix + path, "literal")
            if "[controller]" in path:
                path = _expand_controller_token(path, text)

            hits.append({
                "framework": framework,
                "kind": kind,
                "method": method,
                "path": path,
                "url_kind": url_kind,
                "receiver": receiver,
                "line": _line_of(text, match.start()),
                # The handler symbol when the rule captured one (Django, Express,
                # Go). The raw matched text is kept separately: echoing a
                # truncated source fragment in a report's `handler` field is not
                # a handler, and its unbalanced quotes make downstream rendering
                # unreliable.
                "handler": groups.get("handler") or None,
                "raw": match.group(0)[:160].replace("\n", " ").strip(),
            })
    return hits


def _evidence_line(text: str, index: int, limit: int = 120) -> str:
    """The original line at ``index``, trimmed for a report."""
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    line = text[start:end if end >= 0 else len(text)]
    return line.strip()[:limit]


def discover_auth(text: str, language: str) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    code = mask_non_code(text, language)
    with_strings = mask_non_code(text, language, keep_strings=True)
    for name, languages, pattern, scope in AUTH_RULES:
        if language not in languages:
            continue
        try:
            compiled = re.compile(pattern, re.MULTILINE)
        except re.error:
            continue
        view = with_strings if name in AUTH_STRING_RULES else code
        for match in compiled.finditer(view):
            detail = None
            for group in match.groups():
                if group:
                    detail = group.strip()
                    break
            found.append({
                "mechanism": name,
                "scope": scope,
                "detail": (detail or "")[:120],
                "line": _line_of(text, match.start()),
            })
    return found


def discover_non_http(text: str, language: str) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    code = mask_non_code(text, language)
    for kind, languages, pattern in NON_HTTP_RULES:
        if language not in languages:
            continue
        try:
            compiled = re.compile(pattern, re.MULTILINE)
        except re.error:
            continue
        for match in compiled.finditer(code):
            found.append({"kind": kind, "line": _line_of(text, match.start()),
                          "evidence": _evidence_line(text, match.start())})
    return found


def discover_sources(text: str) -> Dict[str, List[int]]:
    counts: Dict[str, List[int]] = {}
    for label, pattern in SOURCE_RULES:
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue
        lines = [_line_of(text, match.start()) for match in compiled.finditer(text)]
        if lines:
            counts[label] = lines[:20]
    return counts


def discover_validators(text: str) -> Dict[str, List[int]]:
    counts: Dict[str, List[int]] = {}
    for label, pattern in VALIDATOR_RULES:
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue
        lines = [_line_of(text, match.start()) for match in compiled.finditer(text)]
        if lines:
            counts[label] = lines[:20]
    return counts


def _action_candidates(code: str, language: str) -> List[str]:
    """Public method names in a convention-routed controller, in source order."""
    pattern = CONTROLLER_ACTION_PATTERNS.get(language)
    if not pattern:
        return []
    try:
        compiled = re.compile(pattern, re.MULTILINE)
    except re.error:                        # a bad rule must not kill the pass
        return []
    return list(dict.fromkeys(match.group("name") for match in compiled.finditer(code)))


def discover_unenumerable(text: str, language: str) -> List[Dict[str, Any]]:
    """Route-bearing code whose routes no rule can enumerate.

    Two kinds of evidence, strongest first: a class that derives from the
    framework's controller base class -- a route surface even when the file
    declares no route at all -- and a framework namespace or attribute in a file
    where nothing route-shaped matched. The record says *where* the code is and
    *why* it is route-bearing; it never says which URL it serves, because that
    is a convention this pass cannot verify. Runs on the code-only view, so a
    comment that mentions ``Controller`` proves nothing.

    This is a *detector*, not a verdict: an attribute-routed controller matches
    here as well, because a controller class is one either way. ``analyse`` only
    reports a record for a file that produced no route, which is what makes the
    record a coverage gap rather than a second, vaguer description of a route
    this pass already found -- keep that gate at the call site.
    """
    code = mask_non_code(text, language)
    found: List[Dict[str, Any]] = []
    actions: List[str] = []
    for framework, languages, pattern in CONTROLLER_STYLE_RULES:
        if language not in languages:
            continue
        try:
            compiled = re.compile(pattern, re.MULTILINE)
        except re.error:
            continue
        for match in compiled.finditer(code):
            if not actions:
                actions = _action_candidates(code, language)
            found.append({
                "framework": framework,
                "basis": "controller_base_class",
                "class": match.group("name"),
                "base": match.group("base"),
                "line": _line_of(text, match.start()),
                "evidence": _evidence_line(text, match.start()),
                "candidate_actions": actions[:ACTION_SAMPLE_LIMIT],
                "candidate_action_count": len(actions),
            })
    if found:
        return found
    for framework, languages, pattern, basis in CONTROLLER_FRAMEWORK_SIGNALS:
        if language not in languages:
            continue
        try:
            compiled = re.compile(pattern, re.MULTILINE)
        except re.error:
            continue
        match = compiled.search(code)
        if match:
            found.append({
                "framework": framework,
                "basis": basis,
                "class": None,
                "base": None,
                "line": _line_of(text, match.start()),
                "evidence": _evidence_line(text, match.start()),
                "candidate_actions": [],
                "candidate_action_count": 0,
            })
            break
    return found


def _describe_unenumerable(record: Dict[str, Any]) -> str:
    """One ``file:line`` plus why it is route-bearing, for a limitation sentence."""
    where = "%s:%s" % (record.get("file"), record.get("line"))
    if record.get("basis") != "controller_base_class":
        return "%s (%s)" % (where, str(record.get("basis") or "framework present")
                            .replace("_", " "))
    name = record.get("class") or "controller"
    names = list(record.get("candidate_actions") or [])
    count = record.get("candidate_action_count") or len(names)
    if not count:
        return "%s %s (no action method visible)" % (where, name)
    shown = ", ".join(names)
    if count > len(names):
        shown += ", \u2026"
    return "%s %s (%d action method(s): %s)" % (where, name, count, shown)


def _unenumerable_limitations(records: Sequence[Dict[str, Any]]) -> List[str]:
    """One limitation per framework, naming up to eight files and the rest by count."""
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(str(record.get("framework") or "unknown"), []).append(record)
    lines: List[str] = []
    for framework, items in sorted(grouped.items()):
        described = "; ".join(_describe_unenumerable(record) for record in items[:8])
        remainder = "" if len(items) <= 8 else "; and %d more" % (len(items) - 8)
        display = FRAMEWORK_DISPLAY_NAMES.get(framework, framework)
        lines.append(
            "%d file(s) carry %s route-bearing code that no route-discovery rule can "
            "enumerate, because the framework routes it by convention: %s%s. Their entry "
            "points are not listed, so a zero-route result for those files is a coverage "
            "gap, not evidence that they expose no endpoint"
            % (len(items), display, described, remainder))
    return lines


def _controller_prefix(text: str, framework: str, line: int) -> str:
    """Find the class-level prefix that applies to a route on ``line``."""
    for rule_framework, pattern in CONTROLLER_PREFIX_RULES:
        if rule_framework != framework:
            continue
        best = ""
        for match in re.finditer(pattern, text):
            if _line_of(text, match.start()) > line:
                break
            value = (match.groups()[0] if match.groups() else "") or ""
            best = value
        return best
    return ""


def _next_js_route_paths(root: str, files: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Next.js routes are file paths, not calls: derive them from the tree."""
    routes: List[Dict[str, Any]] = []
    for entry in files:
        rel = entry["path"]
        if entry.get("bucket") != "source":
            continue
        match = re.search(r"(?:^|/)(?:pages|app)/(.*?)(?:/route)?\.(?:js|jsx|ts|tsx)$", rel)
        if not match:
            continue
        if "/pages/api/" not in "/" + rel and "/route." not in rel:
            continue
        raw = match.group(1)
        raw = re.sub(r"(?:^|/)index$", "", raw)
        raw = raw.replace("/index", "")
        path = "/" + re.sub(r"\[([^\]]+)\]", r":\1", raw)
        path = re.sub(r"/+$", "", path) or "/"
        routes.append({"framework": "nextjs", "kind": "file_route", "method": "ANY",
                       "path": path, "line": 1, "match_start": 0, "raw": rel})
    return routes


def analyse(root: str, inventory_doc: Optional[Dict[str, Any]] = None,
            technologies: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    root = os.path.abspath(root)
    if inventory_doc is None:
        inventory_doc = inv.inventory(root)
    files = inventory_doc.get("files", [])
    limitations: List[str] = []

    entry_points: List[Dict[str, Any]] = []
    mechanisms: List[Dict[str, Any]] = []
    non_http: List[Dict[str, Any]] = []
    unenumerable: List[Dict[str, Any]] = []
    trust_sources: Dict[str, int] = {}
    validators: Dict[str, int] = {}
    languages_seen: Dict[str, int] = {}

    # Frameworks named by stage 2a win ties between overlapping route rules:
    # ``@app.get`` matches both the Flask and FastAPI patterns.
    FRAMEWORK_TO_RULE = {
        "flask": "flask", "fastapi": "fastapi", "django": "django",
        "django rest framework": "django-drf", "express": "js-router",
        "koa": "js-router", "fastify": "fastify", "nestjs": "nestjs",
        "next.js": "nextjs", "hapi": "hapi", "ruby on rails": "rails",
        "sinatra": "rails", "grape": "rails", "laravel": "laravel",
        "symfony": "symfony", "slim": "slim", "spring boot": "spring",
        "spring": "spring", "asp.net core": "aspnet", "gin": "go-router",
        "echo": "go-router", "chi": "go-router", "gorilla/mux": "go-router",
        "fiber": "go-router", "aiohttp": "aiohttp", "tornado": "tornado",
    }

    #: Generic router rules take their name from the detected framework, so the
    #: report says "Express" rather than the internal "js-router".
    JS_LABEL_ORDER = ("express", "koa", "hapi")
    GO_LABEL_ORDER = ("gin", "echo", "chi", "fiber", "gorilla/mux")
    preferred_rules: set = set()
    web_framework_names: set = set()
    if technologies:
        for row in technologies.get("frameworks", []):
            name = str(row.get("name", "")).lower()
            if row.get("category") == "web_framework":
                web_framework_names.add(name)
            rule = FRAMEWORK_TO_RULE.get(name)
            if rule:
                preferred_rules.add(rule)

    for entry in files:
        if entry.get("bucket") != "source":
            continue
        rel = entry["path"]
        language = entry.get("language")
        if not language:
            continue
        languages_seen[language] = languages_seen.get(language, 0) + 1
        text = _read(os.path.join(root, rel))
        if not text:
            continue

        routes = discover_routes(text, rel, language)
        # Overlapping rules fire on the same line (``@app.get`` matches both the
        # Flask and FastAPI patterns; ``fastify.get`` matches both Fastify and
        # the generic router rule). When technologies.json names the framework,
        # trust it; otherwise keep the first, most specific rule.
        if preferred_rules:
            routes.sort(key=lambda item: (0 if item["framework"] in preferred_rules else 1,
                                          item["line"]))
        # A path-less variant of a route (``[HttpGet]`` next to
        # ``[HttpGet("{id}")]``, or a decorator with no argument) is the same
        # endpoint described twice. Drop it only when a path-bearing hit exists
        # on the same line and method -- two routes can legitimately share a
        # line (a Django urlpatterns list), so the key stays path-sensitive.
        with_path = {(route["line"], route["method"]) for route in routes if route["path"]}
        seen_routes: Dict[Tuple[int, str, str], Dict[str, Any]] = {}
        for route in routes:
            if not route["path"] and (route["line"], route["method"]) in with_path:
                continue
            seen_routes.setdefault((route["line"], route["method"], route["path"]), route)
        routes = sorted((route for route in seen_routes.values()
                         if route["kind"] != "router_prefix"),
                        key=lambda item: (item["line"], item["method"]))
        for route in routes:
            if route["framework"] == "js-router":
                for name in JS_LABEL_ORDER:
                    if name in web_framework_names:
                        route["framework"] = name
                        break
            elif route["framework"] == "go-router":
                for name in GO_LABEL_ORDER:
                    if name in web_framework_names:
                        route["framework"] = name
                        break

        # A file with no route is not the same as a file with no endpoints. When
        # the code is route-bearing by construction -- a controller class the
        # framework routes by convention -- that distinction is the difference
        # between "clean" and "not looked at", so it is counted and stated.
        if not routes:
            for record in discover_unenumerable(text, language):
                unenumerable.append({"file": rel, "language": language, **record})

        auth = discover_auth(text, language)
        mechanisms.extend({"file": rel, **item} for item in auth)

        # Debounce auth hits against routes: a decorator applies to the nearest
        # route within a few lines, never to every route in the file. Without
        # this, one ``@UseGuards`` blessed three unrelated endpoints.
        route_scoped = [item for item in auth if item["scope"] in ("route", "class", "inline")]
        assigned: Dict[int, List[Dict[str, Any]]] = {}
        for item in route_scoped:
            if not routes:
                continue
            nearest = min(routes, key=lambda route: (abs(route["line"] - item["line"]),
                                                     route["line"] < item["line"]))
            if abs(nearest["line"] - item["line"]) <= 4:
                assigned.setdefault(id(nearest), []).append(item)
        global_auth = [item for item in auth if item["scope"] == "global"]
        for route in routes:
            prefix = _controller_prefix(text, route["framework"], route["line"])
            path = route["path"]
            if prefix:
                path = "/" + "/".join(part for part in (prefix.strip("/"), path.strip("/")) if part)
            if "[controller]" in path:
                path = _expand_controller_token(path, text)
            applicable = [item for item in global_auth if item["line"] <= route["line"]]
            applicable.extend(assigned.get(id(route), []))
            # An explicit per-route argument is stronger evidence than a
            # mechanism detected elsewhere in the file.
            explicit = [item for item in applicable
                        if item["scope"] in ("route", "inline")
                        and item["mechanism"] != "aspnet-allow-anonymous"]
            if applicable:
                assessment = "mechanism_visible"
                confidence = "HIGH" if explicit else "MEDIUM"
            else:
                assessment = "no_mechanism_detected"
                confidence = "MEDIUM"
            entry_points.append({
                "id": None,                     # assigned deterministically below
                "kind": route["kind"],
                "framework": route["framework"],
                "method": route["method"],
                "path": path or route["path"],
                "handler": route.get("handler"),
                "file": rel,
                "line": route["line"],
                "auth": {
                    "assessment": assessment,
                    "confidence": confidence,
                    "mechanisms": sorted({item["mechanism"] for item in applicable}),
                    "evidence": [{"mechanism": item["mechanism"], "line": item["line"],
                                  "scope": item["scope"]} for item in applicable][:10],
                },
            })

        # One surface per kind per file. A rule that fires on every call
        # describes one mechanism, not N entry points: 84 ``argparse`` tokens
        # were 16 CLI tools.
        seen_non_http: Dict[str, Dict[str, Any]] = {}
        for item in discover_non_http(text, language):
            seen_non_http.setdefault(item["kind"], item)
        for item in seen_non_http.values():
            non_http.append({"file": rel, "language": language, **item})

        for label, lines in discover_sources(text).items():
            trust_sources[label] = trust_sources.get(label, 0) + len(lines)
        for label, lines in discover_validators(text).items():
            validators[label] = validators.get(label, 0) + len(lines)

    entry_points.extend(_next_js_route_paths(root, files))

    entry_points.sort(key=lambda item: (item["file"], item["line"], item["method"], item["path"]))
    for index, item in enumerate(entry_points, start=1):
        item["id"] = f"EP-{index:03d}"
    mechanisms.sort(key=lambda item: (item["file"], item["line"], item["mechanism"]))
    non_http.sort(key=lambda item: (item["kind"], item["file"], item["line"]))
    unenumerable.sort(key=lambda item: (item["framework"], item["file"], item["line"]))

    unauthenticated = [item for item in entry_points
                       if item["auth"]["assessment"] == "no_mechanism_detected"]
    by_framework: Dict[str, int] = {}
    by_method: Dict[str, int] = {}
    for item in entry_points:
        by_framework[item["framework"]] = by_framework.get(item["framework"], 0) + 1
        by_method[item["method"]] = by_method.get(item["method"], 0) + 1

    non_http_counts: Dict[str, int] = {}
    for item in non_http:
        non_http_counts[item["kind"]] = non_http_counts.get(item["kind"], 0) + 1

    if not entry_points:
        limitations.append("no HTTP entry points detected: either this is not a networked "
                           "application or routes are registered by a mechanism this pass does "
                           "not model (dynamic registration, annotations built at runtime)")
    if unauthenticated:
        limitations.append(
            f"{len(unauthenticated)} entry point(s) have no visible authentication mechanism. "
            f"Absence of a detected mechanism is not proof of missing authentication: verify "
            f"before reporting (references/false-positive-handling.md)")
    limitations.extend(_unenumerable_limitations(unenumerable))
    if technologies is not None:
        modelled = {framework for framework, *_ in ROUTE_RULES}
        # Only real web frameworks matter here; libraries such as boto3 are not
        # route surfaces and listing them would be noise, not a limitation.
        unmodelled = sorted(name for name in web_framework_names
                            if name not in modelled
                            and FRAMEWORK_TO_RULE.get(name) not in modelled)
        if unmodelled:
            limitations.append("detected web framework(s) with no route-discovery rule; their "
                               "entry points are not enumerated: " + ", ".join(unmodelled))

    return {
        "stage": "attack_surface",
        "schema_version": inv.SCHEMA_VERSION,
        "tool": {"name": "attack_surface.py", "version": TOOL_VERSION},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root": root,
        "snapshot": {
            "commit": inventory_doc.get("git", {}).get("commit"),
            "branch": inventory_doc.get("git", {}).get("branch"),
        },
        "summary": {
            "entry_points": len(entry_points),
            "http_routes": sum(1 for item in entry_points if item["kind"] in
                               ("http_route", "file_route", "resource_route")),
            "without_visible_auth": len(unauthenticated),
            "auth_mechanisms": len(mechanisms),
            "non_http_surfaces": len(non_http),
            "unenumerable_routes": len(unenumerable),
            "by_framework": dict(sorted(by_framework.items())),
            "by_method": dict(sorted(by_method.items())),
            "non_http_by_kind": dict(sorted(non_http_counts.items())),
        },
        "entry_points": entry_points,
        "auth_mechanisms": mechanisms,
        "auth_summary": {
            "mechanisms": sorted({item["mechanism"] for item in mechanisms}),
            "files_with_mechanisms": sorted({item["file"] for item in mechanisms}),
        },
        "non_http": non_http,
        "unenumerable_routes": unenumerable,
        "trust_boundaries": {
            "untrusted_sources": dict(sorted(trust_sources.items())),
            "input_occurrences": sum(trust_sources.values()),
            "validators": dict(sorted(validators.items())),
            "validator_occurrences": sum(validators.values()),
            "note": ("Sources and validators are counted per file, not per dataflow path: a "
                     "validator elsewhere in the file does not prove this input is validated."),
        },
        "languages_scanned": dict(sorted(languages_seen.items())),
        "limitations": limitations,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attack_surface.py",
        description="Enumerate HTTP and non-HTTP entry points, auth mechanisms and trust "
                    "boundaries (audit stage 2).",
        epilog="Prints JSON on stdout. Read-only.",
    )
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument("--inventory", help="reuse inventory.json")
    parser.add_argument("--technologies", help="reuse technologies.json for limitation reporting")
    parser.add_argument("--out", help="write JSON here instead of stdout")
    parser.add_argument("--indent", type=int, default=2, help="JSON indent (default 2)")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    inventory_doc = json.load(open(args.inventory, encoding="utf-8")) if args.inventory else None
    technologies = json.load(open(args.technologies, encoding="utf-8")) if args.technologies else None
    root = args.root
    if inventory_doc and root == ".":
        root = inventory_doc.get("root", ".")
    document = analyse(root, inventory_doc, technologies)
    text = json.dumps(document, indent=args.indent, ensure_ascii=False) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(json.dumps({"written": args.out, **document["summary"]}))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

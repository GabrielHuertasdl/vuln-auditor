"""
Auto-remediation Templates — Phase 2.

Maps OWASP categories and CWE IDs to concrete, stack-specific code fixes.
Returns copy-pasteable snippets engineers can drop directly into their codebase.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.schemas import Finding


@dataclass
class RemediationTemplate:
    id: str
    title: str
    description: str
    effort: str        # minutes | hours | days
    owasp_refs: list[str]
    cwe_refs: list[int]
    stacks: list["StackSnippet"]


@dataclass
class StackSnippet:
    stack: str         # nginx | apache | django | laravel | express | spring | php | generic
    language: str      # nginx_conf | python | php | javascript | java | yaml
    label: str         # human-readable stack name
    code: str


# ── Template library ──────────────────────────────────────────────────────────

_TEMPLATES: list[RemediationTemplate] = [

    # ── HSTS / Transport Security ──────────────────────────────────────────────
    RemediationTemplate(
        id="hsts-missing",
        title="Add HTTP Strict Transport Security (HSTS)",
        description="Forces browsers to use HTTPS exclusively. Prevents SSL-stripping attacks.",
        effort="minutes",
        owasp_refs=["A02:2021", "A05:2021"],
        cwe_refs=[319, 326],
        stacks=[
            StackSnippet("nginx", "nginx_conf", "Nginx",
                code="""# Add inside your server {} block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;"""),
            StackSnippet("apache", "apache_conf", "Apache",
                code="""# Add to .htaccess or VirtualHost
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload\""""),
            StackSnippet("django", "python", "Django",
                code="""# settings.py
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True"""),
            StackSnippet("express", "javascript", "Express / Node",
                code="""// npm install helmet
const helmet = require('helmet')
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }))"""),
            StackSnippet("spring", "java", "Spring Boot",
                code="""// SecurityConfig.java
http.headers()
    .httpStrictTransportSecurity()
    .includeSubDomains(true)
    .maxAgeInSeconds(31536000);"""),
        ]
    ),

    # ── Content Security Policy ────────────────────────────────────────────────
    RemediationTemplate(
        id="csp-missing",
        title="Implement Content Security Policy (CSP)",
        description="Prevents XSS by whitelisting trusted script sources. Start in report-only mode.",
        effort="hours",
        owasp_refs=["A03:2021"],
        cwe_refs=[79, 80],
        stacks=[
            StackSnippet("nginx", "nginx_conf", "Nginx",
                code="""add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;"""),
            StackSnippet("django", "python", "Django (django-csp)",
                code="""# pip install django-csp
# settings.py
INSTALLED_APPS += ['csp']
MIDDLEWARE += ['csp.middleware.CSPMiddleware']
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FRAME_ANCESTORS = ("'none'",)"""),
            StackSnippet("laravel", "php", "Laravel",
                code="""// app/Http/Middleware/SecurityHeaders.php
$response->headers->set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none';"
);"""),
            StackSnippet("express", "javascript", "Express / Node",
                code="""// npm install helmet
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    frameAncestors: ["'none'"],
  },
}))"""),
        ]
    ),

    # ── SQL Injection ──────────────────────────────────────────────────────────
    RemediationTemplate(
        id="sql-injection",
        title="Fix SQL Injection — Use Parameterized Queries",
        description="Never interpolate user input into SQL strings. Use ORM or prepared statements.",
        effort="hours",
        owasp_refs=["A03:2021"],
        cwe_refs=[89],
        stacks=[
            StackSnippet("django", "python", "Django ORM",
                code="""# ❌ VULNERABLE
User.objects.raw(f"SELECT * FROM users WHERE name = '{user_input}'")

# ✅ SAFE — Django ORM
User.objects.filter(name=user_input)

# ✅ SAFE — raw SQL with params
User.objects.raw("SELECT * FROM users WHERE name = %s", [user_input])"""),
            StackSnippet("laravel", "php", "Laravel Eloquent",
                code="""// ❌ VULNERABLE
DB::select("SELECT * FROM users WHERE name = '$name'");

// ✅ SAFE — Eloquent
User::where('name', $name)->get();

// ✅ SAFE — Query Builder with bindings
DB::select('SELECT * FROM users WHERE name = ?', [$name]);"""),
            StackSnippet("express", "javascript", "Node / mysql2",
                code="""// ❌ VULNERABLE
db.query(`SELECT * FROM users WHERE name = '${userInput}'`)

// ✅ SAFE — prepared statement
db.execute('SELECT * FROM users WHERE name = ?', [userInput])

// ✅ SAFE — Knex.js
knex('users').where('name', userInput)"""),
            StackSnippet("spring", "java", "Spring Data / JPA",
                code="""// ❌ VULNERABLE
entityManager.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'");

// ✅ SAFE — JPQL with parameters
entityManager.createQuery("SELECT u FROM User u WHERE u.name = :name", User.class)
             .setParameter("name", name)
             .getResultList();

// ✅ SAFE — Spring Data Repository
userRepository.findByName(name);"""),
            StackSnippet("php", "php", "PHP PDO",
                code="""// ❌ VULNERABLE
$result = mysqli_query($conn, "SELECT * FROM users WHERE name = '$name'");

// ✅ SAFE — PDO prepared statement
$stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?');
$stmt->execute([$name]);
$result = $stmt->fetchAll();"""),
        ]
    ),

    # ── XSS ───────────────────────────────────────────────────────────────────
    RemediationTemplate(
        id="xss-reflected",
        title="Fix Cross-Site Scripting (XSS) — Output Encoding",
        description="Encode all user-controlled data before rendering in HTML context.",
        effort="hours",
        owasp_refs=["A03:2021"],
        cwe_refs=[79, 80, 116],
        stacks=[
            StackSnippet("django", "python", "Django Templates",
                code="""# Django auto-escapes by default in templates
# ❌ VULNERABLE — mark_safe bypasses escaping
from django.utils.safestring import mark_safe
output = mark_safe(user_input)  # NEVER do this with user data

# ✅ SAFE — default template rendering
{{ user_input }}  {# automatically HTML-escaped #}

# ✅ SAFE — manual escape in Python
from django.utils.html import escape
safe_output = escape(user_input)"""),
            StackSnippet("laravel", "php", "Laravel Blade",
                code="""{{-- ❌ VULNERABLE — raw output --}}
{!! $userInput !!}

{{-- ✅ SAFE — Blade auto-escapes --}}
{{ $userInput }}

<?php
// ✅ SAFE — manual escape
use Illuminate\\Support\\Str;
$safe = htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');"""),
            StackSnippet("express", "javascript", "Node / React",
                code="""// ❌ VULNERABLE — dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// ✅ SAFE — React auto-escapes JSX
<div>{userInput}</div>

// ✅ SAFE — server-side with DOMPurify
import DOMPurify from 'dompurify'
const clean = DOMPurify.sanitize(userInput)"""),
            StackSnippet("spring", "java", "Thymeleaf / Spring MVC",
                code="""<!-- ❌ VULNERABLE — unescaped -->
<p th:utext="${userInput}"></p>

<!-- ✅ SAFE — Thymeleaf auto-escapes -->
<p th:text="${userInput}"></p>

// Java — OWASP Java Encoder
import org.owasp.encoder.Encode;
String safe = Encode.forHtml(userInput);"""),
        ]
    ),

    # ── Broken Auth / Session ──────────────────────────────────────────────────
    RemediationTemplate(
        id="broken-auth",
        title="Harden Authentication & Session Management",
        description="Enforce strong session configuration, token rotation, and secure cookie flags.",
        effort="hours",
        owasp_refs=["A07:2021"],
        cwe_refs=[287, 384, 613],
        stacks=[
            StackSnippet("django", "python", "Django",
                code="""# settings.py
SESSION_COOKIE_SECURE = True      # HTTPS only
SESSION_COOKIE_HTTPONLY = True     # No JS access
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 3600          # 1 hour
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True"""),
            StackSnippet("express", "javascript", "Express / Node",
                code="""// npm install express-session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,    // HTTPS only
    httpOnly: true,  // No JS access
    sameSite: 'strict',
    maxAge: 3600000  // 1 hour
  }
}))"""),
            StackSnippet("laravel", "php", "Laravel",
                code="""// config/session.php
'secure' => true,        // HTTPS only
'http_only' => true,     // No JS access
'same_site' => 'strict',
'lifetime' => 60,        // 1 hour"""),
            StackSnippet("spring", "java", "Spring Security",
                code="""// SecurityConfig.java
http.sessionManagement()
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
    .maximumSessions(1)
    .and()
    .sessionFixation().migrateSession();

// application.properties
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.same-site=strict
server.servlet.session.timeout=3600"""),
        ]
    ),

    # ── CORS Misconfiguration ─────────────────────────────────────────────────
    RemediationTemplate(
        id="cors-misconfiguration",
        title="Fix CORS Misconfiguration",
        description="Restrict Access-Control-Allow-Origin to trusted domains. Never use wildcard with credentials.",
        effort="minutes",
        owasp_refs=["A05:2021"],
        cwe_refs=[942],
        stacks=[
            StackSnippet("nginx", "nginx_conf", "Nginx",
                code="""# Replace wildcard with explicit allowed origins
map $http_origin $cors_origin {
    "https://app.yourcompany.com" "https://app.yourcompany.com";
    default "";
}
add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;
add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;"""),
            StackSnippet("django", "python", "Django (django-cors-headers)",
                code="""# pip install django-cors-headers
# settings.py
CORS_ALLOWED_ORIGINS = [
    "https://app.yourcompany.com",
    "https://dashboard.yourcompany.com",
]
CORS_ALLOW_CREDENTIALS = True
# ❌ Never use: CORS_ALLOW_ALL_ORIGINS = True  (with credentials)"""),
            StackSnippet("express", "javascript", "Express / Node",
                code="""// npm install cors
const allowedOrigins = ['https://app.yourcompany.com']
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true)
    } else {
      callback(new Error('Not allowed by CORS'))
    }
  },
  credentials: true
}))"""),
            StackSnippet("spring", "java", "Spring Boot",
                code="""// SecurityConfig.java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("https://app.yourcompany.com"));
    config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
    config.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}"""),
        ]
    ),

    # ── Clickjacking / X-Frame-Options ────────────────────────────────────────
    RemediationTemplate(
        id="clickjacking",
        title="Prevent Clickjacking — X-Frame-Options / frame-ancestors",
        description="Block your pages from being embedded in iframes on other domains.",
        effort="minutes",
        owasp_refs=["A05:2021"],
        cwe_refs=[1021],
        stacks=[
            StackSnippet("nginx", "nginx_conf", "Nginx",
                code="""add_header X-Frame-Options "DENY" always;
# Or, using modern CSP (preferred):
add_header Content-Security-Policy "frame-ancestors 'none';" always;"""),
            StackSnippet("apache", "apache_conf", "Apache",
                code="""Header always set X-Frame-Options "DENY\""""),
            StackSnippet("django", "python", "Django",
                code="""# settings.py
MIDDLEWARE = [
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    ...
]
X_FRAME_OPTIONS = 'DENY'"""),
            StackSnippet("express", "javascript", "Express / Node",
                code="""// npm install helmet
app.use(helmet.frameguard({ action: 'deny' }))"""),
        ]
    ),

    # ── Sensitive Data Exposure ────────────────────────────────────────────────
    RemediationTemplate(
        id="sensitive-data-exposure",
        title="Protect Sensitive Data in Responses",
        description="Remove debug info, stack traces, and internal paths from API responses.",
        effort="hours",
        owasp_refs=["A02:2021"],
        cwe_refs=[200, 209, 532],
        stacks=[
            StackSnippet("django", "python", "Django",
                code="""# settings.py (production)
DEBUG = False
ALLOWED_HOSTS = ['yourcompany.com']

# Custom error handler — don't leak internals
# urls.py
handler500 = 'myapp.views.custom_500'

# views.py
def custom_500(request):
    return JsonResponse({'error': 'Internal server error'}, status=500)"""),
            StackSnippet("express", "javascript", "Express / Node",
                code="""// Production error handler — never expose stack traces
app.use((err, req, res, next) => {
  console.error(err)  // log internally
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message
  })
})"""),
            StackSnippet("spring", "java", "Spring Boot",
                code="""# application-production.properties
server.error.include-stacktrace=never
server.error.include-message=never
server.error.include-binding-errors=never
server.error.include-exception=false"""),
            StackSnippet("laravel", "php", "Laravel",
                code="""// config/app.php
'debug' => env('APP_DEBUG', false),  // false in production

// .env (production)
APP_ENV=production
APP_DEBUG=false"""),
        ]
    ),
]


# Index by OWASP and CWE for fast lookup
_BY_OWASP: dict[str, list[RemediationTemplate]] = {}
_BY_CWE: dict[int, list[RemediationTemplate]] = {}

for _t in _TEMPLATES:
    for _ref in _t.owasp_refs:
        _BY_OWASP.setdefault(_ref, []).append(_t)
    for _cwe in _t.cwe_refs:
        _BY_CWE.setdefault(_cwe, []).append(_t)


# ── Public API ────────────────────────────────────────────────────────────────

def get_remediation_for_finding(finding: "Finding") -> list[RemediationTemplate]:
    """Return relevant remediation templates for a finding, ordered by relevance."""
    seen: set[str] = set()
    results: list[RemediationTemplate] = []

    # Match by CWE (most precise)
    for cwe in finding.cwe_ids:
        for tmpl in _BY_CWE.get(cwe, []):
            if tmpl.id not in seen:
                seen.add(tmpl.id)
                results.append(tmpl)

    # Match by OWASP category — normalize "A03:2021-Injection" → "A03:2021"
    if finding.owasp_category:
        key = finding.owasp_category.split("-")[0].strip()
        for tmpl in _BY_OWASP.get(key, []):
            if tmpl.id not in seen:
                seen.add(tmpl.id)
                results.append(tmpl)

    return results


def get_all_templates() -> list[RemediationTemplate]:
    return list(_TEMPLATES)


def get_template_by_id(template_id: str) -> RemediationTemplate | None:
    return next((t for t in _TEMPLATES if t.id == template_id), None)


def filter_snippets_for_stack(
    template: RemediationTemplate, detected_stacks: list[str]
) -> list[StackSnippet]:
    """Return only the snippets relevant to the detected tech stack, or all if unknown."""
    if not detected_stacks:
        return template.stacks
    stacks_lower = {s.lower() for s in detected_stacks}
    matching = [s for s in template.stacks if s.stack in stacks_lower]
    return matching if matching else template.stacks

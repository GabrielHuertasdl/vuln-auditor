"""
Stack detection — infers technology stack from scanner output.

Reads raw findings (nmap service info, ZAP/Nikto evidence) and returns
a deduplicated list of detected technologies.

Detection is passive and evidence-based: we only assert what the scanner
output directly implies. No active probing is performed here.
"""
from __future__ import annotations

import re
import urllib.parse

from core.schemas import RawFinding, ToolName

# ── Detection patterns ─────────────────────────────────────────────────────────
# Each entry: (regex pattern, technology label)
# Applied to relevant fields depending on the context.

_SERVER_HEADER_PATTERNS: list[tuple[str, str]] = [
    (r"apache", "Apache"),
    (r"nginx", "Nginx"),
    (r"microsoft-iis", "IIS"),
    (r"litespeed", "LiteSpeed"),
    (r"tomcat", "Tomcat"),
    (r"jetty", "Jetty"),
    (r"gunicorn", "Python/Gunicorn"),
    (r"uvicorn", "Python/Uvicorn"),
    (r"caddy", "Caddy"),
]

_POWERED_BY_PATTERNS: list[tuple[str, str]] = [
    (r"php", "PHP"),
    (r"asp\.net", "ASP.NET"),
    (r"node\.js", "Node.js"),
    (r"express", "Node.js/Express"),
    (r"django", "Django"),
    (r"rails", "Ruby on Rails"),
    (r"laravel", "Laravel"),
    (r"flask", "Flask"),
    (r"fastapi", "FastAPI"),
    (r"spring", "Java/Spring"),
    (r"wordpress", "WordPress"),
]

_COOKIE_PATTERNS: list[tuple[str, str]] = [
    (r"phpsessid", "PHP"),
    (r"jsessionid", "Java/Servlet"),
    (r"_rails_session", "Ruby on Rails"),
    (r"wordpress_logged_in|wp-settings", "WordPress"),
    (r"connect\.sid|express\.sid", "Node.js/Express"),
    (r"csrftoken|sessionid", "Django"),
    (r"laravel_session", "Laravel"),
    (r"asp\.net_sessionid|\.aspxauth", "ASP.NET"),
]

_PATH_PATTERNS: list[tuple[str, str]] = [
    (r"/wp-content/|/wp-admin/|wp-login\.php", "WordPress"),
    (r"/drupal/|sites/default/files", "Drupal"),
    (r"/joomla/|/components/com_", "Joomla"),
    (r"/magento/|/mage/", "Magento"),
    (r"/api/v\d+/|/rest/v\d+/|/graphql", "API"),
    (r"\.php(\?|$|/)", "PHP"),
    (r"\.aspx?(\?|$|/)", "ASP.NET"),
    (r"\.jsp(\?|$|/)", "Java/JSP"),
    (r"\.do(\?|$|/)", "Java/Struts"),
]

_NMAP_SERVICE_PATTERNS: list[tuple[str, str]] = [
    (r"apache httpd", "Apache"),
    (r"nginx", "Nginx"),
    (r"microsoft-iis", "IIS"),
    (r"tomcat", "Tomcat"),
    (r"node\.?js", "Node.js"),
    (r"openssh", "OpenSSH"),
    (r"mysql", "MySQL"),
    (r"postgresql", "PostgreSQL"),
    (r"mongodb", "MongoDB"),
    (r"redis", "Redis"),
    (r"elasticsearch", "Elasticsearch"),
    (r"php", "PHP"),
]

_WAF_PATTERNS: list[tuple[str, str]] = [
    (r"cloudflare", "WAF/Cloudflare"),
    (r"sucuri", "WAF/Sucuri"),
    (r"incapsula|imperva", "WAF/Imperva"),
    (r"akamai", "WAF/Akamai"),
    (r"f5 big-ip|f5-trafficshield", "WAF/F5"),
    (r"barracuda", "WAF/Barracuda"),
    (r"mod_security|modsecurity", "WAF/ModSecurity"),
    (r"aws waf|awswaf", "WAF/AWS"),
]


def detect_stack(raw_findings: list[RawFinding], target_url: str = "") -> list[str]:
    """
    Infer technology stack from raw scanner findings.

    Sources examined:
      - Nmap: service descriptions in finding titles/descriptions
      - ZAP/Nikto: evidence strings (may contain response headers, cookies, paths)
      - URL paths from all findings
      - Target URL itself

    Returns a deduplicated, sorted list of technology labels.
    No active probing — purely passive analysis of existing scanner output.
    """
    detected: set[str] = set()

    for raw in raw_findings:
        full_text = f"{raw.title} {raw.description} {raw.evidence or ''}".lower()
        path = raw.path.lower()

        if raw.tool == ToolName.NMAP:
            _match_patterns(raw.description.lower(), _NMAP_SERVICE_PATTERNS, detected)

        # Server header hints appear in ZAP/Nikto evidence
        _match_patterns(full_text, _SERVER_HEADER_PATTERNS, detected)
        _match_patterns(full_text, _POWERED_BY_PATTERNS, detected)
        _match_patterns(full_text, _COOKIE_PATTERNS, detected)
        _match_patterns(full_text, _WAF_PATTERNS, detected)
        _match_patterns(path, _PATH_PATTERNS, detected)

    # Also check the target URL itself
    if target_url:
        parsed = urllib.parse.urlparse(target_url)
        _match_patterns(parsed.path.lower(), _PATH_PATTERNS, detected)

    return sorted(detected)


def is_api_target(raw_findings: list[RawFinding], target_url: str = "") -> bool:
    """
    Heuristic: returns True if the target appears to be an API endpoint.

    Signals:
      - Path matches /api/, /v1/, /graphql, /rest/, /swagger, /openapi
      - Evidence contains Content-Type: application/json
      - Target URL contains API path segment
    """
    api_path_re = re.compile(r"/api/|/v\d+/|/graphql|/rest/|/swagger|/openapi", re.IGNORECASE)

    if target_url and api_path_re.search(target_url):
        return True

    for raw in raw_findings:
        text = f"{raw.path} {raw.evidence or ''}"
        if api_path_re.search(text):
            return True
        if "application/json" in (raw.evidence or "").lower():
            return True

    return False


def _match_patterns(text: str, patterns: list[tuple[str, str]], result: set[str]) -> None:
    for pattern, label in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            result.add(label)

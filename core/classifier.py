"""
Maps findings to OWASP Top 10 2021 and OWASP API Security Top 10 2023.

Classification is deterministic and rule-based:
  1. CWE-to-OWASP exact match (highest precision)
  2. Keyword match on title + description (broader, lower precision)

OWASP API Top 10 is applied when the finding appears to be API-related
(based on path, evidence, or detected stack context).
"""
from __future__ import annotations

from core.schemas import Finding

# ── OWASP Top 10 2021 ─────────────────────────────────────────────────────────

A01 = "A01:2021-Broken Access Control"
A02 = "A02:2021-Cryptographic Failures"
A03 = "A03:2021-Injection"
A04 = "A04:2021-Insecure Design"
A05 = "A05:2021-Security Misconfiguration"
A06 = "A06:2021-Vulnerable and Outdated Components"
A07 = "A07:2021-Identification and Authentication Failures"
A08 = "A08:2021-Software and Data Integrity Failures"
A09 = "A09:2021-Security Logging and Monitoring Failures"
A10 = "A10:2021-Server-Side Request Forgery"

CWE_TO_OWASP: dict[int, str] = {
    # A01 — Broken Access Control
    22: A01, 23: A01, 59: A01, 284: A01, 285: A01, 639: A01, 601: A01,
    # A02 — Cryptographic Failures
    310: A02, 319: A02, 326: A02, 327: A02, 328: A02, 359: A02,
    # A03 — Injection
    77: A03, 78: A03, 79: A03, 89: A03, 90: A03, 91: A03,
    94: A03, 95: A03, 643: A03, 611: A03,
    # A04 — Insecure Design
    73: A04, 352: A04,
    # A05 — Security Misconfiguration
    16: A05, 693: A05, 200: A05, 1021: A05, 1392: A05,
    # A06 — Vulnerable and Outdated Components
    1035: A06, 1104: A06,
    # A07 — Identification and Authentication Failures
    287: A07, 306: A07, 307: A07, 384: A07, 521: A07, 613: A07,
    # A08 — Software and Data Integrity Failures
    494: A08, 502: A08, 829: A08,
    # A09 — Logging and Monitoring
    778: A09,
    # A10 — SSRF
    918: A10,
}

# ── OWASP API Security Top 10 2023 ────────────────────────────────────────────

API1 = "API1:2023-Broken Object Level Authorization"
API2 = "API2:2023-Broken Authentication"
API3 = "API3:2023-Broken Object Property Level Authorization"
API4 = "API4:2023-Unrestricted Resource Consumption"
API5 = "API5:2023-Broken Function Level Authorization"
API6 = "API6:2023-Unrestricted Access to Sensitive Business Flows"
API7 = "API7:2023-Server Side Request Forgery"
API8 = "API8:2023-Security Misconfiguration"
API9 = "API9:2023-Improper Inventory Management"
API10 = "API10:2023-Unsafe Consumption of APIs"

CWE_TO_OWASP_API: dict[int, str] = {
    639: API1, 284: API1, 285: API1,
    287: API2, 306: API2, 384: API2, 613: API2,
    200: API3, 359: API3,
    770: API4, 400: API4,
    285: API5, 284: API5,
    918: API7,
    16: API8, 693: API8, 1021: API8,
    1104: API9,
}

# ── Keyword rules (fallback when no CWE is available) ─────────────────────────
# Format: ([keywords], owasp_top10_category, owasp_api_category_or_None, [inferred_cwes])

KEYWORD_RULES: list[tuple[list[str], str, str | None, list[int]]] = [
    (["sql injection", "sqli"],                             A03, None,  [89]),
    (["cross-site scripting", "xss", "reflected xss", "stored xss"], A03, None, [79]),
    (["command injection", "os injection", "shell injection"], A03, None, [78]),
    (["path traversal", "directory traversal", "lfi", "local file inclusion"], A01, None, [22]),
    (["ssrf", "server-side request forgery"],               A10, API7, [918]),
    (["xml external entity", "xxe"],                        A03, None,  [611]),
    (["insecure deserialization", "deserialization"],        A08, None,  [502]),
    (["csrf", "cross-site request forgery"],                A04, None,  [352]),
    (["authentication bypass", "broken auth", "weak password"], A07, API2, [287]),
    (["session fixation", "session hijack"],                A07, API2,  [384]),
    (["open redirect"],                                     A01, None,  [601]),
    (["clickjacking", "x-frame-options", "frame-ancestors"], A05, API8, [693]),
    (["ssl", "tls", "certificate", "https", "weak cipher"], A02, None,  [326]),
    (["information disclosure", "server version", "stack trace", "debug"], A05, API3, [200]),
    (["default credentials", "default password"],           A05, API8,  [1392]),
    (["outdated", "vulnerable component", "cve-"],          A06, API9,  [1035]),
    (["missing security header", "content-security-policy", "x-content-type"], A05, API8, [16]),
    (["broken object", "idor", "insecure direct object"],   A01, API1,  [639]),
    (["rate limit", "throttl", "brute force"],              A07, API4,  [307]),
    (["improper inventory", "shadow api", "undocumented"],  A05, API9,  [1104]),
]

# API-specific path signals that suggest the finding relates to an API
_API_PATH_SIGNALS = ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/swagger")


def classify(finding: Finding) -> Finding:
    """
    Assign OWASP Top 10 (2021) and API Top 10 (2023) categories.

    Stage 1: exact CWE match — highest confidence
    Stage 2: keyword match on title + description — broader coverage

    OWASP API category is set when:
      - CWE has a direct API mapping, or
      - Keyword rule has an API mapping, or
      - The finding path suggests an API endpoint
    """
    is_api_path = any(sig in (finding.path or "").lower() for sig in _API_PATH_SIGNALS)
    updates: dict = {}

    # Stage 1: CWE-exact match
    for cwe in finding.cwe_ids:
        if cwe in CWE_TO_OWASP and not updates.get("owasp_category"):
            updates["owasp_category"] = CWE_TO_OWASP[cwe]
        if cwe in CWE_TO_OWASP_API and not updates.get("owasp_api_category"):
            updates["owasp_api_category"] = CWE_TO_OWASP_API[cwe]

    if updates.get("owasp_category"):
        return finding.model_copy(update=updates)

    # Stage 2: keyword match
    text = (finding.title + " " + finding.description).lower()
    for keywords, owasp_cat, api_cat, inferred_cwes in KEYWORD_RULES:
        if any(k in text for k in keywords):
            cwe_ids = list(set(finding.cwe_ids) | set(inferred_cwes))
            result_updates: dict = {"owasp_category": owasp_cat, "cwe_ids": cwe_ids}
            if api_cat and (is_api_path or api_cat):
                result_updates["owasp_api_category"] = api_cat
            return finding.model_copy(update=result_updates)

    return finding

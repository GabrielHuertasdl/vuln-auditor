"""
API Reachability Analysis — Phase 2.

Determines how exposed each finding is based on endpoint characteristics:
- Is the path publicly accessible (no auth required)?
- What HTTP method? POST/PUT are more exploitable than GET.
- Is it an API endpoint (/api/, /graphql, /v1/)?
- Is it an admin path (/admin/, /dashboard/)?

Applies a risk_multiplier to the finding's priority score so that
a SQL injection on a public login form ranks higher than one
behind admin auth.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.schemas import Finding, DiscoveryItem


class ExposureLevel(str, Enum):
    PUBLIC = "public"           # No auth required, world-accessible
    AUTHENTICATED = "authenticated"   # Requires login
    ADMIN = "admin"             # Admin/privileged path
    API = "api"                 # REST/GraphQL API endpoint
    UNKNOWN = "unknown"


# Path patterns that indicate auth is required
_AUTH_PATHS = re.compile(
    r"/(admin|dashboard|management|console|control|cp|panel|backoffice"
    r"|cms|wp-admin|phpmyadmin|manager|moderator|staff|operator)",
    re.IGNORECASE,
)

# API endpoint patterns
_API_PATHS = re.compile(
    r"/(api|graphql|rest|v\d+|swagger|openapi|rpc|soap|json)",
    re.IGNORECASE,
)

# Public-facing paths (login pages are technically public)
_PUBLIC_PATHS = re.compile(
    r"/(login|signin|register|signup|forgot-password|reset-password"
    r"|contact|about|index|home|public|static|assets|health|ping|status)",
    re.IGNORECASE,
)

# Headers that indicate auth was checked
_AUTH_HEADERS = {"authorization", "x-api-key", "x-auth-token", "cookie", "bearer"}


@dataclass
class ReachabilityResult:
    finding_id: str
    path: str
    method: str
    exposure_level: ExposureLevel
    requires_auth: bool
    is_api_endpoint: bool
    is_public: bool
    risk_multiplier: float
    rationale: str
    attack_vector: str = "network"   # network | adjacent | local


def _classify_path(path: str, method: str | None) -> tuple[ExposureLevel, bool, bool]:
    """Return (exposure_level, requires_auth, is_public)."""
    path_lower = path.lower()
    m = (method or "GET").upper()

    if _AUTH_PATHS.search(path_lower):
        return ExposureLevel.ADMIN, True, False

    if _API_PATHS.search(path_lower):
        # API endpoints — auth depends on headers, default assume semi-public
        return ExposureLevel.API, False, True

    if _PUBLIC_PATHS.search(path_lower):
        return ExposureLevel.PUBLIC, False, True

    # Heuristic: paths with UUIDs/IDs tend to be auth-protected resources
    if re.search(r"/[0-9a-f-]{8,}/|/\d{3,}/", path_lower):
        return ExposureLevel.AUTHENTICATED, True, False

    return ExposureLevel.UNKNOWN, False, True  # Default: assume public for worst-case


def _compute_multiplier(
    exposure: ExposureLevel,
    method: str,
    severity: str,
) -> tuple[float, str]:
    """Return (multiplier, rationale)."""
    base: float
    reason_parts: list[str] = []

    match exposure:
        case ExposureLevel.PUBLIC:
            base = 1.5
            reason_parts.append("public endpoint (no auth required)")
        case ExposureLevel.API:
            base = 1.75
            reason_parts.append("unauthenticated API endpoint")
        case ExposureLevel.ADMIN:
            base = 0.75
            reason_parts.append("admin path (requires elevated privilege)")
        case ExposureLevel.AUTHENTICATED:
            base = 0.9
            reason_parts.append("auth-protected endpoint")
        case _:
            base = 1.0
            reason_parts.append("unknown exposure level")

    # Method bonus
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        base *= 1.15
        reason_parts.append(f"mutable HTTP method ({method})")

    # Severity bonus for already-critical/high findings on public paths
    if severity in ("critical", "high") and exposure in (ExposureLevel.PUBLIC, ExposureLevel.API):
        base *= 1.1
        reason_parts.append("high-severity on public attack surface")

    return round(min(base, 3.0), 2), "; ".join(reason_parts)


class ReachabilityEngine:
    """Annotates a list of findings with reachability metadata."""

    def analyze(self, findings: list["Finding"]) -> list[ReachabilityResult]:
        results: list[ReachabilityResult] = []
        for f in findings:
            if f.is_noise or f.duplicate_of:
                continue
            method = (f.method or "GET").upper()
            exposure, requires_auth, is_public = _classify_path(f.path, method)
            multiplier, rationale = _compute_multiplier(
                exposure, method, f.severity.value
            )
            results.append(
                ReachabilityResult(
                    finding_id=f.id,
                    path=f.path,
                    method=method,
                    exposure_level=exposure,
                    requires_auth=requires_auth,
                    is_api_endpoint=exposure == ExposureLevel.API,
                    is_public=is_public,
                    risk_multiplier=multiplier,
                    rationale=rationale,
                )
            )
        return results

    def apply_multipliers(
        self, findings: list["Finding"], results: list[ReachabilityResult]
    ) -> list["Finding"]:
        """Return new findings with reachability_multiplier tag injected into tags."""
        idx = {r.finding_id: r for r in results}
        out = []
        for f in findings:
            r = idx.get(f.id)
            if r and r.risk_multiplier != 1.0:
                new_tags = list(f.tags) + [f"reachability:{r.exposure_level.value}"]
                f = f.model_copy(update={"tags": new_tags})
            out.append(f)
        return out

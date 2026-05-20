"""Plan-based entitlements and feature gates for the VulnAuditor ASPM platform.

Plans: free | pro | enterprise | unlimited (internal)

Usage:
    from core.entitlements import get_plan_limits, check_entitlement, Feature

    limits = get_plan_limits("pro")
    if limits.max_targets > 0 and target_count >= limits.max_targets:
        raise HTTPException(status_code=402, detail="Target limit reached. Upgrade to add more.")

    if not check_entitlement("free", Feature.SSO):
        raise HTTPException(status_code=402, detail="SSO requires Pro or Enterprise plan.")
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Feature(str, Enum):
    SSO = "sso"
    WEBHOOKS = "webhooks"
    ADVANCED_REPORTS = "advanced_reports"
    COMPLIANCE_REPORTS = "compliance_reports"
    AI_ANALYSIS = "ai_analysis"
    AUDIT_LOGS = "audit_logs"
    API_KEYS = "api_keys"
    MULTIPLE_MEMBERS = "multiple_members"
    CUSTOM_RATE_LIMITS = "custom_rate_limits"
    DATA_RETENTION_EXTENDED = "data_retention_extended"
    PRIORITY_SUPPORT = "priority_support"
    SLA = "sla"


@dataclass(frozen=True)
class PlanLimits:
    plan: str
    # -1 means unlimited
    max_targets: int
    max_scans_per_month: int
    max_members: int
    max_api_keys: int
    max_webhooks: int
    max_ai_requests_per_month: int
    data_retention_days: int  # How long scan data is kept
    features: frozenset[Feature]

    def has_feature(self, feature: Feature) -> bool:
        return feature in self.features


_PLANS: dict[str, PlanLimits] = {
    "free": PlanLimits(
        plan="free",
        max_targets=3,
        max_scans_per_month=10,
        max_members=1,
        max_api_keys=1,
        max_webhooks=0,
        max_ai_requests_per_month=5,
        data_retention_days=30,
        features=frozenset({
            Feature.AI_ANALYSIS,
            Feature.API_KEYS,
        }),
    ),

    "pro": PlanLimits(
        plan="pro",
        max_targets=20,
        max_scans_per_month=100,
        max_members=10,
        max_api_keys=5,
        max_webhooks=3,
        max_ai_requests_per_month=100,
        data_retention_days=180,
        features=frozenset({
            Feature.AI_ANALYSIS,
            Feature.API_KEYS,
            Feature.MULTIPLE_MEMBERS,
            Feature.WEBHOOKS,
            Feature.ADVANCED_REPORTS,
            Feature.COMPLIANCE_REPORTS,
            Feature.AUDIT_LOGS,
        }),
    ),

    "enterprise": PlanLimits(
        plan="enterprise",
        max_targets=-1,
        max_scans_per_month=-1,
        max_members=-1,
        max_api_keys=-1,
        max_webhooks=-1,
        max_ai_requests_per_month=-1,
        data_retention_days=365,
        features=frozenset(Feature),  # All features
    ),

    # Internal plan for demo org and development
    "unlimited": PlanLimits(
        plan="unlimited",
        max_targets=-1,
        max_scans_per_month=-1,
        max_members=-1,
        max_api_keys=-1,
        max_webhooks=-1,
        max_ai_requests_per_month=-1,
        data_retention_days=-1,
        features=frozenset(Feature),
    ),
}

# Legacy alias used in repositories
_PLAN_QUOTAS: dict[str, int] = {
    "free": 10,
    "pro": 100,
    "enterprise": -1,
    "unlimited": -1,
}


def get_plan_limits(plan: str) -> PlanLimits:
    """Return limits for the given plan. Falls back to free if unknown."""
    return _PLANS.get(plan, _PLANS["free"])


def check_entitlement(plan: str, feature: Feature) -> bool:
    """Return True if the plan includes the given feature."""
    return get_plan_limits(plan).has_feature(feature)


def get_scan_quota(plan: str) -> int:
    """Return monthly scan quota for a plan. -1 = unlimited."""
    return get_plan_limits(plan).max_scans_per_month


def within_limit(current: int, maximum: int) -> bool:
    """Return True if current is below maximum. -1 maximum means unlimited."""
    if maximum == -1:
        return True
    return current < maximum


def plan_upgrade_message(plan: str, feature: Feature) -> str:
    """Human-readable upgrade message for a blocked feature."""
    required = {
        Feature.SSO: "Enterprise",
        Feature.WEBHOOKS: "Pro or Enterprise",
        Feature.COMPLIANCE_REPORTS: "Pro or Enterprise",
        Feature.ADVANCED_REPORTS: "Pro or Enterprise",
        Feature.MULTIPLE_MEMBERS: "Pro or Enterprise",
        Feature.AUDIT_LOGS: "Pro or Enterprise",
    }
    upgrade_to = required.get(feature, "a higher tier plan")
    return f"Feature '{feature.value}' requires {upgrade_to}. Current plan: {plan}."

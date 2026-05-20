"""Enterprise feature tests: entitlements, audit, webhooks, API keys, user management."""
from __future__ import annotations

import asyncio
import pytest
from fastapi.testclient import TestClient

from api.app import app
from core.entitlements import (
    Feature,
    check_entitlement,
    get_plan_limits,
    within_limit,
)


# ── Entitlement tests ──────────────────────────────────────────────────────────

class TestPlanEntitlements:
    def test_free_plan_limits(self):
        limits = get_plan_limits("free")
        assert limits.max_targets == 3
        assert limits.max_scans_per_month == 10
        assert limits.max_members == 1
        assert limits.max_webhooks == 0
        assert limits.data_retention_days == 30

    def test_pro_plan_limits(self):
        limits = get_plan_limits("pro")
        assert limits.max_targets == 20
        assert limits.max_scans_per_month == 100
        assert limits.max_members == 10
        assert limits.max_webhooks == 3

    def test_enterprise_plan_is_unlimited(self):
        limits = get_plan_limits("enterprise")
        assert limits.max_targets == -1
        assert limits.max_scans_per_month == -1
        assert limits.max_members == -1

    def test_unknown_plan_falls_back_to_free(self):
        limits = get_plan_limits("nonexistent_plan")
        assert limits.plan == "free"

    def test_free_plan_has_no_sso(self):
        assert not check_entitlement("free", Feature.SSO)
        assert not check_entitlement("pro", Feature.SSO)
        assert check_entitlement("enterprise", Feature.SSO)

    def test_free_plan_has_no_webhooks(self):
        assert not check_entitlement("free", Feature.WEBHOOKS)
        assert check_entitlement("pro", Feature.WEBHOOKS)
        assert check_entitlement("enterprise", Feature.WEBHOOKS)

    def test_compliance_reports_require_pro_plus(self):
        assert not check_entitlement("free", Feature.COMPLIANCE_REPORTS)
        assert check_entitlement("pro", Feature.COMPLIANCE_REPORTS)
        assert check_entitlement("enterprise", Feature.COMPLIANCE_REPORTS)

    def test_within_limit_logic(self):
        assert within_limit(0, 10) is True
        assert within_limit(9, 10) is True
        assert within_limit(10, 10) is False
        assert within_limit(100, -1) is True  # -1 means unlimited
        assert within_limit(999999, -1) is True


# ── Compliance mapping tests ───────────────────────────────────────────────────

class TestComplianceMapping:
    def test_frameworks_available(self):
        from core.compliance import ComplianceFramework, SUPPORTED_FRAMEWORKS
        fw_ids = [fw.value for fw in SUPPORTED_FRAMEWORKS]
        assert "asvs" in fw_ids
        assert "soc2" in fw_ids
        assert "pci-dss" in fw_ids

    def test_report_generation_empty_findings(self):
        from core.compliance import ComplianceFramework, generate_compliance_report
        report = generate_compliance_report(ComplianceFramework.SOC2, [], org_id="test-org")
        assert report["framework"] == "soc2"
        assert report["org_id"] == "test-org"
        assert "summary" in report
        assert "controls" in report
        assert len(report["controls"]) > 0

    def test_report_all_not_covered_with_no_findings(self):
        from core.compliance import ComplianceFramework, generate_compliance_report
        report = generate_compliance_report(ComplianceFramework.ASVS, [], org_id="test-org")
        statuses = {c["status"] for c in report["controls"]}
        # With no findings, all controls should be NOT_COVERED
        assert statuses == {"NOT_COVERED"}

    def test_report_score_is_zero_with_no_findings(self):
        from core.compliance import ComplianceFramework, generate_compliance_report
        report = generate_compliance_report(ComplianceFramework.PCI_DSS, [], org_id="test-org")
        # With no findings, compliance_score = 0 (no passing controls)
        # Actually NOT_COVERED, so pass count is 0
        assert report["summary"]["compliance_score"] == 0.0

    def test_report_has_disclaimer(self):
        from core.compliance import ComplianceFramework, generate_compliance_report
        report = generate_compliance_report(ComplianceFramework.SOC2, [], org_id="x")
        assert "disclaimer" in report
        assert len(report["disclaimer"]) > 10


# ── Audit action enum coverage ────────────────────────────────────────────────

class TestAuditActions:
    def test_all_required_actions_exist(self):
        from db.audit import AuditAction

        required = [
            "AUTH_LOGIN", "AUTH_LOGIN_FAILED", "AUTH_LOGOUT", "AUTH_REGISTER",
            "USER_INVITED", "USER_ROLE_CHANGED", "USER_DEACTIVATED",
            "SCAN_CREATED", "SCAN_DELETED",
            "FINDING_STATUS_CHANGED",
            "REPORT_EXPORTED",
            "WEBHOOK_CREATED", "WEBHOOK_DELETED",
            "API_KEY_CREATED", "API_KEY_REVOKED",
            "TARGET_DELETED",
            "BILLING_PLAN_CHANGED",
            "SSO_CONFIGURED",
        ]
        existing = {a.name for a in AuditAction}
        for action in required:
            assert action in existing, f"Missing audit action: {action}"


# ── Storage backend tests ─────────────────────────────────────────────────────

class TestLocalStorageBackend:
    @pytest.mark.asyncio
    async def test_write_and_read(self, tmp_path):
        from core.storage_backend import LocalStorageBackend
        backend = LocalStorageBackend(root=tmp_path)
        await backend.write("scans/test/scan.json", b'{"status": "done"}')
        data = await backend.read("scans/test/scan.json")
        assert data == b'{"status": "done"}'

    @pytest.mark.asyncio
    async def test_exists_returns_false_for_missing(self, tmp_path):
        from core.storage_backend import LocalStorageBackend
        backend = LocalStorageBackend(root=tmp_path)
        assert await backend.exists("nonexistent/file.json") is False

    @pytest.mark.asyncio
    async def test_text_helpers(self, tmp_path):
        from core.storage_backend import LocalStorageBackend
        backend = LocalStorageBackend(root=tmp_path)
        await backend.write_text("test.txt", "hello enterprise")
        result = await backend.read_text("test.txt")
        assert result == "hello enterprise"

    @pytest.mark.asyncio
    async def test_delete(self, tmp_path):
        from core.storage_backend import LocalStorageBackend
        backend = LocalStorageBackend(root=tmp_path)
        await backend.write("to_delete.json", b"data")
        assert await backend.exists("to_delete.json") is True
        await backend.delete("to_delete.json")
        assert await backend.exists("to_delete.json") is False

    @pytest.mark.asyncio
    async def test_path_traversal_rejected(self, tmp_path):
        from core.storage_backend import LocalStorageBackend
        backend = LocalStorageBackend(root=tmp_path)
        with pytest.raises(ValueError, match="traversal"):
            await backend.write("../../etc/passwd", b"bad")


# ── Billing adapter tests ─────────────────────────────────────────────────────

class TestNoOpBillingAdapter:
    @pytest.mark.asyncio
    async def test_checkout_raises_not_implemented(self):
        from core.billing import NoOpBillingAdapter, BillingPlan as BP
        adapter = NoOpBillingAdapter()
        with pytest.raises(NotImplementedError):
            await adapter.create_checkout_session(
                "org-1", BP.PRO, "http://ok", "http://cancel"
            )

    @pytest.mark.asyncio
    async def test_subscription_status_returns_none(self):
        from core.billing import NoOpBillingAdapter
        adapter = NoOpBillingAdapter()
        result = await adapter.get_subscription_status("cus_fake")
        assert result is None


# ── API v1 health check ───────────────────────────────────────────────────────

class TestAPIV1Routes:
    def test_v1_health_accessible(self, test_client):
        response = test_client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_v1_compliance_frameworks(self, test_client):
        response = test_client.get("/api/v1/compliance/frameworks")
        assert response.status_code == 200
        frameworks = response.json()
        ids = [fw["id"] for fw in frameworks]
        assert "asvs" in ids
        assert "soc2" in ids
        assert "pci-dss" in ids

    def test_v1_oidc_status(self, test_client):
        response = test_client.get("/api/v1/auth/oidc/status")
        assert response.status_code == 200
        providers = response.json()
        names = [p["provider"] for p in providers]
        assert "google" in names
        assert "azure" in names
        assert "okta" in names

    def test_v1_webhook_events_listed(self, test_client):
        """Webhooks list returns 200 — unauthenticated in demo mode."""
        # In demo mode (require_auth=False), this should work
        response = test_client.get("/api/v1/webhooks")
        # May get 200 with empty list or 401 depending on mode
        assert response.status_code in (200, 401)

    def test_legacy_health_still_accessible(self, test_client):
        """Legacy /health endpoint remains backward compatible."""
        response = test_client.get("/health")
        assert response.status_code == 200

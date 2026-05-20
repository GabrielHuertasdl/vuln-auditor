"""Tests for RBAC permission system."""
from __future__ import annotations

import pytest

from api.rbac import Permission, get_role_permissions, has_permission


class TestRolePermissions:
    def test_owner_has_all_permissions(self):
        owner_perms = get_role_permissions("owner")
        for perm in Permission:
            assert perm in owner_perms, f"owner missing permission: {perm}"

    def test_admin_has_most_permissions(self):
        admin_perms = get_role_permissions("admin")
        # Admin should have these core permissions
        assert Permission.TARGETS_CREATE in admin_perms
        assert Permission.SCANS_CREATE in admin_perms
        assert Permission.USERS_INVITE in admin_perms
        assert Permission.AUDIT_READ in admin_perms
        assert Permission.SETTINGS_MANAGE in admin_perms

    def test_admin_cannot_delete_org(self):
        admin_perms = get_role_permissions("admin")
        assert Permission.ORG_DELETE not in admin_perms

    def test_analyst_can_create_scans_and_targets(self):
        analyst_perms = get_role_permissions("analyst")
        assert Permission.SCANS_CREATE in analyst_perms
        assert Permission.TARGETS_CREATE in analyst_perms
        assert Permission.FINDINGS_UPDATE_STATUS in analyst_perms

    def test_analyst_cannot_manage_users(self):
        analyst_perms = get_role_permissions("analyst")
        assert Permission.USERS_INVITE not in analyst_perms
        assert Permission.USERS_UPDATE_ROLE not in analyst_perms
        assert Permission.USERS_DEACTIVATE not in analyst_perms

    def test_analyst_cannot_manage_billing(self):
        analyst_perms = get_role_permissions("analyst")
        assert Permission.BILLING_MANAGE not in analyst_perms

    def test_viewer_is_read_only(self):
        viewer_perms = get_role_permissions("viewer")
        # Viewer should only have read permissions
        write_perms = {
            Permission.TARGETS_CREATE, Permission.TARGETS_UPDATE, Permission.TARGETS_DELETE,
            Permission.SCANS_CREATE, Permission.SCANS_CANCEL,
            Permission.FINDINGS_UPDATE_STATUS,
            Permission.USERS_INVITE, Permission.API_KEYS_CREATE,
            Permission.INTEGRATIONS_MANAGE, Permission.BILLING_MANAGE,
        }
        for perm in write_perms:
            assert perm not in viewer_perms, f"viewer should not have: {perm}"

    def test_viewer_can_read(self):
        viewer_perms = get_role_permissions("viewer")
        assert Permission.TARGETS_READ in viewer_perms
        assert Permission.SCANS_READ in viewer_perms
        assert Permission.FINDINGS_READ in viewer_perms
        assert Permission.REPORTS_READ in viewer_perms

    def test_unknown_role_returns_empty(self):
        perms = get_role_permissions("unknown_role")
        assert len(perms) == 0

    def test_has_permission_helper(self):
        assert has_permission("owner", Permission.ORG_DELETE) is True
        assert has_permission("admin", Permission.ORG_DELETE) is False
        assert has_permission("viewer", Permission.SCANS_CREATE) is False
        assert has_permission("analyst", Permission.SCANS_CREATE) is True

    def test_privilege_escalation_impossible(self):
        """viewer cannot have more permissions than analyst, analyst not more than admin."""
        viewer = get_role_permissions("viewer")
        analyst = get_role_permissions("analyst")
        admin = get_role_permissions("admin")
        owner = get_role_permissions("owner")

        assert viewer.issubset(analyst), "viewer has permissions analyst doesn't"
        assert analyst.issubset(admin), "analyst has permissions admin doesn't"
        assert admin.issubset(owner), "admin has permissions owner doesn't"

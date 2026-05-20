"""initial_schema

Revision ID: cdc5d0b00106
Revises:
Create Date: 2026-04-29 17:21:59.442216

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'cdc5d0b00106'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'organizations',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('slug', sa.String(), nullable=True),
        sa.Column('website', sa.String(), nullable=True),
        sa.Column('api_key_hash', sa.String(), nullable=False),
        sa.Column('plan', sa.String(), nullable=False, server_default='free'),
        sa.Column('scan_quota', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('scans_this_month', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('quota_reset_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('sso_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('settings_json', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('api_key_hash'),
        sa.UniqueConstraint('slug'),
    )
    op.create_index('ix_organizations_slug', 'organizations', ['slug'])

    op.create_table(
        'users',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('password_hash', sa.String(), nullable=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('role', sa.String(), nullable=False, server_default='admin'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_login_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
    )
    op.create_index('ix_users_email', 'users', ['email'])

    op.create_table(
        'memberships',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('org_id', sa.String(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('invited_by', sa.String(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('invited_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('accepted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'org_id', name='uq_membership'),
    )
    op.create_index('ix_memberships_user_id', 'memberships', ['user_id'])
    op.create_index('ix_memberships_org_id', 'memberships', ['org_id'])

    op.create_table(
        'invite_tokens',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=False),
        sa.Column('invited_by', sa.String(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('accepted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )
    op.create_index('ix_invite_tokens_email', 'invite_tokens', ['email'])

    op.create_table(
        'refresh_tokens',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('device_hint', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )
    op.create_index('ix_refresh_tokens_user_id', 'refresh_tokens', ['user_id'])
    op.create_index('ix_refresh_tokens_token_hash', 'refresh_tokens', ['token_hash'])

    op.create_table(
        'oidc_accounts',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('provider_sub', sa.String(), nullable=False),
        sa.Column('provider_email', sa.String(), nullable=True),
        sa.Column('linked_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('provider', 'provider_sub', name='uq_oidc_account'),
    )
    op.create_index('ix_oidc_accounts_user_id', 'oidc_accounts', ['user_id'])

    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('key_hash', sa.String(), nullable=False),
        sa.Column('key_prefix', sa.String(), nullable=False),
        sa.Column('scopes', sa.String(), nullable=False, server_default='["read","write"]'),
        sa.Column('created_by', sa.String(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_hash'),
    )
    op.create_index('ix_api_keys_org_id', 'api_keys', ['org_id'])
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'])

    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), sa.ForeignKey('organizations.id'), nullable=True),
        sa.Column('actor_id', sa.String(), nullable=True),
        sa.Column('actor_email', sa.String(), nullable=True),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('resource_type', sa.String(), nullable=True),
        sa.Column('resource_id', sa.String(), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('user_agent', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_logs_org_id', 'audit_logs', ['org_id'])
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])

    op.create_table(
        'webhook_endpoints',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('url', sa.String(), nullable=False),
        sa.Column('secret_hash', sa.String(), nullable=True),
        sa.Column('events', sa.String(), nullable=False,
                  server_default='["scan.completed","finding.created","finding.status_changed"]'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_by', sa.String(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_triggered_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_webhook_endpoints_org_id', 'webhook_endpoints', ['org_id'])

    op.create_table(
        'webhook_deliveries',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('endpoint_id', sa.String(), sa.ForeignKey('webhook_endpoints.id'), nullable=False),
        sa.Column('event', sa.String(), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('response_body', sa.Text(), nullable=True),
        sa.Column('attempt_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('succeeded', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_webhook_deliveries_endpoint_id', 'webhook_deliveries', ['endpoint_id'])

    op.create_table(
        'targets',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('url', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('tags', sa.String(), nullable=False, server_default='[]'),
        sa.Column('schedule', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scan_count', sa.Integer(), nullable=False, server_default='0'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('org_id', 'url', name='uq_target_org_url'),
    )

    op.create_table(
        'scans',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('target_id', sa.String(), sa.ForeignKey('targets.id'), nullable=True),
        sa.Column('initiated_by', sa.String(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('scan_mode', sa.String(), nullable=False, server_default='full'),
        sa.Column('tools_requested', sa.String(), nullable=False, server_default='[]'),
        sa.Column('tools_succeeded', sa.String(), nullable=False, server_default='[]'),
        sa.Column('tools_failed', sa.String(), nullable=False, server_default='{}'),
        sa.Column('detected_stack', sa.String(), nullable=False, server_default='[]'),
        sa.Column('severity_summary', sa.String(), nullable=False, server_default='{}'),
        sa.Column('priority_summary', sa.String(), nullable=False, server_default='{}'),
        sa.Column('finding_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('new_finding_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('regressed_finding_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('ai_executive_summary', sa.Text(), nullable=True),
        sa.Column('ai_generated', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('report_path', sa.String(), nullable=True),
        sa.Column('error', sa.String(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'findings',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('target_id', sa.String(), sa.ForeignKey('targets.id'), nullable=False),
        sa.Column('global_fingerprint', sa.String(), nullable=False),
        sa.Column('correlation_key', sa.String(), nullable=False),
        sa.Column('endpoint_fingerprint', sa.String(), nullable=False, server_default=''),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('host', sa.String(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(), nullable=False, server_default='tcp'),
        sa.Column('path', sa.String(), nullable=False, server_default='/'),
        sa.Column('method', sa.String(), nullable=True),
        sa.Column('parameter', sa.String(), nullable=True),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('priority', sa.String(), nullable=False),
        sa.Column('confidence', sa.String(), nullable=False),
        sa.Column('exploitability', sa.String(), nullable=False, server_default='unknown'),
        sa.Column('remediation_effort', sa.String(), nullable=False, server_default='hours'),
        sa.Column('owasp_category', sa.String(), nullable=True),
        sa.Column('owasp_api_category', sa.String(), nullable=True),
        sa.Column('cwe_ids', sa.String(), nullable=False, server_default='[]'),
        sa.Column('status', sa.String(), nullable=False, server_default='open'),
        sa.Column('is_noise', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('duplicate_of', sa.String(), nullable=True),
        sa.Column('related_findings', sa.String(), nullable=False, server_default='[]'),
        sa.Column('tags', sa.String(), nullable=False, server_default='[]'),
        sa.Column('detected_stack', sa.String(), nullable=False, server_default='[]'),
        sa.Column('sources', sa.String(), nullable=False, server_default='[]'),
        sa.Column('source_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('normalized_evidence', sa.Text(), nullable=True),
        sa.Column('solution', sa.Text(), nullable=True),
        sa.Column('references', sa.String(), nullable=False, server_default='[]'),
        sa.Column('ai_mitigation', sa.Text(), nullable=True),
        sa.Column('first_seen_scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('last_seen_scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolution_note', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('org_id', 'target_id', 'global_fingerprint', name='uq_finding_org_target_fp'),
    )

    op.create_table(
        'scan_findings',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('finding_id', sa.String(), sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('is_new', sa.Boolean(), nullable=False),
        sa.Column('is_regressed', sa.Boolean(), nullable=False),
        sa.Column('severity_snapshot', sa.String(), nullable=False),
        sa.Column('confidence_snapshot', sa.String(), nullable=False),
        sa.Column('evidence_snapshot', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scan_id', 'finding_id', name='uq_scan_finding'),
    )

    op.create_table(
        'finding_status_history',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('finding_id', sa.String(), sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('scan_id', sa.String(), nullable=True),
        sa.Column('status_from', sa.String(), nullable=False),
        sa.Column('status_to', sa.String(), nullable=False),
        sa.Column('severity_from', sa.String(), nullable=True),
        sa.Column('severity_to', sa.String(), nullable=True),
        sa.Column('changed_by', sa.String(), nullable=True),
        sa.Column('changed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('note', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'verification_domains',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    op.create_table(
        'security_controls',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('domain_id', sa.String(), sa.ForeignKey('verification_domains.id'), nullable=False),
        sa.Column('code', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code'),
    )

    op.create_table(
        'verification_records',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('control_id', sa.String(), sa.ForeignKey('security_controls.id'), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('evidence_summary', sa.String(), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'asset_discovery',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('type', sa.String(), nullable=False),
        sa.Column('data', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.String(), nullable=False),
        sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'posture_scores',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('overall_score', sa.Float(), nullable=False),
        sa.Column('domain_scores', sa.JSON(), nullable=False),
        sa.Column('coverage_score', sa.Float(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('exposure_score', sa.Float(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('posture_scores')
    op.drop_table('asset_discovery')
    op.drop_table('verification_records')
    op.drop_table('security_controls')
    op.drop_table('verification_domains')
    op.drop_table('finding_status_history')
    op.drop_table('scan_findings')
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('targets')
    op.drop_table('webhook_deliveries')
    op.drop_table('webhook_endpoints')
    op.drop_table('audit_logs')
    op.drop_table('api_keys')
    op.drop_table('oidc_accounts')
    op.drop_table('refresh_tokens')
    op.drop_table('invite_tokens')
    op.drop_table('memberships')
    op.drop_table('users')
    op.drop_table('organizations')

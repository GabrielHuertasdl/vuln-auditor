# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [2.0.0] — 2026-05-20

### Added

**Multi-tenancy & RBAC**
- `Organization` ↔ `User` via `Membership` table; all entities scoped by `org_id`
- RBAC with 4 roles: `owner > admin > analyst > viewer`; 30+ granular `Permission` values
- `require_permission()` FastAPI dependency for declarative route protection
- Privilege-escalation impossible by design: viewer ⊂ analyst ⊂ admin ⊂ owner

**Authentication hardening**
- Refresh tokens now stored as SHA-256 hashes in DB — true revocation and rotation
- `POST /auth/logout` endpoint revokes refresh token server-side
- `POST /auth/refresh` rotates token (old revoked, new issued)
- Failed login counter on User; `last_login_at` tracked
- Invite flow: `InviteToken` with expiry, accepted-at, role pre-assignment
- `OIDCAccount` table links SSO identities to local users

**OIDC / SSO** (requires `pip install ".[sso]"`)
- Google Workspace, Microsoft Azure AD / Entra ID, Okta
- `GET /api/v1/auth/oidc/{provider}/authorize` → redirect
- `GET /api/v1/auth/oidc/{provider}/callback` → issue JWT + create/link user
- CSRF protection via server-side session state

**API key management**
- `APIKeyRecord` with `vak_` prefix, SHA-256 hashed storage, per-org scopes
- `GET/POST/DELETE /api/v1/api-keys`; raw key returned once on creation

**Webhooks**
- `WebhookEndpoint` + `WebhookDelivery` tables
- HMAC-SHA256 signed payloads; 3 retries with exponential backoff
- `GET/POST/DELETE /api/v1/webhooks`; `POST /api/v1/webhooks/{id}/test`
- Events: `scan.completed`, `scan.failed`, `finding.status_changed`, `target.deleted`

**Audit logging**
- Immutable `AuditLog` table; fire-and-forget `emit_audit()` (non-blocking)
- 30+ `AuditAction` values covering auth, scans, findings, users, webhooks, billing
- `GET /api/v1/audit` (requires `AUDIT_READ` + Pro/Enterprise plan)

**Plan entitlements**
- Plans: `free`, `pro`, `enterprise`, `unlimited`
- `PlanLimits` dataclass: `max_targets`, `max_scans_per_month`, `max_members`, `max_webhooks`, `data_retention_days`
- `Feature` enum + `check_entitlement()` + `within_limit()` utilities
- `GET /api/v1/compliance/frameworks` and `GET /api/v1/compliance/{framework}` gated to Pro+

**Compliance foundations**
- CWE → ASVS / SOC2 / PCI-DSS control mapping
- `generate_compliance_report()` with per-control pass/fail/partial/not_covered status and compliance score %
- Supported frameworks: ASVS 4.0, SOC 2 Type II, PCI DSS 4.0

**Storage abstraction**
- `StorageBackend` ABC with `LocalStorageBackend` and `S3StorageBackend` (MinIO-compatible)
- Path-traversal protection in local backend
- Configured via `STORAGE_BACKEND=local|s3`

**Billing scaffold** (requires `pip install ".[billing]"`)
- `BillingAdapter` ABC: `StripeAdapter` + `NoOpBillingAdapter`
- `BillingPlan` enum with Stripe price ID mapping
- Checkout session + customer portal + webhook handler stubs

**API versioning**
- All new routes under `/api/v1/`; legacy routes preserved at original paths (backward compatible)
- OpenAPI docs at `/api/docs`, ReDoc at `/api/redoc`

**AI resilience**
- `asyncio.wait_for()` timeout + exponential backoff retry on all AI calls
- Gemini → Anthropic automatic fallback
- Configurable via `AI_TIMEOUT_SECONDS`, `AI_MAX_RETRIES`

**Configuration hardening**
- Production validation on startup: rejects weak `JWT_SECRET` (<32 chars or in blocklist), rejects SQLite in production, rejects `REQUIRE_AUTH=false` in production
- Per-endpoint rate limits via settings: `RATE_LIMIT_AUTH`, `RATE_LIMIT_SCAN_CREATE`, `RATE_LIMIT_AI`, `RATE_LIMIT_REPORT_EXPORT`
- Comprehensive `.env.example` with all settings documented

**Infrastructure**
- Alembic migration `002_enterprise_features.py` with full downgrade
- Docker Compose: `JWT_SECRET` marked required, `REQUIRE_AUTH=true` default, MinIO section (commented), health checks, restart policies
- `pyproject.toml` optional dep groups: `sso`, `billing`, `storage-s3`, `all-enterprise`

### Changed
- `User.password_hash` nullable (SSO-only users have no password)
- `ScanRecord` adds `initiated_by` FK to users
- `FindingStatusHistory` adds `changed_by` FK
- `Organization` adds `slug`, `website`, `sso_enabled`, `settings_json`
- CORS tightened in production (only `FRONTEND_URL` origin)
- Security headers middleware: `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `HSTS` (production only)
- `POST /auth/register` now assigns role `owner` (was `admin`) to org creator

### Security
- Refresh tokens no longer JWT — server-side revocation now possible
- API keys stored as SHA-256 hashes — raw key never retrievable after creation
- Webhook secrets stored as SHA-256 hashes
- Path traversal blocked in local storage backend
- Production startup validator prevents common misconfigurations

## [1.0.0] — initial release

- FastAPI + SQLAlchemy 2.0 async
- ZAP, Nmap, Nikto scanner integration
- AI analysis via Anthropic + Gemini
- JWT authentication (single-tenant)
- PDF + JSON report export
- Basic vulnerability scoring

---

[Unreleased]: https://github.com/your-org/vulnerability-detector/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/your-org/vulnerability-detector/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/your-org/vulnerability-detector/releases/tag/v1.0.0

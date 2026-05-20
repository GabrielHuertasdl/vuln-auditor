# Authentication & Authorization

## Overview

VulnAuditor uses JWT access tokens (short-lived, 60 min) with DB-backed refresh tokens (revocable, rotated on use).

## Endpoints

### Register

```http
POST /auth/register
Content-Type: application/json

{
  "name": "Alice",
  "email": "alice@acme.com",
  "password": "strongpassword",
  "org_name": "Acme Corp"       # creates new org; omit if accepting invite
  "invite_token": "tok_..."     # join existing org via invite
}
```

Response `201`:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "...",
  "token_type": "bearer",
  "user": {"id": "...", "email": "...", "role": "owner"}
}
```

First registrant of an org gets `role=owner`. Invite-based registrants get the role specified in the invite.

### Login

```http
POST /auth/login
Content-Type: application/json

{"email": "alice@acme.com", "password": "strongpassword"}
```

Response `200`: same shape as register.

### Refresh

```http
POST /auth/refresh
Content-Type: application/json

{"refresh_token": "..."}
```

Old token is **revoked immediately**. New token pair returned. Use this to silently renew sessions.

### Logout

```http
POST /auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json

{"refresh_token": "..."}
```

Revokes the refresh token server-side. Access token remains valid until natural expiry (60 min).

## API Keys

Long-lived machine credentials for CI/CD pipelines.

```http
POST /api/v1/api-keys
Authorization: Bearer <access_token>
Content-Type: application/json

{"name": "CI Pipeline", "scopes": ["scans:create", "findings:read"]}
```

Response includes `raw_key` (shown **once** — store it). Format: `vak_<random>`.

Use in requests:
```http
X-API-Key: vak_abc123...
```

## OIDC SSO

Requires `pip install "vulnerability-detector[sso]"` and provider credentials in `.env`.

### Supported Providers

| Provider | Env vars needed |
|---|---|
| Google Workspace | `OIDC_GOOGLE_CLIENT_ID`, `OIDC_GOOGLE_CLIENT_SECRET` |
| Azure AD / Entra ID | `OIDC_AZURE_CLIENT_ID`, `OIDC_AZURE_CLIENT_SECRET`, `OIDC_AZURE_TENANT_ID` |
| Okta | `OIDC_OKTA_DOMAIN`, `OIDC_OKTA_CLIENT_ID`, `OIDC_OKTA_CLIENT_SECRET` |

### Flow

1. `GET /api/v1/auth/oidc/{provider}/authorize` → redirect to provider login
2. Provider redirects to `GET /api/v1/auth/oidc/{provider}/callback?code=...&state=...`
3. Server exchanges code, creates or links user, returns JWT pair

First SSO login for a new email creates a new org. Subsequent logins link to existing account.

### Check configured providers

```http
GET /api/v1/auth/oidc/status
```

```json
[
  {"provider": "google", "configured": true, "enabled": true},
  {"provider": "azure", "configured": false, "enabled": false}
]
```

## Security Notes

- Refresh tokens stored as SHA-256 hashes — cannot be extracted from DB
- API keys stored as SHA-256 hashes — raw key never retrievable after creation
- Failed login counter incremented on bad password (brute-force detection hook)
- Rate limit on `/auth/login` and `/auth/register`: configurable via `RATE_LIMIT_AUTH`

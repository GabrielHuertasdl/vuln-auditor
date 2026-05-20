# RBAC — Role-Based Access Control

## Roles

Roles form a strict hierarchy: `viewer ⊂ analyst ⊂ admin ⊂ owner`. Each role has all permissions of the roles below it.

| Role | Description |
|---|---|
| `owner` | Full control including org deletion, billing, SSO configuration |
| `admin` | All except org deletion and billing management |
| `analyst` | Create/run scans, manage findings, create targets |
| `viewer` | Read-only access to all resources |

## Permission Reference

### Organization

| Permission | owner | admin | analyst | viewer |
|---|:---:|:---:|:---:|:---:|
| `org:read` | ✓ | ✓ | ✓ | ✓ |
| `org:update` | ✓ | ✓ | — | — |
| `org:delete` | ✓ | — | — | — |

### Users

| Permission | owner | admin | analyst | viewer |
|---|:---:|:---:|:---:|:---:|
| `users:read` | ✓ | ✓ | ✓ | ✓ |
| `users:invite` | ✓ | ✓ | — | — |
| `users:update_role` | ✓ | ✓ | — | — |
| `users:deactivate` | ✓ | ✓ | — | — |

### Targets

| Permission | owner | admin | analyst | viewer |
|---|:---:|:---:|:---:|:---:|
| `targets:read` | ✓ | ✓ | ✓ | ✓ |
| `targets:create` | ✓ | ✓ | ✓ | — |
| `targets:update` | ✓ | ✓ | ✓ | — |
| `targets:delete` | ✓ | ✓ | — | — |

### Scans

| Permission | owner | admin | analyst | viewer |
|---|:---:|:---:|:---:|:---:|
| `scans:read` | ✓ | ✓ | ✓ | ✓ |
| `scans:create` | ✓ | ✓ | ✓ | — |
| `scans:cancel` | ✓ | ✓ | ✓ | — |
| `scans:delete` | ✓ | ✓ | — | — |

### Findings

| Permission | owner | admin | analyst | viewer |
|---|:---:|:---:|:---:|:---:|
| `findings:read` | ✓ | ✓ | ✓ | ✓ |
| `findings:update_status` | ✓ | ✓ | ✓ | — |

### Reports

| Permission | owner | admin | analyst | viewer |
|---|:---:|:---:|:---:|:---:|
| `reports:read` | ✓ | ✓ | ✓ | ✓ |
| `reports:export` | ✓ | ✓ | ✓ | — |

### API Keys

| Permission | owner | admin | analyst | viewer |
|---|:---:|:---:|:---:|:---:|
| `api_keys:read` | ✓ | ✓ | — | — |
| `api_keys:create` | ✓ | ✓ | — | — |
| `api_keys:revoke` | ✓ | ✓ | — | — |

### Audit & Settings

| Permission | owner | admin | analyst | viewer |
|---|:---:|:---:|:---:|:---:|
| `audit:read` | ✓ | ✓ | — | — |
| `settings:manage` | ✓ | ✓ | — | — |
| `integrations:manage` | ✓ | ✓ | — | — |
| `billing:manage` | ✓ | — | — | — |
| `sso:manage` | ✓ | — | — | — |

## Usage in Code

```python
from api.rbac import Permission, require_permission

@router.delete("/targets/{target_id}")
async def delete_target(
    target_id: str,
    current_user: User = Depends(require_permission(Permission.TARGETS_DELETE)),
):
    ...
```

`require_permission()` returns a FastAPI dependency that:
1. Validates JWT / API key
2. Loads `Membership` for current org
3. Checks role has the required permission
4. Raises `403 Forbidden` if not

## Invite Flow & Role Assignment

Only `owner` and `admin` can invite members. The invited user gets exactly the role specified in the invite — no elevation possible.

To prevent lockout: the last `owner` cannot be demoted or deactivated.

## Plan Limits on Members

Free plan: max 1 member (no invites).  
Pro plan: max 10 members.  
Enterprise: unlimited.

Member limit checked at invite creation time. Existing members are not affected if plan downgrades.

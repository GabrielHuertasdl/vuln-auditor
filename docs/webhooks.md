# Webhooks

## Overview

Webhooks deliver real-time event notifications to your systems (Slack, PagerDuty, custom endpoints). Available on Pro and Enterprise plans.

## Managing Endpoints

### Create endpoint

```http
POST /api/v1/webhooks
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "PagerDuty alerts",
  "url": "https://events.pagerduty.com/integration/abc123/enqueue",
  "events": ["scan.completed", "scan.failed", "finding.status_changed"]
}
```

Response includes `secret` — store it for signature verification. Not retrievable later.

### List endpoints

```http
GET /api/v1/webhooks
```

### Delete endpoint

```http
DELETE /api/v1/webhooks/{webhook_id}
```

### Test delivery

```http
POST /api/v1/webhooks/{webhook_id}/test
```

Sends a `webhook.test` event to the endpoint immediately.

## Supported Events

| Event | Triggered when |
|---|---|
| `scan.completed` | Scan finishes successfully |
| `scan.failed` | Scan errors or times out |
| `finding.status_changed` | Finding status updated (open → accepted_risk etc.) |
| `target.deleted` | Target and all associated scans removed |
| `webhook.test` | Manual test delivery |

## Payload Format

```json
{
  "event": "scan.completed",
  "timestamp": "2026-05-20T18:00:00Z",
  "org_id": "org_abc123",
  "data": {
    "scan_id": "scan_xyz",
    "target": "example.com",
    "status": "completed",
    "finding_count": 12,
    "critical_count": 2
  }
}
```

## Signature Verification

Every delivery includes an HMAC-SHA256 signature header:

```
X-VulnAuditor-Signature: sha256=<hex_digest>
```

Verify in Python:
```python
import hashlib, hmac

def verify_signature(payload_bytes: bytes, secret: str, signature_header: str) -> bool:
    expected = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    received = signature_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, received)
```

Always verify signatures before processing. Reject requests with invalid signatures.

## Retry Policy

Failed deliveries (non-2xx response or timeout) are retried 3 times with exponential backoff:
- Attempt 1: immediate
- Attempt 2: 2 seconds
- Attempt 3: 4 seconds

After 3 failures the delivery is marked failed. Delivery history is logged in `webhook_deliveries`.

## Plan Limits

| Plan | Max endpoints |
|---|---|
| Free | 0 (webhooks unavailable) |
| Pro | 3 |
| Enterprise | Unlimited |

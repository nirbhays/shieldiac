# ShieldIaC API Reference

> Complete endpoint documentation for the ShieldIaC backend API.

Base URL: `https://api.shieldiac.dev/api/v1`

---

## Authentication

All API endpoints require authentication via one of:

| Method | Use Case | Header |
|--------|----------|--------|
| **Webhook HMAC** | GitHub/GitLab webhooks | `X-Hub-Signature-256` |
| **Clerk JWT** | Dashboard API calls | `Authorization: Bearer <jwt>` |
| **API Key** | Programmatic access (Business+) | `Authorization: Bearer shld_...` |

---

## Webhooks

### `POST /webhooks/github`

Receives GitHub push and pull_request events.

**Headers:**
- `X-Hub-Signature-256`: HMAC-SHA256 signature
- `X-GitHub-Event`: Event type (`push` or `pull_request`)
- `X-GitHub-Delivery`: Unique delivery ID

**Response:** `202 Accepted` (scan queued)

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Scan enqueued for processing"
}
```

### `POST /webhooks/gitlab`

Receives GitLab push and merge_request events.

**Headers:**
- `X-Gitlab-Token`: Webhook secret token

**Response:** `202 Accepted`

---

## Scans

### `POST /scans`

Trigger a manual scan.

**Request Body:**
```json
{
  "repo_url": "https://github.com/org/repo",
  "ref": "main",
  "files": ["main.tf", "modules/vpc/main.tf"]
}
```

**Response:** `201 Created`
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "trigger": "manual",
  "created_at": "2026-02-08T12:00:00Z"
}
```

### `GET /scans`

List scans for the authenticated organization.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `repo_id` | uuid | -- | Filter by repository |
| `status` | string | -- | Filter: queued, scanning, completed, failed |
| `page` | int | 1 | Page number |
| `per_page` | int | 20 | Results per page (max 100) |

**Response:** `200 OK`
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "repo": "org/repo",
      "trigger": "pr",
      "status": "completed",
      "score": 72,
      "grade": "C",
      "finding_count": 12,
      "critical_count": 2,
      "high_count": 4,
      "duration_seconds": 8.3,
      "created_at": "2026-02-08T12:00:00Z"
    }
  ],
  "total": 156,
  "page": 1,
  "per_page": 20
}
```

### `GET /scans/{scan_id}`

Get detailed scan results including all findings.

**Response:** `200 OK`
```json
{
  "id": "550e8400-...",
  "repo": "org/repo",
  "status": "completed",
  "score": 72,
  "grade": "C",
  "summary": {
    "critical": 2,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1
  },
  "findings": [
    {
      "rule_id": "SHLD-S3-002",
      "severity": "CRITICAL",
      "file_path": "modules/storage/main.tf",
      "line_number": 15,
      "resource_name": "aws_s3_bucket.data",
      "description": "S3 bucket missing public access block configuration",
      "remediation": "Add aws_s3_bucket_public_access_block resource",
      "ai_fix_suggestion": "resource \"aws_s3_bucket_public_access_block\" ...",
      "compliance": [
        {"framework": "CIS-AWS", "control_id": "2.1.5"},
        {"framework": "SOC2", "control_id": "CC6.1"}
      ]
    }
  ],
  "file_results": {
    "modules/storage/main.tf": {"findings": 3, "score": 45},
    "main.tf": {"findings": 1, "score": 85}
  }
}
```

---

## Findings

### `GET /findings`

List findings across all scans.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filter: CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `rule_id` | string | Filter by specific rule |
| `framework` | string | Filter by compliance framework |
| `repo_id` | uuid | Filter by repository |

### `GET /findings/{finding_id}`

Get a single finding with full details.

### `GET /findings/trends`

Get finding trends over time.

**Response:**
```json
{
  "data_points": [
    {"date": "2026-02-01", "critical": 5, "high": 12, "medium": 8},
    {"date": "2026-02-08", "critical": 2, "high": 8, "medium": 6}
  ],
  "trend": "improving"
}
```

---

## Rules

### `GET /rules`

List all available security rules.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `resource_type` | string | terraform, kubernetes, dockerfile, cloudformation |
| `severity` | string | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `framework` | string | CIS-AWS, SOC2, HIPAA, PCI-DSS, etc. |
| `tag` | string | Filter by tag (encryption, networking, etc.) |

**Response:**
```json
{
  "rules": [
    {
      "id": "SHLD-S3-001",
      "description": "S3 bucket missing server-side encryption",
      "severity": "HIGH",
      "resource_type": "terraform",
      "remediation": "Enable SSE-S3 or SSE-KMS encryption",
      "compliance": [
        {"framework": "CIS-AWS", "control_id": "2.1.1"}
      ],
      "tags": ["encryption", "s3", "aws"]
    }
  ],
  "total": 103
}
```

### `POST /rules/custom` (Business+)

Create a custom rule using OPA/Rego policy.

---

## Compliance

### `GET /compliance/dashboard`

Get compliance status across all frameworks.

### `GET /compliance/reports/{framework}`

Generate a compliance report for a specific framework.

**Response:** `200 OK` with PDF download or JSON

---

## Billing

### `GET /billing/subscription`

Get current subscription status.

### `POST /billing/checkout`

Create a Stripe checkout session for plan upgrade.

### `POST /billing/portal`

Create a Stripe billing portal session.

---

## Health

### `GET /health`

Basic health check.

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "rules_loaded": 103,
  "uptime_seconds": 86400
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": {
    "code": "SCAN_LIMIT_EXCEEDED",
    "message": "Free plan allows 50 scans per month. Upgrade to Pro for unlimited.",
    "details": {"used": 50, "limit": 50}
  }
}
```

| HTTP Status | Meaning |
|-------------|---------|
| 400 | Bad request / validation error |
| 401 | Missing or invalid authentication |
| 403 | Insufficient permissions or plan tier |
| 404 | Resource not found |
| 429 | Rate limited or scan limit exceeded |
| 500 | Internal server error |

---

## Rate Limits

| Plan | Requests/min | Scans/month |
|------|-------------|-------------|
| Free | 30 | 50 |
| Pro | 120 | Unlimited |
| Business | 300 | Unlimited |
| Enterprise | 600 | Unlimited |

Rate limit headers are included in every response:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

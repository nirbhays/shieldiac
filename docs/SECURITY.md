# ShieldIaC Security Model

> How ShieldIaC handles your code, data, and credentials securely.

---

## Principles

1. **Minimal access**: We request only the GitHub permissions we need (read code, write comments)
2. **No code storage**: IaC files are processed in memory and never written to disk
3. **Encryption everywhere**: TLS in transit, encryption at rest for all stored data
4. **Org isolation**: All data queries are scoped by organization ID

---

## Data Handling

### What we access
- Changed IaC files in your pull requests (.tf, .yaml, Dockerfile)
- Repository metadata (name, branch, PR number)
- GitHub user/org information for authentication

### What we store
- Scan results (findings with file paths, line numbers, descriptions)
- Security scores and compliance mappings
- Organization and subscription data
- **We do NOT store your source code**

### What we send to third parties
- **OpenAI (GPT-4.1-mini)**: 40-line code snippets around findings for AI fix generation
  - Only for CRITICAL and HIGH severity findings
  - Can be disabled via `SHIELDIAC_AI_FIX_ENABLED=false`
  - Responses are cached for 24 hours to minimize data sent

---

## Authentication

### Webhook Verification
- HMAC-SHA256 signature verification on all GitHub/GitLab webhooks
- Constant-time comparison to prevent timing attacks
- Webhook secrets stored in environment variables (never in code)

### Dashboard Authentication
- Clerk JWT tokens validated against Clerk's JWKS endpoint
- GitHub OAuth for user identity
- Session management handled by Clerk

### API Key Authentication (Business+)
- API keys prefixed with `shld_` for identification
- SHA-256 hashed before storage (raw keys never stored)
- Revocable at any time via dashboard

---

## Input Validation

| Input | Validation | Limit |
|-------|-----------|-------|
| File size | Maximum per file | 5 MB |
| File count | Maximum per scan | 500 files |
| YAML depth | Maximum nesting | 50 levels |
| Scan timeout | Maximum duration | 300 seconds |
| YAML parsing | `yaml.safe_load` only | No code execution |

---

## Threat Model

| Threat | Attack Vector | Mitigation |
|--------|--------------|-----------|
| **Webhook forgery** | Attacker sends fake webhook | HMAC-SHA256 signature verification |
| **YAML bomb** | Recursive YAML aliases | safe_load + depth limit (50) |
| **Large file DoS** | Upload very large files | 5MB file size limit |
| **Path traversal** | Malicious file paths | In-memory processing, no disk I/O |
| **AI prompt injection** | Crafted IaC to manipulate AI output | Hardened system prompt, output validation |
| **Code exfiltration** | Repo code sent externally | Only 40-line snippets to OpenAI |
| **Multi-tenant leak** | Access another org's data | org_id filter on all database queries |
| **Credential exposure** | Secrets in scan results | Finding descriptions reference issues, not values |

---

## Infrastructure Security

- **Cloud Run**: Serverless containers with automatic OS patching
- **Supabase**: SOC 2 Type II compliant, encryption at rest (AES-256)
- **Upstash Redis**: TLS encrypted connections, authentication required
- **Cloudflare**: WAF, DDoS protection, TLS termination
- **Secret Manager**: All API keys and secrets stored in GCP Secret Manager

---

## Compliance

ShieldIaC's own infrastructure follows the security practices it recommends:

| Control | Status |
|---------|--------|
| Encryption at rest | All databases encrypted |
| Encryption in transit | TLS everywhere |
| Access logging | Cloud Run request logs |
| Minimal permissions | Least-privilege IAM roles |
| Dependency scanning | Dependabot + automated updates |
| No secrets in code | All secrets via environment variables |

---

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it to **security@shieldiac.dev**. We follow responsible disclosure practices and will respond within 48 hours.

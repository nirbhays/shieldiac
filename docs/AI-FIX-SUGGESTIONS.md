# ShieldIaC — AI Fix Suggestions

## Overview

ShieldIaC uses GPT-4.1-mini to generate context-aware, production-ready code fixes for CRITICAL and HIGH severity security findings. This document explains how the AI fix pipeline works, how to configure it, and its limitations.

## How It Works

### Pipeline

```
Finding (CRITICAL/HIGH)
    ↓
Build prompt (system + few-shot + finding context)
    ↓
Check cache (SHA-256 hash of rule_id + file + resource)
    ↓ cache miss
Call OpenAI GPT-4.1-mini
    ↓
Extract code fix from response
    ↓
Cache result (24-hour TTL)
    ↓
Attach to Finding as `ai_fix` field
    ↓
Render in PR comment as code diff
```

### Prompt Engineering

The AI fix generator uses a carefully engineered prompt:

1. **System prompt** — Establishes ShieldIaC as an IaC security expert with strict rules:
   - Output ONLY the corrected code snippet (no explanations)
   - Preserve original code style
   - Fix ONLY the specific issue (no unrelated refactoring)
   - Use latest provider syntax
   - Never introduce new security issues

2. **Few-shot examples** — 3 curated examples showing input findings and expected output fixes for Terraform, Kubernetes, and Dockerfile

3. **Finding context** — The actual finding with:
   - Rule ID, severity, description
   - Original code snippet (surrounding lines from the file)
   - File path and resource name

### Example

**Input finding:**
```
Rule: SHLD-S3-001 — S3 bucket missing encryption
Severity: HIGH
File: infra/main.tf

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "private"
}
```

**AI fix output:**
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHIELDIAC_OPENAI_API_KEY` | OpenAI API key | — (required for AI fixes) |
| `SHIELDIAC_OPENAI_MODEL` | Model to use | `gpt-4.1-mini` |
| `SHIELDIAC_AI_FIX_ENABLED` | Enable/disable AI fixes | `true` |
| `SHIELDIAC_AI_FIX_MAX_PER_SCAN` | Max fixes per scan | `10` |
| `SHIELDIAC_AI_FIX_CACHE_TTL` | Cache TTL in seconds | `86400` (24 hours) |

### Severity Threshold

By default, AI fixes are generated only for **CRITICAL** and **HIGH** findings. This balances cost vs. value — lower severity findings typically have well-known fixes that don't need AI generation.

To include MEDIUM findings:
```python
# In scanner_engine.py
AI_FIX_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
```

## Caching Strategy

### Cache Key
```python
key = SHA256(f"{finding.rule_id}:{finding.file_path}:{finding.resource}:{code_snippet}")
```

This ensures:
- Same finding on same code → cache hit (no duplicate API calls)
- Different code for same rule → cache miss (generates fresh fix)
- Code change → new hash → fresh fix

### Cache Backends
- **Development:** In-memory dict (`_fix_cache` in `ai_fix_generator.py`)
- **Production:** Redis with 24-hour TTL (`SHIELDIAC_AI_FIX_CACHE_TTL`)

### Cost Optimization
- GPT-4.1-mini: ~$0.02 per fix generation
- Average scan: 3-5 AI fixes (CRITICAL + HIGH only)
- 24-hour cache eliminates duplicate costs for re-scans
- Max 10 fixes per scan prevents cost runaway

## PR Comment Rendering

AI fixes appear in PR comments as collapsible code blocks:

```markdown
### 🤖 AI Fix Suggestion

<details>
<summary>Click to expand suggested fix for SHLD-S3-001</summary>

\`\`\`hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
\`\`\`

</details>
```

## Limitations

1. **Code context window:** The generator receives ~50 lines around the finding. Very large files may lose context.
2. **No execution validation:** Fixes are syntactically plausible but not tested against `terraform validate` or `kubectl apply --dry-run`.
3. **Provider version assumptions:** Fixes assume latest provider versions (AWS v5+, GCP v5+).
4. **Complex dependencies:** Fixes for resources with many cross-references may be incomplete.
5. **Rate limits:** OpenAI rate limits apply. Burst scans (>100 concurrent) may see 429 errors.

## Fallback Behavior

If the AI fix generator fails (API error, rate limit, no API key):
1. The finding is still reported normally
2. The `ai_fix` field is set to `None`
3. The static `remediation` text from the rule is shown instead
4. A warning is logged but the scan continues

## Supported LLM Providers

Currently: **OpenAI** (GPT-4.1-mini recommended for cost/quality balance)

Planned:
- Anthropic Claude (via compatible API)
- Local models via Ollama (for air-gapped/self-hosted deployments)
- Azure OpenAI Service (for enterprise compliance)

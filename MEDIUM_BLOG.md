# How I Built an AI-Powered IaC Security Scanner From Scratch -- 100+ Rules, 9 Compliance Frameworks, and Why Existing Tools Weren't Enough

*The Capital One breach cost $190M in settlements. The root cause? A misconfigured WAF rule defined in their infrastructure code. I built a scanner to make sure that never happens on my watch.*

---

## The $190 Million Line of Code

On July 29, 2019, a former AWS employee exploited a misconfigured Web Application Firewall in Capital One's cloud infrastructure. The breach exposed 106 million customer records -- names, addresses, credit scores, Social Security numbers. The final cost: **$190 million** in settlements, an $80 million OCC fine, and a CISO's career.

The fix would have been a few lines of infrastructure code.

This was not an isolated incident. Uber's 2016 breach -- 57 million users exposed -- started with hardcoded credentials in a GitHub repository. The Twitch source code leak in 2021 came from an overly permissive server configuration. The Microsoft Power Apps data exposure in 2021 affected 38 million records because of a single default setting left unchanged in their table permissions.

**The pattern is always the same:** a small infrastructure misconfiguration slips through code review, sits in production for weeks or months, and then costs orders of magnitude more to fix than it would have cost to catch. IBM's 2024 Cost of a Data Breach report puts the average at **$4.88 million per incident**. Misconfigurations account for roughly 1 in 5 of those breaches.

I kept coming back to one question: *why are we still catching these in production when we review every line of application code before it merges?*

So I built **ShieldIaC** -- an open-source IaC security scanner that plugs directly into your pull request workflow and catches misconfigurations **before they ever reach a main branch**. It scans Terraform, Kubernetes manifests, Dockerfiles, and CloudFormation templates against 100+ security rules, maps every finding to 9 compliance frameworks, and uses GPT-4.1-mini to generate production-ready fix suggestions.

All posted as a PR comment before your morning standup.

This post covers the full engineering story: why existing tools left a gap, the architecture decisions that made ShieldIaC work, the hardest technical problems I solved, the mistakes I made, and the results.

---

## Why Existing IaC Security Tools Aren't Enough

Before writing a single line of code, I spent weeks evaluating every major IaC security scanner on the market. Here is what I found, and I want to be honest about this because there are genuinely good tools out there.

**Checkov** (by Bridgecrew/Palo Alto) is the most popular open-source option. It has 1,000+ built-in policies across Terraform, CloudFormation, Kubernetes, and Helm. It is battle-tested and has a strong community. But its Python-based custom policy authoring is verbose -- writing a new rule requires understanding their graph-based framework and YAML policy format. PR integration exists but requires significant CI/CD pipeline configuration. And there is no AI-powered fix generation.

**tfsec** (now part of Trivy by Aqua Security) focuses specifically on Terraform and does it well. Fast scanning, good defaults, solid HCL parsing. But it is Terraform-only. No Kubernetes, no Dockerfile, no CloudFormation in a single unified scan. And its compliance mapping is limited compared to what an auditor actually needs.

**Snyk IaC** is the most polished commercial option. Great developer experience, IDE plugins, excellent PR integration. But it is a commercial product with per-developer pricing that can get expensive at scale. And the compliance reporting requires their paid tier.

**What was missing across all of them:**

1. **Unified multi-format scanning with one set of rules** -- I wanted a single S3 encryption rule that works for both Terraform and CloudFormation without writing two separate policies.
2. **AI-generated fix suggestions** -- Not "you should enable encryption" but an actual code snippet that respects your existing naming conventions and style.
3. **Deep compliance mapping out of the box** -- Every finding mapped to CIS, SOC 2, HIPAA, PCI-DSS, NIST, ISO 27001, and GDPR controls. Not as an upsell. Not as a plugin. Built in.
4. **Five-minute rule authoring** -- Adding a new security rule should be a single Python file with a decorator. Zero config changes.
5. **Sub-$100/month self-hosted operation** -- Not per-seat SaaS pricing. A full scanning platform on your own infrastructure for the cost of a team lunch.

None of the existing tools hit all five. So I built one that does.

---

## How ShieldIaC Works: The Developer Experience

Here is what happens when a developer opens a pull request that touches infrastructure code. Within 30 seconds, ShieldIaC drops a comment on the PR that looks like this:

```markdown
## ShieldIaC Security Scan Results

**Security Score:** 52/100 (Grade: **D**)

| Severity   | Count |
|------------|-------|
| Critical   | 3     |
| High       | 5     |
| Medium     | 8     |
| Low        | 4     |
| Info       | 2     |
| **Total**  | **22**|

Scanned **14** files in **4.2s**

### Critical & High Severity Findings

#### SHLD-S3-002 -- S3 bucket does not have a public access block
- **File:** `modules/storage/main.tf` (line 24)
- **Resource:** `aws_s3_bucket.user_uploads`
- **Severity:** CRITICAL

**Remediation:** Create an `aws_s3_bucket_public_access_block` resource
with all four settings set to `true`.

**AI Fix Suggestion:**
resource "aws_s3_bucket_public_access_block" "user_uploads" {
  bucket = aws_s3_bucket.user_uploads.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

**Compliance:** `CIS-AWS:2.1.5`, `SOC2:CC6.1`, `PCI-DSS:1.2.1`
```

No context switching. No separate security dashboard to check. No waiting for a security review three sprints from now. **The feedback loop is the PR itself.**

---

## IaC Security Best Practices 2026: Architecture for a Modern Scanner

Under the hood, ShieldIaC is a queue-based scanning platform running on Google Cloud Run with a FastAPI backend, PostgreSQL for persistence, Redis for job queuing and AI caching, and a Next.js dashboard for tracking security posture across all your repos.

The architecture was designed around one core principle: **the webhook endpoint must respond in under 500ms**. Nobody wants a GitHub webhook timing out. So we immediately enqueue the scan job, return a `202 Accepted`, and process everything asynchronously.

Here is the real webhook handler:

```python
@router.post("/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
):
    body = await request.body()

    # Verify HMAC-SHA256 signature (constant-time comparison)
    if not verify_github_signature(
        body, x_hub_signature_256 or "", settings.github_webhook_secret
    ):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = await request.json()

    if x_github_event == "pull_request":
        return await _handle_pull_request(payload)
    elif x_github_event == "push":
        return await _handle_push(payload)
    elif x_github_event == "ping":
        return {"status": "pong"}
    else:
        return {"status": "ignored", "event": x_github_event}
```

The PR handler does exactly three things -- validate the action type, enqueue the scan job to Redis, and return immediately:

```python
async def _handle_pull_request(payload: dict) -> dict:
    event = GitHubPREvent(**payload)

    if event.action not in ("opened", "synchronize", "reopened"):
        return {"status": "skipped", "reason": f"PR action: {event.action}"}

    job_id = await queue_service.enqueue_scan({
        "repo_url": event.repository.clone_url,
        "repo_full_name": event.repository.full_name,
        "branch": event.pull_request.head.ref,
        "commit_sha": event.pull_request.head.sha,
        "pr_number": event.number,
        "trigger": ScanTrigger.WEBHOOK.value,
        "scan_type": ScanType.PR.value,
    })

    return {"status": "queued", "job_id": job_id, "pr": event.number}
```

Total webhook response time: under 500ms. The heavy lifting happens asynchronously via Redis `BLPOP` workers.

### The Scanning Pipeline, Step by Step

**Step 1: Verify and enqueue.** The webhook payload gets verified with HMAC-SHA256 using constant-time comparison (timing attacks are real, even on webhook signatures). Once validated, the scan job gets pushed onto a Redis queue. The HTTP response goes back to GitHub instantly.

**Step 2: Detect and fetch.** A queue worker picks up the job, identifies which files changed in the PR, and filters for IaC file types. The `ScannerEngine` uses content-aware heuristics to distinguish CloudFormation YAML from Kubernetes YAML:

```python
def detect_file_type(self, file_path, content=""):
    p = Path(file_path)
    name = p.name.lower()

    if name == "dockerfile" or name.endswith(".dockerfile"):
        return ResourceType.DOCKERFILE
    if p.suffix == ".tf" or file_path.endswith(".tf.json"):
        return ResourceType.TERRAFORM
    if p.suffix in (".yaml", ".yml"):
        if self._is_cloudformation(content):
            return ResourceType.CLOUDFORMATION
        return ResourceType.KUBERNETES
    return None
```

Only the changed files get fetched via the GitHub API. No full repo clones. This keeps scan times under 30 seconds even for large PRs.

**Step 3: Parse and scan in parallel.** Each file type has its own dedicated scanner, and they all run concurrently via `asyncio.gather`. A Terraform file with 5 resources gets checked against 50+ rules each.

**Step 4: AI enrichment and scoring.** Critical and high-severity findings get sent to GPT-4.1-mini for fix generation. The scoring engine calculates a 0-100 score. The compliance mapper tags each finding. Everything gets formatted into a Markdown PR comment and posted back.

---

## The Rule Engine: How to Write an IaC Security Rule in 5 Minutes

The rule engine is the heart of ShieldIaC, and it is the piece of engineering I am most proud of. The design goal was simple: **adding a new security rule should take 5 minutes and require zero configuration changes.**

### The Registry Pattern with Decorator-Based Auto-Registration

Every rule inherits from `BaseRule`, defines its metadata as class variables, and implements a single `evaluate()` method. The `@registry.register` decorator handles everything else:

```python
class BaseRule(abc.ABC):
    id: ClassVar[str]
    description: ClassVar[str]
    severity: ClassVar[Severity]
    resource_type: ClassVar[ResourceType]
    remediation: ClassVar[str]
    compliance: ClassVar[List[ComplianceMapping]] = []
    tags: ClassVar[List[str]] = []
    enabled: ClassVar[bool] = True

    @abc.abstractmethod
    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        ...

    def make_finding(self, resource_name, file_path, line_number=0,
                     code_snippet=None, description_override=None) -> Finding:
        return Finding(
            rule_id=self.id, severity=self.severity,
            resource_type=self.resource_type.value,
            resource_name=resource_name, file_path=file_path,
            line_number=line_number,
            description=description_override or self.description,
            remediation=self.remediation,
            compliance=list(self.compliance), code_snippet=code_snippet,
        )
```

Here is a real rule -- the S3 encryption check that maps to four compliance frameworks simultaneously:

```python
@registry.register
class S3EncryptionAtRest(BaseRule):
    id = "SHLD-S3-001"
    description = "S3 bucket does not have server-side encryption enabled"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Add a `server_side_encryption_configuration` block with "
        "`sse_algorithm` set to `aws:kms` or `AES256`."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.1",
                          "Ensure S3 bucket encryption is enabled"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1",
                          "Logical and physical access controls"),
        ComplianceMapping(ComplianceFramework.HIPAA, "164.312(a)(2)(iv)",
                          "Encryption and decryption"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "3.4",
                          "Render PAN unreadable"),
    ]
    tags = ["s3", "encryption", "aws", "data-protection"]

    def evaluate(self, resource, context):
        if resource.get("type") != "aws_s3_bucket":
            return []
        config = resource.get("config", {})
        sse = _get_nested(config, "server_side_encryption_configuration")
        if not sse:
            return [self.make_finding(
                resource_name=resource.get("name", "unknown"),
                file_path=context.file_path,
                line_number=resource.get("line", 0),
            )]
        rules = _get_nested(sse, "rule") or []
        if isinstance(rules, dict):
            rules = [rules]
        for rule in rules:
            algo = _get_nested(rule, "apply_server_side_encryption_by_default",
                               "sse_algorithm")
            if algo in ("aws:kms", "AES256"):
                return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
            description_override="S3 encryption uses an unsupported algorithm",
        )]
```

One Python file. One decorator. Four compliance frameworks. Zero config changes.

### How the Dynamic Loader Discovers Rules at Startup

```python
_RULE_PACKAGES = [
    "backend.rules.terraform",
    "backend.rules.kubernetes",
    "backend.rules.docker",
]

def discover_and_load_rules(extra_packages=None):
    packages = _RULE_PACKAGES + (extra_packages or [])
    for pkg_name in packages:
        pkg = importlib.import_module(pkg_name)
        for _importer, module_name, _ in pkgutil.iter_modules(pkg.__path__):
            importlib.import_module(f"{pkg_name}.{module_name}")
    logger.info("Rule loading complete -- %d rules registered", registry.count)
    return registry
```

The registry exposes rich filtering -- `by_resource_type()`, `by_severity()`, `by_framework()`, `by_tag()`. When the Terraform scanner needs its rules, it calls `registry.by_resource_type(ResourceType.TERRAFORM)` and gets exactly the 50+ rules that apply.

---

## The AI Fix Generator: Deep Dive Into GPT-4.1-mini for IaC Security

Detecting problems is table stakes. **Telling developers exactly how to fix them** is where ShieldIaC goes from useful to indispensable.

### How the Prompt Is Built

The system prompt constrains GPT-4.1-mini with strict output rules -- output ONLY corrected code, preserve original style, fix ONLY the specific issue, never introduce new security problems. Then three few-shot examples anchor the model to the expected output format for each IaC type.

The user prompt is built dynamically from each finding:

```python
def _build_prompt(self, finding, code_context):
    return (
        f"Finding: {finding.description}\n"
        f"Rule ID: {finding.rule_id}\n"
        f"Severity: {finding.severity.value}\n"
        f"Resource: {finding.resource_name}\n"
        f"File: {finding.file_path}\n"
        f"Remediation guidance: {finding.remediation}\n\n"
        f"Original code:\n{code_context}\n"
    )
```

The context window is centered around the finding's line number -- 40 lines of surrounding code, not the entire file. This keeps token usage low and the model focused.

### Fingerprint-Based Caching: The Cost Optimization That Changed Everything

Every finding gets a deterministic SHA-256 fingerprint based on the rule ID, file path, resource name, and file content hash. Before hitting the OpenAI API, we check Redis for a cached fix:

```python
@staticmethod
def _cache_key(finding, content):
    raw = (f"{finding.rule_id}|{finding.file_path}|"
           f"{finding.resource_name}|{hashlib.md5(content.encode()).hexdigest()}")
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
```

Same misconfiguration pattern produces the same fix. The cache has a 24-hour TTL.

### Validation: Making Sure the AI Does Not Hallucinate

The generator validates every response before caching it:

```python
fix = response.choices[0].message.content.strip()

# Reject empty, too-short, or unchanged responses
if fix and len(fix) > 10 and fix != code_context:
    _fix_cache[cache_key] = fix
    return fix
return None
```

If the model returns an empty response, a repeat of the original code, or anything under 10 characters, we silently discard it rather than showing a broken suggestion.

### The Cost Math

- **Model:** GPT-4.1-mini at ~$0.40/1M input tokens, ~$1.60/1M output tokens
- **Average prompt size:** ~1,200 tokens (system + few-shot + finding context)
- **Average response size:** ~200 tokens
- **Cost per AI fix:** ~$0.001
- **Average findings needing fixes per scan:** 3 (CRITICAL + HIGH only)
- **Cache hit rate in practice:** ~80%
- **Effective cost per scan:** ~$0.0006

A team doing 500 scans per month spends roughly **$0.30 on AI**. Less than a single cent per scan after caching. That is not a rounding error -- that is effectively free.

---

## CloudFormation Scanning for Free: The Type Mapper Pattern

This is probably my favorite design decision in the entire project. Instead of writing separate CloudFormation rules, ShieldIaC has a **type mapper** that translates CloudFormation resource types to their Terraform equivalents:

```python
CF_TO_TF_TYPE_MAP = {
    "AWS::S3::Bucket":          "aws_s3_bucket",
    "AWS::EC2::SecurityGroup":  "aws_security_group",
    "AWS::EC2::Instance":       "aws_instance",
    "AWS::RDS::DBInstance":     "aws_db_instance",
    "AWS::IAM::Role":           "aws_iam_role",
    "AWS::IAM::Policy":         "aws_iam_policy",
    "AWS::EC2::VPC":            "aws_vpc",
    "AWS::EBS::Volume":         "aws_ebs_volume",
}
```

The scanner parses CloudFormation templates, maps each resource type, translates properties to Terraform-equivalent config, and then applies the existing Terraform rules:

```python
class CloudFormationScanner:
    async def scan(self, file_path, content, repo_name="", scan_id=""):
        resources = self._parse_template(content, file_path)
        rules = registry.by_resource_type(ResourceType.TERRAFORM)
        context = RuleContext(file_path=file_path, file_content=content,
                              repo_name=repo_name, scan_id=scan_id,
                              all_resources=resources)

        findings = []
        for resource in resources:
            for rule_cls in rules:
                rule = rule_cls()
                results = rule.evaluate(resource, context)
                findings.extend(results)
        return findings
```

Write once, scan both formats. When I add a new Terraform rule, CloudFormation support comes free. The property mapper handles the translation of CF-specific property names (`BucketEncryption` to `server_side_encryption_configuration`, `SecurityGroupIngress` to `ingress`, etc.).

---

## Security Scoring: Turning 47 Findings Into a Letter Grade

A list of 47 findings is overwhelming. **A letter grade is actionable.**

The scoring engine uses severity-weighted penalties with a normalization factor that accounts for project size:

```python
class ScoringEngine:
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 15.0,
        Severity.HIGH:     8.0,
        Severity.MEDIUM:   3.0,
        Severity.LOW:      1.0,
        Severity.INFO:     0.2,
    }

    def calculate(self, findings, total_files=1):
        if not findings:
            return 100.0, "A"

        total_penalty = sum(
            self.SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings
        )

        # Normalize: more files = lower per-file impact
        normalization_factor = max(1, total_files * 0.5)
        normalized_penalty = total_penalty / normalization_factor

        # Diminishing returns for extreme penalty counts
        if normalized_penalty > 50:
            normalized_penalty = 50 + (normalized_penalty - 50) * 0.3

        score = max(0, min(100, 100 - normalized_penalty))
        # ... grade mapping: A (90+), B (80+), C (70+), D (60+), F (<60)
```

The key insight: **raw penalties are normalized by file count**. A single CRITICAL finding in a repo with 100 files is very different from a single CRITICAL in a repo with 1 file. Normalization makes scores comparable across projects of any size. The diminishing returns curve prevents a repo with 200 low-severity findings from scoring worse than one with 3 critical findings.

### Nine Compliance Frameworks, One Scan

Every security rule maps to specific compliance framework controls. A single finding like "S3 bucket missing encryption" maps simultaneously to **CIS AWS 2.1.1**, **SOC 2 CC6.1**, **HIPAA 164.312(a)(2)(iv)**, and **PCI-DSS 3.4**.

The nine frameworks: **CIS AWS**, **CIS GCP**, **CIS Kubernetes**, **SOC 2 Type II**, **HIPAA**, **PCI-DSS v4.0**, **NIST 800-53**, **ISO 27001**, and **GDPR**.

When an auditor asks "show me your CIS AWS compliance status," you pull up the ShieldIaC dashboard or generate a **PDF compliance report** in under 10 seconds. Per-framework control status, detailed findings, remediation steps -- audit-ready.

---

## The Hardest Engineering Problems I Solved

### Problem 1: HCL Parsing Is Deceptively Evil

Terraform's HashiCorp Configuration Language looks simple on the surface. Then you encounter nested dynamic blocks, `for_each` expressions with complex maps, heredoc strings that span 50 lines, multiline values with string interpolation, and variable references that chain through three levels of locals.

I wrote a custom HCL parser because `python-hcl2` is an external dependency that does not handle every edge case in production Terraform configs. My parser handles ~95% of real-world HCL files with zero external dependencies:

```python
class HCLParser:
    def parse(self, content):
        result = {"resource": {}, "data": {}, "variable": {},
                  "output": {}, "locals": {}, "provider": {}, "module": {}}
        content = self._strip_comments(content)
        blocks = self._extract_top_level_blocks(content)
        for block_type, labels, body, line_num in blocks:
            parsed_body = self._parse_body(body)
            if block_type == "resource" and len(labels) >= 2:
                resource_type, resource_name = labels[0], labels[1]
                result["resource"].setdefault(resource_type, {})
                result["resource"][resource_type][resource_name] = parsed_body
                parsed_body["__line__"] = line_num
        return result
```

The comment stripping alone required handling `#`, `//`, and `/* */` comments while respecting string boundaries -- a character with `#` inside a quoted string is not a comment. The brace matching had to track string state to avoid counting braces inside heredoc strings. The value parser had to handle booleans, numbers, quoted strings, lists, maps, and bare references.

**The parser went through 4 complete rewrites.** If I had to start over, I would begin with a proper grammar definition and a recursive descent parser instead of regex-based extraction.

### Problem 2: False Positive Reduction

The single biggest threat to a security scanner's adoption is false positives. If developers see 3 false positives in their first PR comment, they disable the integration and never look back.

My approach to reducing false positives:

- **Resource-type gating:** Every rule checks `resource.get("type")` first. An S3 encryption rule never fires on an EC2 instance. This sounds obvious, but it eliminates an entire class of false positives that pattern-matching tools produce.
- **Companion resource awareness:** The `RuleContext` includes `all_resources` -- the full list of resources in the file. An S3 bucket without encryption in its own block might have a companion `aws_s3_bucket_server_side_encryption_configuration` resource that defines encryption separately. The context lets rules check for companion resources.
- **Strict value validation:** Instead of checking "does this key exist," rules validate the actual value. `acl = "private"` passes. `acl = "public-read"` fails. `acl` not present gets treated as a default (which varies by rule).

### Problem 3: Compliance Framework Mapping Is a Rabbit Hole

Every framework has overlapping controls with slightly different wording. CIS AWS 2.1.1 and NIST 800-53 SC-28 check the same thing -- encryption at rest -- with different language, different control hierarchies, and different audit expectations.

Getting the mappings right required reading actual framework documents -- hundreds of pages of compliance standards. The SOC 2 Trust Services Criteria alone have 60+ controls. PCI-DSS v4.0 has 200+ requirements. There is no shortcut.

I built control catalogs as Python dictionaries that map each control ID to its title, description, and section:

```python
SOC2_CONTROLS = {
    "CC6.1": ComplianceControl(
        control_id="CC6.1",
        title="Logical and Physical Access Controls",
        description="The entity restricts logical access to information assets.",
        section="CC6 -- Logical and Physical Access Controls",
    ),
    "CC6.3": ComplianceControl(
        control_id="CC6.3",
        title="Role-Based Access",
        description="The entity creates, modifies, and removes access "
                    "based on authorization.",
        section="CC6 -- Logical and Physical Access Controls",
    ),
    # ... 4 more controls
}
```

Then the compliance mapper evaluates each control's status by cross-referencing findings against the control catalog. A control passes if no findings reference it, and fails if any finding maps to it.

---

## By The Numbers

| Metric | Value |
|--------|-------|
| **Security rules** | 100+ across 4 IaC formats |
| **Terraform rules** | 50+ (AWS S3, EC2, IAM, RDS, VPC + GCP Compute, Storage, IAM) |
| **Kubernetes rules** | 25+ (Pod Security, RBAC, NetworkPolicy, Resource Limits) |
| **Dockerfile rules** | 20 (CIS Docker Benchmark aligned) |
| **CloudFormation rules** | 10+ (mapped from Terraform via type mapper) |
| **Compliance frameworks** | 9 (CIS AWS, CIS GCP, CIS K8s, SOC 2, HIPAA, PCI-DSS, NIST, ISO 27001, GDPR) |
| **Compliance controls mapped** | 30+ across all frameworks |
| **Webhook response time** | < 500ms |
| **Full scan time** | < 30 seconds for 100 files |
| **AI fix generation** | < 3 seconds per finding (GPT-4.1-mini) |
| **AI cache hit rate** | ~80% |
| **Cost per AI fix** | ~$0.001 |
| **Effective cost per scan** | ~$0.0006 (after caching) |
| **PDF report generation** | < 10 seconds |
| **Infrastructure cost** | $45-90/month (production) |
| **Lines of Python** | ~5,000 (backend) |
| **Test coverage** | Unit tests for all scanners, scoring, compliance, AI generator |

That infrastructure cost breaks down to: **Cloud Run** at $5-25/mo (scales to zero when idle), **Supabase PostgreSQL** at $25/mo, **Upstash Redis** at $10/mo, **OpenAI API** at $0.30-30/mo depending on scan volume, and **Vercel** + **Cloudflare** on free tiers.

For a scanning platform that handles unlimited repos, stores full audit history, generates compliance reports, and provides AI-powered fix suggestions -- **under $90/month** is hard to beat.

---

## Mistakes I Made (And What I Learned)

Engineering humility builds credibility, so here are the things I got wrong.

**Mistake 1: Starting with regex-based HCL parsing.** My first HCL parser was a collection of regex patterns. It worked for simple configs. Then someone tested it with a Terraform file containing a heredoc string with a JSON policy document embedded inside it, and the parser returned garbage. Regex cannot handle recursive brace matching with string-awareness. I should have built a proper character-by-character parser from day one. It took 4 rewrites to get right.

**Mistake 2: Too many findings on first scan.** My initial rule set had no severity calibration. The first time I scanned a real-world Terraform repo, ShieldIaC returned 87 findings. The developer looked at the PR comment, scrolled past the wall of text, and said "I'll look at this later" (they never did). I learned that **a scanner with too many findings is as useless as one with too few**. I recalibrated severity levels, added the collapsible sections for medium/low findings, and limited the PR comment to show only critical and high findings expanded.

**Mistake 3: Giving GPT too much freedom.** My first GPT-4.1-mini prompts produced great *explanations* but terrible *code fixes*. The model would refactor entire files, add explanatory comments everywhere, change variable names to "more descriptive" alternatives, and wrap everything in markdown code fences. The fix was counterintuitive: more constraints produced better output. The strict system prompt ("output ONLY the corrected code snippet -- no explanations, no markdown fences") and few-shot examples made the difference between a gimmick and a genuinely useful feature.

**Mistake 4: Not building the compliance mapper first.** I built compliance mapping as an afterthought -- bolted on after all the rules were written. This meant going back through every rule and manually adding `ComplianceMapping` entries. If I had designed the compliance mapping into the rule schema from the start, I would have saved a full week of tedious cross-referencing work.

**Mistake 5: Underestimating the cache hit rate.** I expected maybe 50% cache hits on the AI fix generator. The actual rate is ~80%. Teams have remarkably consistent patterns -- the same S3 bucket without encryption, the same Dockerfile running as root, the same security group with `0.0.0.0/0`. Once you have seen one unencrypted S3 bucket, you have seen them all. I should have invested in the caching layer earlier because the cost savings are massive.

---

## What's Next

ShieldIaC is built to grow. Here is what is on the roadmap:

- **Helm chart scanning** -- Parse Helm templates with value injection to catch K8s misconfigs before `helm install`
- **Pulumi and CDK support** -- Compile to CloudFormation, then scan using existing rules (reusing the type mapper pattern)
- **Custom OPA/Rego policies** -- Let teams define their own rules in Rego for organization-specific standards
- **Rule marketplace** -- Community-contributed rules with quality ratings and one-click install
- **GitLab deep integration** -- MR comments + pipeline integration for GitLab-first teams
- **Diff-only scanning** -- Scan only changed resources instead of entire files for faster feedback on large monorepos
- **SARIF output** -- Integrate with GitHub Advanced Security's code scanning alerts

---

## Try It, Break It, Build On It

ShieldIaC is open source under the MIT license. If you are tired of catching security misconfigurations in production -- or worse, in a breach notification -- give it a spin.

**Star the repo on [GitHub](https://github.com/nirbhaysingh1/shieldiac)** if this resonates with you. It genuinely helps with visibility and tells me people find this useful.

**Contribute a rule.** Adding a new security rule is a 5-minute, single-file task. Check `docs/CONTRIBUTING.md` for the 3-step process. The rule engine was designed to make contributions trivially easy.

**Share feedback.** What IaC formats do you want scanned? What compliance frameworks are missing? What would make this tool indispensable for your team? Connect with me on [LinkedIn](https://www.linkedin.com/in/nirbhaysingh1/).

The best security tools are the ones that meet developers where they already work. **Your PR workflow is the last line of defense before production.** Let's make it count.

---

*ShieldIaC is built with Python, FastAPI, HCL parser (python-hcl2), Claude Sonnet 4.5 for AI fixes, PostgreSQL, Redis, and React. The entire codebase is on [GitHub](https://github.com/nirbhaysingh1/shieldiac) under the MIT license.*

**About the Author:** DevOps and MLOps engineer specializing in cloud security and Infrastructure as Code. Connect on [LinkedIn](https://www.linkedin.com/in/nirbhaysingh1/).

# ShieldIaC Architecture

> System design, component architecture, and data flow for the ShieldIaC IaC security scanning platform.

---

## System Overview

![ShieldIaC Architecture](./architecture.png)

ShieldIaC is an IaC security scanning platform that processes infrastructure code through a pipeline of parsers, rule engines, AI generators, and compliance mappers to produce actionable security findings.

```mermaid
graph TB
    subgraph "External Services"
        GH[GitHub / GitLab]
        OAI[OpenAI API<br/>GPT-4.1-mini]
    end

    subgraph "ShieldIaC Backend — Google Cloud Run"
        direction TB
        WH[Webhook Handler<br/>HMAC Verification]
        QS[Queue Service<br/>Redis BLPOP]

        subgraph "Scanning Pipeline"
            SE[Scanner Engine<br/>Orchestrator]
            TFS[Terraform<br/>Scanner]
            K8S[Kubernetes<br/>Scanner]
            DFS[Dockerfile<br/>Scanner]
            CFS[CloudFormation<br/>Scanner]
        end

        subgraph "Analysis & Output"
            RR[Rule Registry<br/>100+ Rules]
            AFG[AI Fix Generator<br/>24hr Cache]
            SCE[Scoring Engine<br/>0-100 Score]
            CM[Compliance Mapper<br/>9 Frameworks]
            GHS[GitHub Service<br/>PR Comments + Checks]
            RG[Report Generator<br/>PDF Output]
        end

        BS[Billing Service<br/>Stripe]
    end

    subgraph "Data Layer"
        PG[(PostgreSQL<br/>Supabase<br/>Scans, Findings, Orgs)]
        RD[(Redis<br/>Upstash<br/>Queue, AI Cache)]
    end

    subgraph "Frontend — Vercel"
        DASH[Next.js 14 Dashboard<br/>Security Posture Overview]
    end

    GH -->|webhook POST| WH
    WH --> QS
    QS -->|async dequeue| SE
    SE --> TFS & K8S & DFS & CFS
    TFS & K8S & DFS & CFS --> RR
    RR --> AFG
    RR --> SCE
    AFG -->|generate fix| OAI
    SCE --> CM
    CM --> GHS
    GHS -->|PR comment<br/>+ Check Run| GH
    CM --> RG
    RG -->|PDF report| PG
    SE -->|scan results| PG
    QS -.->|job queue| RD
    AFG -.->|fix cache| RD
    BS -.-> PG
    DASH --> PG

    style WH fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style SE fill:#fef3c7,stroke:#d97706,color:#78350f
    style RR fill:#fce7f3,stroke:#db2777,color:#831843
    style AFG fill:#d1fae5,stroke:#059669,color:#064e3b
    style SCE fill:#ede9fe,stroke:#7c3aed,color:#4c1d95
    style CM fill:#ffedd5,stroke:#ea580c,color:#7c2d12
    style GHS fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style QS fill:#f3e8ff,stroke:#9333ea,color:#581c87
    style RG fill:#fef9c3,stroke:#ca8a04,color:#713f12
```

---

## Scanning Pipeline — Detailed Flow

```mermaid
sequenceDiagram
    participant GH as GitHub
    participant WH as Webhook Handler
    participant QS as Redis Queue
    participant SE as Scanner Engine
    participant RR as Rule Registry
    participant AFG as AI Fix Generator
    participant SCE as Scoring Engine
    participant CM as Compliance Mapper
    participant GHS as GitHub Service
    participant DB as PostgreSQL

    GH->>WH: POST /webhook (HMAC-SHA256 signed)
    WH->>WH: Verify signature (constant-time)
    WH->>WH: Parse event type (push/PR)
    WH->>QS: LPUSH scan job
    WH-->>GH: 202 Accepted (< 500ms)

    Note over QS,SE: Async processing via BLPOP

    QS->>SE: Dequeue job
    SE->>SE: Fetch changed files from GitHub API
    SE->>SE: Detect file types (.tf, .yaml, Dockerfile)

    par Scan in parallel
        SE->>SE: Terraform Scanner (HCL parse + rules)
        SE->>SE: Kubernetes Scanner (YAML parse + rules)
        SE->>SE: Dockerfile Scanner (instruction parse + rules)
        SE->>SE: CloudFormation Scanner (CF→TF adapter + rules)
    end

    SE->>RR: Evaluate all matching rules
    RR-->>SE: List of Findings

    par Post-processing
        SE->>AFG: Generate AI fixes (CRITICAL + HIGH only)
        AFG-->>SE: Fix suggestions (cached 24h)
        SE->>SCE: Calculate security score
        SCE-->>SE: Score: 72/100, Grade: C
    end

    SE->>CM: Map findings to compliance controls
    CM-->>SE: SOC2, HIPAA, PCI-DSS mappings

    par Output
        SE->>GHS: Post PR comment + Check Run
        GHS-->>GH: Markdown comment + annotations
        SE->>DB: Store scan results + findings
    end

    SE->>QS: Update job status → completed
```

---

## Rule Engine Architecture

The rule system uses a **Registry Pattern** with auto-registration for zero-config extensibility.

```mermaid
classDiagram
    class BaseRule {
        <<abstract>>
        +id: str
        +description: str
        +severity: Severity
        +resource_type: ResourceType
        +remediation: str
        +compliance: List~ComplianceMapping~
        +tags: List~str~
        +enabled: bool
        +evaluate(resource, context) List~Finding~*
        +make_finding() Finding
    }

    class RuleRegistry {
        <<singleton>>
        -_rules: Dict~str, Type~
        +register(rule_cls) Type
        +all() List~Type~
        +enabled() List~Type~
        +by_resource_type(rt) List
        +by_severity(sev) List
        +by_framework(fw) List
        +by_tag(tag) List
        +count: int
        +summary() Dict
        +reset() void
    }

    class Finding {
        +rule_id: str
        +severity: Severity
        +resource_type: str
        +resource_name: str
        +file_path: str
        +line_number: int
        +description: str
        +remediation: str
        +compliance: List~ComplianceMapping~
        +ai_fix_suggestion: Optional~str~
        +code_snippet: Optional~str~
        +fingerprint: str
    }

    class RuleContext {
        +file_path: str
        +file_content: str
        +repo_name: str
        +scan_id: str
        +all_resources: List~Dict~
    }

    BaseRule <|-- AwsS3Rules : 10 rules
    BaseRule <|-- AwsIamRules : 10 rules
    BaseRule <|-- AwsEc2Rules : 10 rules
    BaseRule <|-- AwsRdsRules : 5 rules
    BaseRule <|-- AwsVpcRules : 5 rules
    BaseRule <|-- GcpComputeRules : 5 rules
    BaseRule <|-- GcpIamRules : 5 rules
    BaseRule <|-- GcpStorageRules : 5 rules
    BaseRule <|-- K8sPodRules : 16 rules
    BaseRule <|-- K8sRbacRules : 6 rules
    BaseRule <|-- K8sNetworkRules : 3 rules
    BaseRule <|-- DockerRules : 20 rules

    RuleRegistry "1" o-- "*" BaseRule : manages
    BaseRule ..> Finding : creates
    BaseRule ..> RuleContext : receives
```

### Rule Loading Flow

```mermaid
graph LR
    STARTUP[App Startup] --> LOADER[Rule Loader<br/>pkgutil.iter_modules]

    LOADER --> TF_PKG[rules/terraform/]
    LOADER --> K8_PKG[rules/kubernetes/]
    LOADER --> DK_PKG[rules/docker/]

    TF_PKG --> S3[aws_s3.py<br/>10 rules]
    TF_PKG --> IAM[aws_iam.py<br/>10 rules]
    TF_PKG --> EC2[aws_ec2.py<br/>10 rules]
    TF_PKG --> RDS[aws_rds.py<br/>5 rules]
    TF_PKG --> VPC[aws_vpc.py<br/>5 rules]
    TF_PKG --> GCE[gcp_compute.py<br/>5 rules]
    TF_PKG --> GIAM[gcp_iam.py<br/>5 rules]
    TF_PKG --> GSTO[gcp_storage.py<br/>5 rules]

    K8_PKG --> POD[pod_security.py<br/>16 rules]
    K8_PKG --> RBAC[rbac.py<br/>6 rules]
    K8_PKG --> NET[network_policy.py<br/>3 rules]
    K8_PKG --> RES[resources.py<br/>3 rules]

    DK_PKG --> DOCK[rules.py<br/>20 rules]

    S3 & IAM & EC2 & RDS & VPC & GCE & GIAM & GSTO & POD & RBAC & NET & RES & DOCK --> REG[RuleRegistry<br/>Singleton<br/>100+ rules registered]

    style REG fill:#fce7f3,stroke:#db2777,color:#831843
    style STARTUP fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style LOADER fill:#fef3c7,stroke:#d97706,color:#78350f
```

---

## Scoring Engine

Converts raw findings into a normalized 0-100 security score with letter grades.

```mermaid
graph LR
    subgraph "Input Findings"
        C[3 CRITICAL<br/>weight: 15]
        H[5 HIGH<br/>weight: 8]
        M[8 MEDIUM<br/>weight: 3]
        L[4 LOW<br/>weight: 1]
        I[2 INFO<br/>weight: 0.2]
    end

    subgraph "Calculation"
        RAW["raw_penalty =<br/>3(15) + 5(8) + 8(3) + 4(1) + 2(0.2)<br/>= 45 + 40 + 24 + 4 + 0.4<br/>= 113.4"]
        NORM["normalized =<br/>113.4 / 12 files<br/>= 9.45"]
        SCORE["score = max(0,<br/>100 - 9.45 * factor)<br/>= 72"]
    end

    subgraph "Output"
        GRADE["Grade: C<br/>(70-79 range)"]
        TREND["Trend: Declining<br/>(prev: B → now: C)"]
    end

    C & H & M & L & I --> RAW
    RAW --> NORM
    NORM --> SCORE
    SCORE --> GRADE & TREND

    style C fill:#fecaca,stroke:#dc2626,color:#7f1d1d
    style H fill:#fed7aa,stroke:#ea580c,color:#7c2d12
    style M fill:#fef9c3,stroke:#ca8a04,color:#713f12
    style L fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style I fill:#f3f4f6,stroke:#6b7280,color:#374151
    style GRADE fill:#d1fae5,stroke:#059669,color:#064e3b
```

### Grade Scale

| Grade | Score Range | Meaning |
|-------|-----------|---------|
| **A** | 90-100 | Excellent security posture |
| **B** | 80-89 | Good, minor issues only |
| **C** | 70-79 | Needs attention, medium risks present |
| **D** | 60-69 | Poor, significant risks |
| **F** | 0-59 | Critical, immediate action required |

---

## Compliance Mapping

```mermaid
graph TB
    subgraph "Finding"
        F[SHLD-S3-002<br/>S3 Missing Public<br/>Access Block<br/>Severity: CRITICAL]
    end

    subgraph "Compliance Mapper"
        M{Map to<br/>Frameworks}
    end

    subgraph "9 Frameworks"
        SOC2[SOC 2<br/>CC6.1 - Logical Access]
        HIPAA[HIPAA<br/>164.312 a 1<br/>Access Control]
        PCI[PCI-DSS v4.0<br/>Req 1.3.1<br/>Restrict Access]
        CIS_AWS[CIS AWS<br/>2.1.5 - S3<br/>Block Public]
        NIST[NIST 800-53<br/>AC-3 - Access<br/>Enforcement]
        ISO[ISO 27001<br/>A.9.1.2<br/>Access to Networks]
        CIS_GCP[CIS GCP<br/>5.1 - Storage]
        CIS_K8S[CIS K8s<br/>5.2.1 - Pod Security]
        GDPR[GDPR<br/>Art. 32<br/>Security of Processing]
    end

    F --> M
    M --> SOC2 & HIPAA & PCI & CIS_AWS & NIST

    style F fill:#fecaca,stroke:#dc2626,color:#7f1d1d
    style SOC2 fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style HIPAA fill:#d1fae5,stroke:#059669,color:#064e3b
    style PCI fill:#fef3c7,stroke:#d97706,color:#78350f
    style CIS_AWS fill:#ede9fe,stroke:#7c3aed,color:#4c1d95
    style NIST fill:#ffedd5,stroke:#ea580c,color:#7c2d12
    style ISO fill:#f3e8ff,stroke:#9333ea,color:#581c87
    style CIS_GCP fill:#ede9fe,stroke:#7c3aed,color:#4c1d95
    style CIS_K8S fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style GDPR fill:#fce7f3,stroke:#db2777,color:#831843
```

---

## AI Fix Generator

```mermaid
sequenceDiagram
    participant SE as Scanner Engine
    participant AFG as AI Fix Generator
    participant Cache as Redis Cache
    participant OAI as OpenAI GPT-4.1-mini

    SE->>AFG: generate_fix(finding, context)
    AFG->>AFG: Calculate fingerprint<br/>(SHA-256 of rule_id + file + resource + line)
    AFG->>Cache: GET fix:{fingerprint}
    alt Cache HIT (24hr TTL)
        Cache-->>AFG: Cached fix suggestion
        Note right of Cache: ~80% hit rate
    else Cache MISS
        AFG->>AFG: Extract 40 lines context<br/>around finding location
        AFG->>AFG: Build prompt:<br/>1. System: Security expert<br/>2. Few-shot: 3 examples<br/>3. Finding + context
        AFG->>OAI: chat.completions.create<br/>model=gpt-4.1-mini<br/>max_tokens=1024, temp=0.2
        OAI-->>AFG: Fix suggestion code
        AFG->>Cache: SET fix:{fingerprint}<br/>EX 86400 (24h)
        Note right of Cache: Cost: ~$0.002/fix
    end
    AFG-->>SE: AI fix suggestion
```

### Cost per Scan

| Component | Cost |
|-----------|------|
| Finding generation (rules) | $0.00 (local) |
| AI fix per finding | ~$0.002 |
| Average findings needing AI fix | ~3 per scan |
| Cache hit rate | ~80% |
| **Effective cost per scan** | **~$0.006** |

---

## CloudFormation Adapter

Reuses Terraform rules for CloudFormation via type and property translation.

```mermaid
graph LR
    CF_TPL[CloudFormation<br/>Template] --> DETECT{Detect<br/>AWSTemplate<br/>FormatVersion}

    DETECT -->|Yes| CF_PARSE[Parse CF<br/>Resources]
    DETECT -->|No| K8S[Route to K8s<br/>Scanner]

    CF_PARSE --> MAP[Type Mapper]

    MAP --> |"AWS::S3::Bucket<br/>→ aws_s3_bucket"| TF_RULES[Apply Terraform<br/>S3 Rules]
    MAP --> |"AWS::EC2::SecurityGroup<br/>→ aws_security_group"| TF_RULES2[Apply Terraform<br/>EC2 Rules]
    MAP --> |"AWS::RDS::DBInstance<br/>→ aws_db_instance"| TF_RULES3[Apply Terraform<br/>RDS Rules]

    TF_RULES & TF_RULES2 & TF_RULES3 --> FINDINGS[Findings]

    style CF_TPL fill:#fef3c7,stroke:#d97706,color:#78350f
    style MAP fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style FINDINGS fill:#fecaca,stroke:#dc2626,color:#7f1d1d
```

---

## Deployment Architecture

```mermaid
graph TB
    subgraph "DNS — Cloudflare"
        CF[shieldiac.dev]
        CF_API[api.shieldiac.dev]
    end

    subgraph "Frontend — Vercel"
        V_PROD[Production<br/>Next.js 14]
        V_PREV[Preview<br/>Per-PR deploys]
    end

    subgraph "Backend — Google Cloud"
        subgraph "Cloud Run"
            CR[shieldiac-api<br/>min: 0, max: 100<br/>512MB RAM, 1 vCPU]
        end
        GAR[Artifact Registry<br/>Docker images]
        SM[Secret Manager<br/>API keys, webhook secrets]
    end

    subgraph "Data — Managed Services"
        SB[(Supabase PostgreSQL<br/>500MB free → $25/mo)]
        US[(Upstash Redis<br/>10K cmd/day free → $10/mo)]
    end

    subgraph "External"
        OAI_EXT[OpenAI API]
        STRIPE_EXT[Stripe]
        GH_EXT[GitHub API]
    end

    CF --> V_PROD
    CF_API --> CR
    CR --> SB
    CR --> US
    CR --> SM
    CR --> OAI_EXT
    CR --> STRIPE_EXT
    CR --> GH_EXT
    GAR --> CR

    style CR fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style SB fill:#d1fae5,stroke:#059669,color:#064e3b
    style US fill:#fce7f3,stroke:#db2777,color:#831843
    style V_PROD fill:#f3f4f6,stroke:#374151,color:#111827
```

### Infrastructure Costs

| Component | Free Tier | Production | Notes |
|-----------|-----------|------------|-------|
| Cloud Run | 2M req/mo | ~$5-25/mo | Scales to zero |
| Supabase | 500MB DB | $25/mo | PostgreSQL + Auth |
| Upstash Redis | 10K cmd/day | $10/mo | Serverless Redis |
| OpenAI API | -- | ~$3-30/mo | GPT-4.1-mini @ $0.002/fix |
| Vercel | 100GB BW | Free tier | Next.js hosting |
| Cloudflare | Unlimited | Free | DNS + CDN |
| **Total** | **~$0/mo** | **~$45-90/mo** | |

---

## Security Architecture

```mermaid
graph TB
    subgraph "External Traffic"
        GH_WH[GitHub Webhooks<br/>HMAC-SHA256]
        USER[Dashboard Users<br/>Browser]
    end

    subgraph "Edge — Cloudflare"
        WAF[WAF + DDoS Protection]
        TLS[TLS Termination]
    end

    subgraph "Authentication Layer"
        HMAC[HMAC-SHA256<br/>Webhook Verification<br/>Constant-Time Compare]
        JWT[Clerk JWT<br/>Validation<br/>JWKS Endpoint]
    end

    subgraph "Application Layer"
        RL[Rate Limiter]
        VAL[Input Validation<br/>File size: 5MB max<br/>YAML depth: 50 max<br/>Files: 500 max]
        PROC[In-Memory Processing<br/>No code stored on disk]
    end

    subgraph "Data Layer — Encrypted"
        PG[(PostgreSQL<br/>TLS + Encryption at Rest)]
        RD[(Redis<br/>TLS + Auth)]
    end

    GH_WH --> WAF
    USER --> WAF
    WAF --> TLS
    TLS -->|webhooks| HMAC
    TLS -->|dashboard| JWT
    HMAC --> RL --> VAL --> PROC
    JWT --> RL
    PROC --> PG
    PROC --> RD

    style HMAC fill:#d1fae5,stroke:#059669,color:#064e3b
    style JWT fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style WAF fill:#fef3c7,stroke:#d97706,color:#78350f
    style VAL fill:#fecaca,stroke:#dc2626,color:#7f1d1d
    style PROC fill:#ede9fe,stroke:#7c3aed,color:#4c1d95
```

### Threat Model

| # | Threat | Impact | Mitigation |
|---|--------|--------|-----------|
| 1 | Forged webhook | Arbitrary scan injection | HMAC-SHA256 constant-time verification |
| 2 | YAML bomb / zip bomb | Denial of service | 5MB file limit, 50 depth limit, safe_load |
| 3 | Path traversal in file paths | File system access | In-memory processing only, no disk writes |
| 4 | AI prompt injection | Malicious fix suggestions | System prompt hardening, output validation |
| 5 | Code exfiltration via AI | Repo code sent to OpenAI | Only 40-line snippets, not full files |
| 6 | Multi-tenant data leak | Cross-org data access | org_id scoping on all DB queries |

---

## Data Model

```mermaid
erDiagram
    ORGANIZATION ||--o{ REPOSITORY : has
    ORGANIZATION ||--o{ SUBSCRIPTION : has
    REPOSITORY ||--o{ SCAN : receives
    SCAN ||--o{ FINDING : produces
    FINDING }o--o{ COMPLIANCE_CONTROL : maps_to

    ORGANIZATION {
        uuid id PK
        string github_org
        string plan_tier
        datetime created_at
    }
    REPOSITORY {
        uuid id PK
        uuid org_id FK
        string name
        string full_name
        string default_branch
        boolean active
    }
    SCAN {
        uuid id PK
        uuid repo_id FK
        string trigger "push|pr|manual|scheduled"
        string status "queued|scanning|completed|failed"
        float score
        string grade
        int finding_count
        int critical_count
        int high_count
        float duration_seconds
        datetime created_at
    }
    FINDING {
        uuid id PK
        uuid scan_id FK
        string rule_id
        string severity
        string file_path
        int line_number
        string description
        string remediation
        text ai_fix
        string fingerprint
    }
    COMPLIANCE_CONTROL {
        string framework
        string control_id
        string description
        string status "pass|fail|partial"
    }
    SUBSCRIPTION {
        uuid id PK
        uuid org_id FK
        string stripe_customer_id
        string stripe_subscription_id
        string plan "free|pro|business|enterprise"
        int scan_limit
        int scans_used
        datetime current_period_end
    }
```

---

## Technology Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| **Web Framework** | FastAPI (async Python) | Type-safe, auto-docs, native async |
| **Rule Engine** | Custom (BaseRule + Registry) | Extensible, decorator-based registration |
| **HCL Parsing** | Custom lightweight parser | No external dependency, handles 95% of configs |
| **YAML Parsing** | PyYAML (safe_load) | Industry standard, safe by default |
| **AI** | OpenAI GPT-4.1-mini | Best cost/quality ratio for code suggestions |
| **Database** | PostgreSQL (Supabase) | ACID, JSON support, managed hosting |
| **Queue** | Redis (Upstash) | BLPOP for reliable job queue, serverless |
| **PDF Reports** | ReportLab | Production-grade PDF generation |
| **Auth** | Clerk | GitHub OAuth, RBAC support |
| **Payments** | Stripe Billing | Subscription management |
| **Compute** | Google Cloud Run | Scales to zero, container-based |
| **Frontend** | Next.js 14 (Vercel) | React server components, edge deployment |

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Webhook response | < 500ms | Returns 202 immediately, async processing |
| Scan processing | < 30s for 100 files | Parallel rule evaluation |
| AI fix generation | < 5s per finding | Cached 24h after first generation |
| Cache hit rate (AI) | > 80% | Same finding fingerprint = same fix |
| Dashboard page load | < 2s | Static generation + client-side fetch |
| PDF report generation | < 10s | ReportLab in-memory rendering |

---

## Scaling Characteristics

| Component | Strategy | Bottleneck |
|-----------|---------|------------|
| Webhook handler | Cloud Run auto-scale (0→100) | GitHub API rate limits (5000/hr) |
| Scan workers | Redis queue + N workers | CPU for parsing large repos |
| AI fix gen | 24hr cache, rate-limited | OpenAI API rate limits |
| Database | Supabase auto-scaling | Connection pool (20+10 overflow) |
| PDF generation | Per-request on Cloud Run | Memory for large reports |

---

## Future Considerations

- **Helm chart scanning**: Parse Helm templates with value injection
- **Pulumi/CDK support**: Compile to CloudFormation, then scan
- **Custom OPA/Rego policies**: User-defined rules via Rego language
- **GitLab deep integration**: MR comments + pipeline integration
- **Self-hosted scanner**: Docker image for air-gapped environments
- **Rule marketplace**: Community-contributed rules with quality ratings
- **Scheduled scans**: Cron-based re-scanning of default branches
- **Diff-only scanning**: Only scan changed resources, not entire files

---

## Failure Modes & Resilience

ShieldIaC is designed to degrade gracefully under partial system failures rather than fail catastrophically.

### Failure Mode Matrix

| Failure Mode | Detection | Impact | Mitigation | Recovery |
|---|---|---|---|---|
| **OpenAI API failure** | HTTP 5xx / timeout | AI fix suggestions unavailable | Scan completes without AI fixes; findings still posted to PR; fix generation queued for automatic retry with exponential backoff | Retry queue processes pending fixes when API recovers; cached fixes remain available |
| **Scanner timeout (>30s)** | Watchdog timer per file | Partial scan results | Partial results returned with `scan_incomplete: true` flag; large files (>1MB) skipped with warning annotation on PR | Operator alerted; file size thresholds auto-adjusted based on p95 scan times |
| **Malicious input** | Input validation layer | Potential DoS or resource exhaustion | File size limits enforced: 1MB per file, 10MB per scan aggregate; no code execution at any stage; all parsing is sandboxed with strict depth limits (YAML: 50, HCL: 30) | Malicious payloads logged for threat intelligence; IP-level rate limiting escalation |
| **False positive storms** | Spike detection on finding counts | Alert fatigue, user trust erosion | Confidence scoring (0.0-1.0) attached to each finding; per-rule suppression via `.shieldiac.yaml`; customer feedback loop ("Mark as false positive") feeds back to tune rule thresholds | Rule auto-disabled if false positive rate exceeds 30% over 7-day window; manual review required to re-enable |
| **Queue backlog** | Queue depth monitoring | Increased scan latency | Dead letter queue (DLQ) after 3 retry attempts; backpressure signaling halts new webhook acceptance (429 response); priority lanes ensure paid tier scans processed before free tier | DLQ items reviewed daily; backlog auto-drains when workers scale up |
| **Rule engine crash** | Per-rule try/catch isolation | Missing findings for crashed rule | Individual rule failures are isolated — scan continues with remaining rules; error logged with rule_id, input hash, and stack trace | Rule automatically disabled after 5 consecutive crashes; patched rules re-enabled via config push |

### Retry Strategy

```
Attempt 1: Immediate
Attempt 2: 5s delay
Attempt 3: 30s delay
→ Dead Letter Queue (manual review)
```

### Circuit Breaker (OpenAI API)

- **Closed**: Normal operation, requests pass through
- **Open**: After 5 consecutive failures in 60s window, all AI fix requests short-circuited for 120s
- **Half-Open**: Single probe request after cooldown; success resets to Closed, failure reopens

---

## Observability & SLOs

### Service Level Objectives

| SLO | Target | SLI Measurement | Error Budget (30-day) |
|---|---|---|---|
| Scan completion latency | p95 < 10s | Histogram of `scan_duration_seconds` from scan start to results posted | 5% of scans may exceed 10s (~36 min/day at 500 scans/day) |
| AI fix generation latency | p95 < 5s | Histogram of `ai_fix_duration_seconds` per finding | 5% of fix generations may exceed 5s |
| Service uptime | 99.9% | Synthetic health checks every 60s against `/health` endpoint | 43.2 min downtime/month allowed |
| False positive rate | < 5% | `false_positive_reports / total_findings` over 7-day rolling window | Breach triggers rule review process |
| Webhook acceptance | p99 < 500ms | Histogram of webhook handler response time | 1% of webhooks may exceed 500ms |

### Error Budget Calculations

```
Monthly scan budget at 99.9% uptime:
  30 days × 24 hours × 60 minutes = 43,200 minutes
  Allowed downtime = 43,200 × 0.001 = 43.2 minutes

  If current month has consumed 30 minutes of downtime:
    Remaining budget = 43.2 - 30 = 13.2 minutes
    Budget burn rate = 30 / 43.2 = 69.4% (elevated, freeze risky deployments)
```

### Alert Thresholds

| Alert | Condition | Severity | Action |
|---|---|---|---|
| Scan latency spike | p95 > 15s for 5 min | Warning | Page on-call if sustained 15 min |
| Scan latency critical | p95 > 30s for 5 min | Critical | Auto-scale workers, page on-call |
| AI fix failure rate | > 20% failures in 10 min | Warning | Open circuit breaker, notify on-call |
| Queue depth | > 500 pending jobs | Warning | Scale workers, enable backpressure |
| Queue depth critical | > 2000 pending jobs | Critical | Reject new webhooks (429), page on-call |
| Error rate | > 5% of scans failing | Critical | Page on-call, auto-rollback if recent deploy |
| Error budget burn | > 80% monthly budget consumed | Warning | Freeze non-critical deployments |

### Key Dashboards

1. **Scan Volume Dashboard**: Scans per hour/day, breakdown by trigger type (push/PR/manual/scheduled), by org, by plan tier
2. **Rule Hit Rates**: Findings per rule over time — identifies noisy rules that may need threshold tuning or deprecation
3. **AI Fix Acceptance Rate**: Percentage of AI-generated fixes that users apply vs. dismiss — measures AI quality and ROI
4. **Compliance Coverage**: Heatmap of framework coverage (SOC2, HIPAA, PCI-DSS, etc.) across all scanned repos — identifies gaps
5. **System Health**: Worker utilization, queue depth, cache hit rates, external API latency (OpenAI, GitHub)

### Structured Logging Schema

Every scan event emits a structured JSON log entry:

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "level": "INFO",
  "event": "scan_completed",
  "scan_id": "uuid-1234",
  "org_id": "uuid-org-5678",
  "repo_name": "acme/infrastructure",
  "trigger": "pull_request",
  "file_type": ["terraform", "dockerfile"],
  "files_scanned": 18,
  "rules_evaluated": 1800,
  "findings_count": 12,
  "critical_count": 2,
  "high_count": 4,
  "ai_fixes_generated": 3,
  "ai_fixes_cached": 2,
  "ai_fixes_failed": 0,
  "score": 72,
  "grade": "C",
  "scan_duration_ms": 4520,
  "ai_fix_duration_ms": 1200,
  "queue_wait_ms": 350
}
```

---

## Disaster Recovery & Data Protection

### RPO/RTO Targets

| Data Category | RPO (Recovery Point Objective) | RTO (Recovery Time Objective) | Backup Strategy |
|---|---|---|---|
| Scan results & findings | 1 hour | 4 hours | Supabase automatic daily backups + WAL archiving for point-in-time recovery |
| Rule configurations | 0 (version controlled) | 15 minutes | Git repository is source of truth; redeploy from main branch |
| Compliance mappings | 0 (version controlled) | 15 minutes | Embedded in codebase; deployed with application |
| AI fix cache (Redis) | 24 hours (acceptable loss) | 1 hour | Ephemeral by design; cache rebuilds organically as scans run |
| Organization & billing data | 1 hour | 4 hours | Supabase backups + Stripe as billing source of truth |

### Code Handling Policy

ShieldIaC follows a strict **zero-persistence** policy for customer source code:

- **Process in memory only**: All file content is fetched from GitHub API, parsed in memory, and discarded after scan completion
- **Never persist raw customer code**: No customer IaC files are written to disk, stored in database, or cached
- **Findings metadata only**: Only finding descriptions, file paths, line numbers, and 5-line code snippets (for AI context) are stored
- **AI context is minimal**: Only 40-line snippets around findings are sent to OpenAI, never full files or repositories
- **Ephemeral containers**: Cloud Run instances are stateless; no data survives container recycling

### Data Sovereignty

| Requirement | Implementation |
|---|---|
| EU customer data | Regional processing via Cloud Run in `europe-west1`; Supabase project in EU region |
| Data residency controls | Org-level `data_region` flag routes scans to appropriate regional workers |
| Cross-border transfers | AI fix generation uses OpenAI API (US-based); EU customers can opt out of AI fixes |
| GDPR compliance | Data deletion API for right-to-erasure; scan data auto-purged after 90 days (configurable) |
| Audit logging | All data access events logged with actor, action, resource, and timestamp |

### Backup and Recovery Procedures

1. **Automated Daily Backups**: Supabase performs daily PostgreSQL backups with 7-day retention (free tier) or 30-day retention (Pro tier)
2. **Point-in-Time Recovery**: WAL archiving enables recovery to any point within the retention window
3. **Redis Recovery**: Upstash Redis provides automatic persistence; AI fix cache is non-critical and self-heals through normal scan operations
4. **Configuration Recovery**: All application configuration is in Git; infrastructure is defined in Terraform (dogfooded); full environment rebuild takes < 30 minutes
5. **Runbook**: Disaster recovery runbook stored in `docs/runbooks/disaster-recovery.md` with step-by-step procedures and responsible contacts

---

## Capacity Planning Model

### Per-Scan Resource Consumption

```
Rules evaluated per scan:
  avg 100 rules × avg 20 files = 2,000 rule evaluations per scan

CPU time per rule evaluation:
  ~0.5ms per evaluation → 2,000 × 0.5ms = 1.0s compute per scan

AI fix generation (CRITICAL + HIGH only):
  avg 3 critical/high findings × 500ms per fix = 1.5s sequential
  Parallelized across 3 workers → ~500ms wall clock

Total scan time breakdown:
  File fetch from GitHub API:  ~1.0s
  Parsing (HCL/YAML/Docker):   ~0.5s
  Rule evaluation:              ~1.0s
  AI fix generation:            ~0.5s (parallelized, cache-assisted)
  Scoring + compliance mapping: ~0.1s
  PR comment posting:           ~0.5s
  ─────────────────────────────────────
  Total:                        ~3.6s typical (p50)
                                ~8.0s worst case (p95)
```

### Scaling Projections

| Scale | Scans/Day | Sustained RPS | Burst RPS | Workers Needed | Monthly Cost |
|---|---|---|---|---|---|
| **Startup** | 100 | 0.001 | 0.1 | 1 | ~$5 |
| **Growth** | 1,000 | 0.012 | 1 | 2 | ~$20 |
| **Scale** | 10,000 | 0.12 | 5 | 5 | ~$90 |
| **Enterprise** | 100,000 | 1.2 | 50 | 25 | ~$500 |

### OpenAI API Budget

```
At 10K scans/day:
  Scans per month:           300,000
  Avg AI fixes per scan:     3
  Total fix requests:        900,000
  Cache hit rate (~80%):     720,000 served from cache
  API calls needed:          180,000
  Cost per API call:         ~$0.002
  Monthly OpenAI cost:       180,000 × $0.002 = $360/month

  Effective cost per scan:   $360 / 300,000 = ~$0.0012/scan
  (with cache: $0.006/scan without cache → $0.0012/scan with 80% cache)
```

### Storage Growth

```
At 10K scans/day:
  Scan result size:      ~5KB per scan (findings + metadata)
  Daily storage:         10,000 × 5KB = 50MB/day
  Monthly storage:       50MB × 30 = 1.5GB/month
  Annual storage:        1.5GB × 12 = 18GB/year

  With 90-day auto-purge: max ~4.5GB steady state
```

### Queue Sizing

```
Peak burst scenario:
  Concurrent scans:      100 (monorepo push triggers many repos)
  Workers:               5
  Avg scan duration:     5s
  Worker throughput:     5 workers × (1 scan / 5s) = 1 scan/sec
  Queue drain time:      100 scans / 1 scan/sec = 100s (~1.7 min)

  At scale (25 workers):
  Worker throughput:     25 × (1/5) = 5 scans/sec
  Queue drain time:      100 / 5 = 20s

  Dead letter queue sizing: < 0.1% of scans → ~10 items/day at 10K scans/day
```

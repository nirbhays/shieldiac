-- =============================================================================
-- ShieldIaC — Complete Database Schema
-- PostgreSQL 16+ (Supabase-compatible)
-- =============================================================================

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- Organizations & Users
-- =============================================================================

CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(255) UNIQUE NOT NULL,
    clerk_org_id    VARCHAR(255) UNIQUE,
    plan            VARCHAR(50) NOT NULL DEFAULT 'free',
    stripe_customer_id VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           VARCHAR(255) UNIQUE NOT NULL,
    name            VARCHAR(255),
    avatar_url      TEXT,
    clerk_user_id   VARCHAR(255) UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE org_memberships (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            VARCHAR(50) NOT NULL DEFAULT 'member', -- owner, admin, member
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, user_id)
);

-- =============================================================================
-- Repositories
-- =============================================================================

CREATE TABLE repositories (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    full_name       VARCHAR(500) NOT NULL, -- owner/repo
    url             TEXT NOT NULL,
    clone_url       TEXT NOT NULL,
    provider        VARCHAR(50) NOT NULL DEFAULT 'github', -- github, gitlab
    default_branch  VARCHAR(255) NOT NULL DEFAULT 'main',
    is_private      BOOLEAN NOT NULL DEFAULT false,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    security_score  DECIMAL(5,2) DEFAULT 100.00,
    grade           CHAR(1) DEFAULT 'A',
    last_scan_at    TIMESTAMPTZ,
    installation_id VARCHAR(255), -- GitHub App installation ID
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, full_name)
);

CREATE INDEX idx_repos_org ON repositories(org_id);
CREATE INDEX idx_repos_provider ON repositories(provider);
CREATE INDEX idx_repos_score ON repositories(security_score);

-- =============================================================================
-- Scans
-- =============================================================================

CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repo_id         UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id),
    branch          VARCHAR(255) NOT NULL,
    commit_sha      VARCHAR(64),
    pr_number       INTEGER,
    status          VARCHAR(50) NOT NULL DEFAULT 'queued', -- queued, in_progress, completed, failed, cancelled
    trigger_type    VARCHAR(50) NOT NULL DEFAULT 'manual', -- webhook, manual, schedule, api
    scan_type       VARCHAR(50) NOT NULL DEFAULT 'full',   -- full, incremental, pull_request
    -- Summary
    total_files     INTEGER DEFAULT 0,
    total_findings  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    info_count      INTEGER DEFAULT 0,
    security_score  DECIMAL(5,2) DEFAULT 100.00,
    grade           CHAR(1) DEFAULT 'A',
    duration_ms     INTEGER,
    error_message   TEXT,
    -- Timestamps
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_repo ON scans(repo_id);
CREATE INDEX idx_scans_org ON scans(org_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
CREATE INDEX idx_scans_pr ON scans(repo_id, pr_number) WHERE pr_number IS NOT NULL;

-- =============================================================================
-- Findings
-- =============================================================================

CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repo_id         UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    rule_id         VARCHAR(100) NOT NULL,
    severity        VARCHAR(20) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    resource_type   VARCHAR(50) NOT NULL, -- terraform, kubernetes, dockerfile, cloudformation
    resource_name   VARCHAR(500) NOT NULL,
    file_path       TEXT NOT NULL,
    line_number     INTEGER DEFAULT 0,
    description     TEXT NOT NULL,
    remediation     TEXT NOT NULL,
    ai_fix          TEXT,
    code_snippet    TEXT,
    fingerprint     VARCHAR(64) NOT NULL, -- For dedup across scans
    -- Status
    status          VARCHAR(50) NOT NULL DEFAULT 'open', -- open, resolved, suppressed, false_positive
    resolved_at     TIMESTAMPTZ,
    resolved_by     UUID REFERENCES users(id),
    -- Timestamps
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_repo ON findings(repo_id);
CREATE INDEX idx_findings_rule ON findings(rule_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_file ON findings(file_path);

-- =============================================================================
-- Built-in Rules Registry (stored in DB for UI management)
-- =============================================================================

CREATE TABLE rules (
    id              VARCHAR(100) PRIMARY KEY,
    description     TEXT NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    resource_type   VARCHAR(50) NOT NULL,
    remediation     TEXT NOT NULL,
    tags            JSONB DEFAULT '[]'::jsonb,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    is_builtin      BOOLEAN NOT NULL DEFAULT true,
    -- Custom rules (OPA/Rego)
    rego_policy     TEXT,
    -- Metadata
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rules_resource ON rules(resource_type);
CREATE INDEX idx_rules_severity ON rules(severity);
CREATE INDEX idx_rules_enabled ON rules(enabled);

-- =============================================================================
-- Compliance Mappings
-- =============================================================================

CREATE TABLE compliance_mappings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id         VARCHAR(100) NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    framework       VARCHAR(50) NOT NULL, -- SOC2, HIPAA, PCI-DSS, CIS-AWS, CIS-GCP, CIS-K8S
    control_id      VARCHAR(100) NOT NULL,
    control_desc    TEXT DEFAULT '',
    UNIQUE(rule_id, framework, control_id)
);

CREATE INDEX idx_compliance_rule ON compliance_mappings(rule_id);
CREATE INDEX idx_compliance_framework ON compliance_mappings(framework);

-- =============================================================================
-- Compliance Reports (generated)
-- =============================================================================

CREATE TABLE compliance_reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repo_id         UUID REFERENCES repositories(id),
    scan_id         UUID REFERENCES scans(id),
    framework       VARCHAR(50) NOT NULL,
    total_controls  INTEGER DEFAULT 0,
    passing         INTEGER DEFAULT 0,
    failing         INTEGER DEFAULT 0,
    compliance_pct  DECIMAL(5,2) DEFAULT 0.00,
    report_data     JSONB DEFAULT '{}'::jsonb,
    pdf_path        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_reports_org ON compliance_reports(org_id);
CREATE INDEX idx_compliance_reports_repo ON compliance_reports(repo_id);

-- =============================================================================
-- Subscriptions & Billing
-- =============================================================================

CREATE TABLE subscriptions (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id                  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stripe_subscription_id  VARCHAR(255) UNIQUE,
    stripe_customer_id      VARCHAR(255),
    plan                    VARCHAR(50) NOT NULL DEFAULT 'free',
    status                  VARCHAR(50) NOT NULL DEFAULT 'active', -- active, canceled, past_due, trialing
    current_period_start    TIMESTAMPTZ,
    current_period_end      TIMESTAMPTZ,
    cancel_at_period_end    BOOLEAN DEFAULT false,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_subscriptions_org ON subscriptions(org_id);

-- =============================================================================
-- Usage Tracking
-- =============================================================================

CREATE TABLE usage_records (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    period_start    DATE NOT NULL,
    period_end      DATE NOT NULL,
    scans_count     INTEGER DEFAULT 0,
    repos_count     INTEGER DEFAULT 0,
    findings_count  INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, period_start)
);

-- =============================================================================
-- Audit Log
-- =============================================================================

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID REFERENCES organizations(id),
    user_id         UUID REFERENCES users(id),
    action          VARCHAR(255) NOT NULL,
    resource_type   VARCHAR(100),
    resource_id     VARCHAR(255),
    details         JSONB DEFAULT '{}'::jsonb,
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_org ON audit_log(org_id);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);

-- =============================================================================
-- Updated-at trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_repositories_updated_at BEFORE UPDATE ON repositories FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_rules_updated_at BEFORE UPDATE ON rules FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_subscriptions_updated_at BEFORE UPDATE ON subscriptions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

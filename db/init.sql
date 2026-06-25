-- ShakerScan - PostgreSQL Schema
-- Open Source Edition (no auth, single-user)

CREATE TABLE app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- TARGETS - Assets to scan
-- ============================================================
CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Target identification
    url TEXT UNIQUE NOT NULL,
    -- Scheme/trailing-slash-insensitive canonical origin (auto-maintained by the
    -- trg_targets_canonical_key trigger below); UNIQUE so duplicate origins can't form.
    canonical_key TEXT,
    name TEXT,
    root_domain TEXT,
    is_root BOOLEAN DEFAULT false,  -- true for root domains, false for subdomains

    -- Discovery metadata
    discovery_source TEXT DEFAULT 'manual',  -- manual, subfinder, gungnir-monitor, import, model-intake
    parent_target_id UUID REFERENCES targets(id) ON DELETE SET NULL,

    -- Scan configuration
    is_active BOOLEAN DEFAULT true,
    scan_options JSONB DEFAULT '{}',

    -- Ownership/accountability metadata for the exposure inventory
    -- (owner, environment, risk_tier, data_classification), mirroring
    -- ai_targets.metadata_json
    metadata_json JSONB NOT NULL DEFAULT '{}',

    -- Continuous ASM policy (docs §16 Phase 3/4): the background dispatcher
    -- auto-drains/refreshes this target's endpoint inventory when enabled.
    asm_enabled BOOLEAN NOT NULL DEFAULT false,
    asm_config JSONB NOT NULL DEFAULT '{}',   -- batch_size, stale_days, intervals, caps, time windows
    asm_last_test_at TIMESTAMPTZ,
    asm_last_recon_at TIMESTAMPTZ,

    -- Statistics (updated after each scan)
    last_scan_id UUID,
    last_scanned_at TIMESTAMPTZ,
    last_score INTEGER,
    last_grade TEXT,
    total_scans INTEGER DEFAULT 0,
    active_findings_count INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Canonical de-dupe: keep canonical_key in sync with url (must match the Python
-- _canonical_target_key in api.py), and forbid two rows sharing a canonical origin.
CREATE OR REPLACE FUNCTION targets_set_canonical_key() RETURNS trigger AS $$
BEGIN
    NEW.canonical_key := rtrim(
        regexp_replace(lower(btrim(COALESCE(NEW.url, ''))), '^https?://', ''), '/');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_targets_canonical_key
    BEFORE INSERT OR UPDATE OF url ON targets
    FOR EACH ROW EXECUTE FUNCTION targets_set_canonical_key();
CREATE UNIQUE INDEX idx_targets_canonical_key ON targets(canonical_key);

-- ============================================================
-- SCANS - Individual scan runs
-- ============================================================
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Target reference
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,

    -- Job tracking
    job_id TEXT UNIQUE,
    worker_id TEXT,

    -- Status
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, running, completed, failed
    progress INTEGER DEFAULT 0,  -- 0-100
    current_phase TEXT,  -- dns, tls, http, discovery, active, ai

    -- Scan configuration
    options JSONB DEFAULT '{}',
    scan_type TEXT DEFAULT 'quick',  -- quick, standard, thorough, full
    run_kind TEXT NOT NULL DEFAULT 'web_dast',  -- web_dast, ai_api, ai_widget, ai_rag, ai_trace, ai_mcp, model_intake
    subject_ref TEXT,

    -- Results
    result JSONB,
    score INTEGER,
    grade TEXT,
    findings_count INTEGER DEFAULT 0,

    -- Delta (change detection)
    baseline_scan_id UUID REFERENCES scans(id),
    delta JSONB,

    -- Timing
    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,

    -- Error handling
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,

    -- Parallel scan orchestration (parent/shard/merge fan-out)
    parent_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    scan_role TEXT NOT NULL DEFAULT 'standalone',  -- standalone, parent, shard
    shard_index INTEGER,
    shard_count INTEGER
);

-- ============================================================
-- AI TARGETS - Chat/RAG/agent/MCP surfaces for AI Gate scans
-- ============================================================
CREATE TABLE ai_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'api_chat',
    endpoint_url TEXT UNIQUE NOT NULL,
    method TEXT NOT NULL DEFAULT 'POST',
    headers_template JSONB NOT NULL DEFAULT '{}',
    request_template JSONB NOT NULL DEFAULT '{}',
    response_path TEXT,
    streaming_mode TEXT NOT NULL DEFAULT 'json',
    rate_limit_rps INTEGER,
    token_budget INTEGER,
    request_budget INTEGER,
    production_mode BOOLEAN DEFAULT false,

    last_scanned_at TIMESTAMPTZ,
    last_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT ai_targets_target_type_check
        CHECK (target_type IN ('api_chat', 'widget', 'rag', 'agent_trace', 'mcp_trace')),
    CONSTRAINT ai_targets_method_check
        CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH')),
    CONSTRAINT ai_targets_streaming_mode_check
        CHECK (streaming_mode IN ('json', 'sse'))
);

CREATE TABLE ai_target_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ai_target_id UUID UNIQUE NOT NULL REFERENCES ai_targets(id) ON DELETE CASCADE,
    auth_kind TEXT NOT NULL DEFAULT 'none',
    header_name TEXT,
    secret_value TEXT,
    secret_preview TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,

    CONSTRAINT ai_target_credentials_auth_kind_check
        CHECK (auth_kind IN (
            'none', 'bearer', 'api_key_header', 'custom_header',
            'basic_auth', 'cookie', 'multi_header', 'query_param'
        ))
);

ALTER TABLE scans
ADD COLUMN ai_target_id UUID REFERENCES ai_targets(id) ON DELETE SET NULL;

-- ============================================================
-- FINDINGS - Vulnerabilities discovered
-- ============================================================
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    ai_target_id UUID REFERENCES ai_targets(id) ON DELETE CASCADE,

    -- Finding identification (for deduplication)
    fingerprint TEXT NOT NULL,

    -- Core details
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,  -- critical, high, medium, low, info
    cvss_score NUMERIC(3,1),

    -- Classification
    tool TEXT,
    cwe TEXT,
    cwe_name TEXT,
    owasp TEXT,

    -- Evidence
    url TEXT,
    evidence JSONB,
    request TEXT,
    response TEXT,

    -- Tracking status
    status TEXT DEFAULT 'active',  -- active, resolved, false_positive, accepted_risk
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resurfaced_count INTEGER DEFAULT 0,

    -- AI analysis (optional)
    ai_verdict TEXT,  -- true_positive, false_positive, needs_review
    ai_confidence NUMERIC(3,2),
    ai_rationale TEXT,
    ai_recommendations JSONB,

    -- Notes
    notes TEXT,

    -- Verification summary (latest retest state)
    last_verification_status TEXT,  -- queued, running, still_vulnerable, likely_fixed, inconclusive, error
    last_verification_verdict TEXT,  -- exploited, blocked_by_security, out_of_scope_internal, false_positive, likely_fixed, inconclusive, error
    last_verification_confidence NUMERIC(3,2),
    last_verified_at TIMESTAMPTZ,
    verification_count INTEGER DEFAULT 0,

    -- Source tracking
    source TEXT DEFAULT 'scan',  -- scan, manual, ai_session, ai_gate
    session_id TEXT,  -- For AI session findings

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- EVIDENCE OBJECTS - First-class durable evidence (hash, redaction
-- profile, retention class, storage URI, scan/finding links)
-- ============================================================
CREATE TABLE evidence_objects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    object_type TEXT NOT NULL DEFAULT 'finding_evidence',
    content_sha256 TEXT,
    size_bytes INTEGER,
    storage_uri TEXT,
    redaction_profile TEXT,
    retention_class TEXT NOT NULL DEFAULT 'standard',
    content JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT evidence_objects_finding_type_unique UNIQUE (finding_id, object_type)
);
CREATE INDEX idx_evidence_objects_finding ON evidence_objects(finding_id);
CREATE INDEX idx_evidence_objects_scan ON evidence_objects(scan_id);

-- ============================================================
-- APPLICATION GRAPH - First-class per-target graph of routes,
-- objects, producer/consumer links, auth boundaries, sensitive
-- fields (persisted from the BOLA resource_map + discovery)
-- ============================================================
CREATE TABLE application_graph_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    node_type TEXT NOT NULL,        -- route | object | principal
    node_key TEXT NOT NULL,         -- canonical, type-prefixed id
    label TEXT,
    attributes JSONB,
    scan_id UUID,
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT app_graph_node_unique UNIQUE (target_id, node_type, node_key)
);
CREATE TABLE application_graph_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    src_key TEXT NOT NULL,
    dst_key TEXT NOT NULL,
    edge_type TEXT NOT NULL,        -- produces | consumed_by | auth_boundary
    attributes JSONB,
    scan_id UUID,
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT app_graph_edge_unique UNIQUE (target_id, src_key, dst_key, edge_type)
);
CREATE INDEX idx_app_graph_nodes_target ON application_graph_nodes(target_id);
CREATE INDEX idx_app_graph_edges_target ON application_graph_edges(target_id);

-- ============================================================
-- FINDING VERIFICATIONS - Retest attempts and proof history
-- ============================================================
CREATE TABLE finding_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,

    -- Job metadata
    job_id TEXT,
    requested_by TEXT DEFAULT 'api',
    status TEXT NOT NULL DEFAULT 'queued',  -- queued, running, completed, failed
    result_status TEXT,  -- still_vulnerable, likely_fixed, inconclusive, error
    verdict TEXT,  -- exploited, blocked_by_security, out_of_scope_internal, false_positive, likely_fixed, inconclusive, error
    verdict_reason TEXT,

    -- Retest inputs
    finding_type TEXT NOT NULL,  -- xss, sqli, ssrf, path_traversal, open_redirect, cors
    target_url TEXT NOT NULL,
    original_url TEXT,
    param TEXT,
    payload TEXT,
    method TEXT,
    request_body TEXT,
    replay_commands JSONB,

    -- Auth context (forwarded from original scan for authenticated retests)
    auth_context JSONB,

    -- Retest outputs
    proof JSONB,
    artifacts JSONB,
    confidence NUMERIC(3,2),
    attempt_count INTEGER DEFAULT 0,
    attempts_exhausted BOOLEAN DEFAULT FALSE,
    retry_class TEXT,
    retryable BOOLEAN DEFAULT FALSE,
    message TEXT,
    error_message TEXT,

    -- AI verification (opt-in)
    verification_mode TEXT DEFAULT 'deterministic',  -- deterministic, ai_driven
    ai_plan JSONB,         -- LLM's exploitation plan (audit trail)
    ai_reasoning TEXT,     -- LLM's reasoning about exploitability

    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- DISCOVERY RUNS - Subdomain enumeration history
-- ============================================================
CREATE TABLE discovery_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Target
    root_domain TEXT NOT NULL,

    -- Status
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, running, completed, failed

    -- Results
    subdomains_found INTEGER DEFAULT 0,
    new_subdomains INTEGER DEFAULT 0,
    result JSONB,

    -- Sources breakdown
    sources_used JSONB,  -- {"gungnir": 150, "subfinder": 80, "crtsh": 120}

    -- Timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- SCHEDULES - Recurring scans (optional feature)
-- ============================================================
CREATE TABLE schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Target
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    name TEXT,

    -- Schedule configuration
    frequency TEXT NOT NULL,  -- daily, weekly, biweekly, monthly
    day_of_week INTEGER,  -- 0-6 (Sunday-Saturday) for weekly
    time_of_day TEXT DEFAULT '02:00',  -- HH:MM in UTC
    timezone TEXT DEFAULT 'UTC',
    jitter_minutes INTEGER DEFAULT 30,

    -- Scan configuration
    scan_type TEXT DEFAULT 'standard',
    scan_options JSONB DEFAULT '{}',

    -- Status
    is_active BOOLEAN DEFAULT true,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- INDEXES
-- ============================================================

-- Targets
CREATE INDEX idx_targets_root_domain ON targets(root_domain);
CREATE INDEX idx_targets_active ON targets(is_active) WHERE is_active = true;
CREATE INDEX idx_targets_is_root ON targets(is_root) WHERE is_root = true;

-- Scans
CREATE INDEX idx_scans_target_id ON scans(target_id);
CREATE INDEX idx_scans_ai_target_id ON scans(ai_target_id) WHERE ai_target_id IS NOT NULL;
CREATE INDEX idx_scans_run_kind ON scans(run_kind);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
CREATE INDEX idx_scans_job_id ON scans(job_id);
CREATE INDEX idx_scans_parent ON scans(parent_scan_id) WHERE parent_scan_id IS NOT NULL;

-- ============================================================
-- SCAN CAMPAIGNS - Durable budget/allocator records for Full Coverage + ASM
-- ============================================================
CREATE TABLE scan_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    root_domain TEXT,
    requested_by TEXT NOT NULL DEFAULT 'api',
    mode TEXT NOT NULL,                      -- full_coverage|continuous_asm|focused_family|finding_retest|surface_recon
    priority INTEGER NOT NULL DEFAULT 100,
    budget_profile TEXT,
    wide_budget JSONB NOT NULL DEFAULT '{}'::jsonb,
    deep_budget JSONB NOT NULL DEFAULT '{}'::jsonb,
    check_families JSONB NOT NULL DEFAULT '[]'::jsonb,
    auth_states JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_windows JSONB NOT NULL DEFAULT '{}'::jsonb,
    daily_cap INTEGER,
    rate_caps JSONB NOT NULL DEFAULT '{}'::jsonb,
    parent_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    policy_id UUID,
    status TEXT NOT NULL DEFAULT 'active',
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX idx_scan_campaigns_target_status ON scan_campaigns(target_id, status, created_at DESC);
CREATE INDEX idx_scan_campaigns_parent ON scan_campaigns(parent_scan_id) WHERE parent_scan_id IS NOT NULL;

ALTER TABLE scans
ADD COLUMN campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL;

-- finding_verifications is created before scan_campaigns, so its campaign_id
-- (a retest/verification can belong to a campaign) is added here by ALTER.
ALTER TABLE finding_verifications
ADD COLUMN campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL;

-- ============================================================
-- TARGET ENDPOINTS - Continuous ASM attack-surface inventory (docs §16)
-- Recon upserts discovered endpoints; exploitation drains untested/stale ones.
-- ============================================================
CREATE TABLE target_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    method TEXT NOT NULL DEFAULT 'GET',
    path TEXT NOT NULL,
    param_shape TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL,                 -- auth + method + normalized path + param location/names
    source TEXT,                               -- crawl | har | js | ffuf | openapi | manual
    auth_state TEXT NOT NULL DEFAULT 'anonymous',
    param_location TEXT NOT NULL DEFAULT 'query', -- query|form|json|none
    replay_spec TEXT,                          -- scanner custom-endpoint string preserving body/query shape
    content_type TEXT,
    content_hash TEXT,
    priority_score INTEGER NOT NULL DEFAULT 10,
    test_status TEXT NOT NULL DEFAULT 'untested',  -- untested|in_progress|tested|stale|gone
    last_attempt_status TEXT,                  -- leased|completed|partial|auth_missing|failed
    last_verdict TEXT,
    last_finding_id UUID,
    credential_ref TEXT,
    campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL,
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_http_status INTEGER,                  -- HTTP status from last reachability probe
    unreachable_streak INTEGER NOT NULL DEFAULT 0, -- consecutive 404/soft-404 observations; retire to 'gone' at threshold
    last_reachability_at TIMESTAMPTZ,          -- when reachability was last probed
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_tested_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_target_endpoints_fp ON target_endpoints(target_id, fingerprint);
CREATE INDEX idx_target_endpoints_status ON target_endpoints(target_id, test_status, priority_score DESC);
CREATE INDEX idx_target_endpoints_auth_status ON target_endpoints(target_id, auth_state, test_status, priority_score DESC);
CREATE INDEX idx_target_endpoints_lease ON target_endpoints(lease_expires_at) WHERE test_status = 'in_progress';
CREATE INDEX idx_target_endpoints_campaign ON target_endpoints(campaign_id) WHERE campaign_id IS NOT NULL;

CREATE TABLE asm_endpoint_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES target_endpoints(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    parent_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL,
    worker_id TEXT,
    auth_state TEXT NOT NULL DEFAULT 'anonymous',
    check_family TEXT NOT NULL DEFAULT 'all',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL,                      -- completed|partial|timeout|auth_missing|rate_limited|error
    attempted_params_count INTEGER NOT NULL DEFAULT 0,
    completed_params_count INTEGER NOT NULL DEFAULT 0,
    finding_ids UUID[] NOT NULL DEFAULT '{}'::uuid[],
    error_summary TEXT,
    scanner_telemetry_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_asm_endpoint_attempts_endpoint ON asm_endpoint_attempts(endpoint_id, started_at DESC);
CREATE INDEX idx_asm_endpoint_attempts_scan ON asm_endpoint_attempts(scan_id) WHERE scan_id IS NOT NULL;
CREATE INDEX idx_asm_endpoint_attempts_campaign ON asm_endpoint_attempts(campaign_id, status);
CREATE INDEX idx_asm_endpoint_attempts_campaign_family ON asm_endpoint_attempts(campaign_id, check_family, status);

-- AI targets
CREATE INDEX idx_ai_targets_active ON ai_targets(is_active) WHERE is_active = true;
CREATE INDEX idx_ai_targets_created ON ai_targets(created_at DESC);

-- Findings
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_target_id ON findings(target_id);
CREATE INDEX idx_findings_ai_target_id ON findings(ai_target_id) WHERE ai_target_id IS NOT NULL;
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_first_seen ON findings(first_seen_at DESC);
CREATE INDEX idx_findings_last_seen ON findings(last_seen_at DESC NULLS LAST);
CREATE INDEX idx_findings_source ON findings(source);
CREATE INDEX idx_findings_session_id ON findings(session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_findings_last_verified_at ON findings(last_verified_at DESC) WHERE last_verified_at IS NOT NULL;
CREATE INDEX idx_findings_last_verification_verdict ON findings(last_verification_verdict);
-- Dedup hot path: save_findings looks up by (target_id, fingerprint) on every
-- finding write. UNIQUE doubles as the race guard for concurrent save_findings
-- calls that previously could both SELECT-miss and both INSERT.
CREATE UNIQUE INDEX idx_findings_target_fingerprint
    ON findings(target_id, fingerprint)
    WHERE target_id IS NOT NULL;

-- Finding verifications
CREATE INDEX idx_finding_verifications_finding_id ON finding_verifications(finding_id, created_at DESC);
CREATE INDEX idx_finding_verifications_status ON finding_verifications(status);
CREATE INDEX idx_finding_verifications_result_status ON finding_verifications(result_status);
CREATE INDEX idx_finding_verifications_verdict ON finding_verifications(verdict);
CREATE INDEX idx_finding_verifications_job_id ON finding_verifications(job_id) WHERE job_id IS NOT NULL;
CREATE INDEX idx_finding_verifications_retry_class ON finding_verifications(retry_class) WHERE retry_class IS NOT NULL;

-- Discovery
CREATE INDEX idx_discovery_root_domain ON discovery_runs(root_domain);
CREATE INDEX idx_discovery_created ON discovery_runs(created_at DESC);

-- Schedules
CREATE INDEX idx_schedules_next_run ON schedules(next_run_at) WHERE is_active = true;

-- ============================================================
-- VIEWS
-- ============================================================

-- Latest scan per target
CREATE VIEW latest_scans AS
SELECT DISTINCT ON (target_url) *
FROM scans
WHERE status = 'completed'
  AND (scan_role IS NULL OR scan_role <> 'shard')
ORDER BY target_url, completed_at DESC;

-- Active findings summary
CREATE VIEW findings_summary AS
SELECT
    target_id,
    COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'active') as critical_count,
    COUNT(*) FILTER (WHERE severity = 'high' AND status = 'active') as high_count,
    COUNT(*) FILTER (WHERE severity = 'medium' AND status = 'active') as medium_count,
    COUNT(*) FILTER (WHERE severity = 'low' AND status = 'active') as low_count,
    COUNT(*) FILTER (WHERE severity = 'info' AND status = 'active') as info_count,
    COUNT(*) FILTER (WHERE status = 'active') as total_active,
    COUNT(*) FILTER (WHERE status = 'resolved') as total_resolved,
    COUNT(*) FILTER (WHERE status = 'false_positive') as total_false_positive
FROM findings
GROUP BY target_id;

-- Dashboard metrics
CREATE VIEW dashboard_metrics AS
SELECT
    (SELECT COUNT(*) FROM targets WHERE is_active = true) as total_targets,
    (SELECT COUNT(*) FROM scans WHERE status = 'completed' AND (scan_role IS NULL OR scan_role <> 'shard')) as total_scans,
    (SELECT COUNT(*) FROM scans WHERE status = 'running' AND (scan_role IS NULL OR scan_role <> 'shard')) as running_scans,
    (SELECT COUNT(*) FROM findings WHERE status = 'active') as active_findings,
    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND severity = 'critical') as critical_findings,
    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND severity = 'high') as high_findings,
    (SELECT AVG(score) FROM latest_scans) as avg_score;

-- ============================================================
-- FUNCTIONS
-- ============================================================

-- Update target stats after scan completion
CREATE OR REPLACE FUNCTION update_target_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed'
       AND NEW.target_id IS NOT NULL
       AND COALESCE(NEW.scan_role, 'standalone') <> 'shard' THEN
        UPDATE targets SET
            last_scan_id = NEW.id,
            last_scanned_at = NEW.completed_at,
            last_score = NEW.score,
            last_grade = NEW.grade,
            total_scans = total_scans + 1,
            active_findings_count = (
                SELECT COUNT(*) FROM findings
                WHERE target_id = NEW.target_id AND status = 'active'
            ),
            updated_at = NOW()
        WHERE id = NEW.target_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_target_stats
AFTER UPDATE ON scans
FOR EACH ROW
WHEN (NEW.status = 'completed' AND OLD.status != 'completed')
EXECUTE FUNCTION update_target_stats();

-- Update finding timestamps
CREATE OR REPLACE FUNCTION update_finding_timestamps()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    IF NEW.status = 'resolved' AND OLD.status != 'resolved' THEN
        NEW.resolved_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_finding_timestamps
BEFORE UPDATE ON findings
FOR EACH ROW
EXECUTE FUNCTION update_finding_timestamps();

-- R4: durable policy profiles + finding exceptions (also created idempotently in
-- run_schema_migrations for existing installs).
CREATE TABLE IF NOT EXISTS policy_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    product_area TEXT NOT NULL DEFAULT 'ai_gate',
    environment TEXT NOT NULL DEFAULT 'production',
    minimum_block_severity TEXT NOT NULL DEFAULT 'high',
    expires_days INTEGER NOT NULL DEFAULT 30,
    strict_model_intake BOOLEAN NOT NULL DEFAULT false,
    allow_active_exceptions BOOLEAN NOT NULL DEFAULT true,
    owner TEXT,
    version TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    active_from TIMESTAMPTZ,
    active_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS finding_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id TEXT,
    fingerprint TEXT,
    policy_id UUID REFERENCES policy_profiles(id) ON DELETE SET NULL,
    target_id UUID,
    scope TEXT,
    owner TEXT,
    approver TEXT,
    reason TEXT,
    compensating_controls TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT finding_exceptions_status_check
        CHECK (status IN ('active','approved','accepted_risk','revoked','expired'))
);
CREATE INDEX IF NOT EXISTS idx_finding_exceptions_target_status ON finding_exceptions(target_id, status);
CREATE INDEX IF NOT EXISTS idx_finding_exceptions_finding ON finding_exceptions(finding_id);

-- R9: durable AI surface inventory + attempt ledger (also created idempotently in
-- run_schema_migrations for existing installs).
CREATE TABLE IF NOT EXISTS ai_surfaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ai_target_id UUID REFERENCES ai_targets(id) ON DELETE CASCADE,
    surface_type TEXT NOT NULL DEFAULT 'api_chat',
    endpoint_url TEXT,
    auth_kind TEXT,
    owner TEXT,
    environment TEXT,
    risk_tier TEXT,
    data_classification TEXT,
    tools_count INTEGER NOT NULL DEFAULT 0,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_seen TIMESTAMPTZ,
    last_tested TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ai_surfaces_target_unique UNIQUE (ai_target_id)
);

CREATE TABLE IF NOT EXISTS ai_surface_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    surface_id UUID REFERENCES ai_surfaces(id) ON DELETE CASCADE,
    scan_id UUID,
    probe_pack TEXT,
    scan_profile TEXT,
    environment TEXT,
    families TEXT[],
    status TEXT,
    proof_state TEXT,
    findings_count INTEGER NOT NULL DEFAULT 0,
    critical_high_count INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ai_surface_attempts_unique UNIQUE (surface_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_ai_surface_attempts_surface ON ai_surface_attempts(surface_id, completed_at DESC);

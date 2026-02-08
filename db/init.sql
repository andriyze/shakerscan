-- DAST Scanner - PostgreSQL Schema
-- Open Source Edition (no auth, single-user)

-- ============================================================
-- TARGETS - Assets to scan
-- ============================================================
CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Target identification
    url TEXT UNIQUE NOT NULL,
    name TEXT,
    root_domain TEXT,
    is_root BOOLEAN DEFAULT false,  -- true for root domains, false for subdomains

    -- Discovery metadata
    discovery_source TEXT DEFAULT 'manual',  -- manual, subfinder, gungnir-monitor, import
    parent_target_id UUID REFERENCES targets(id) ON DELETE SET NULL,

    -- Scan configuration
    is_active BOOLEAN DEFAULT true,
    scan_options JSONB DEFAULT '{}',

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
    retry_count INTEGER DEFAULT 0
);

-- ============================================================
-- FINDINGS - Vulnerabilities discovered
-- ============================================================
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,

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
    last_verification_confidence NUMERIC(3,2),
    last_verified_at TIMESTAMPTZ,
    verification_count INTEGER DEFAULT 0,

    -- Source tracking
    source TEXT DEFAULT 'scan',  -- scan, manual, ai_session
    session_id TEXT,  -- For AI session findings

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

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

    -- Retest inputs
    finding_type TEXT NOT NULL,  -- xss, sqli, ssrf, path_traversal
    target_url TEXT NOT NULL,
    original_url TEXT,
    param TEXT,
    payload TEXT,
    method TEXT,
    request_body TEXT,

    -- Retest outputs
    proof JSONB,
    confidence NUMERIC(3,2),
    message TEXT,
    error_message TEXT,

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
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
CREATE INDEX idx_scans_job_id ON scans(job_id);

-- Findings
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_target_id ON findings(target_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_first_seen ON findings(first_seen_at DESC);
CREATE INDEX idx_findings_source ON findings(source);
CREATE INDEX idx_findings_session_id ON findings(session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_findings_last_verified_at ON findings(last_verified_at DESC) WHERE last_verified_at IS NOT NULL;

-- Finding verifications
CREATE INDEX idx_finding_verifications_finding_id ON finding_verifications(finding_id, created_at DESC);
CREATE INDEX idx_finding_verifications_status ON finding_verifications(status);
CREATE INDEX idx_finding_verifications_result_status ON finding_verifications(result_status);
CREATE INDEX idx_finding_verifications_job_id ON finding_verifications(job_id) WHERE job_id IS NOT NULL;

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
    (SELECT COUNT(*) FROM scans WHERE status = 'completed') as total_scans,
    (SELECT COUNT(*) FROM scans WHERE status = 'running') as running_scans,
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
    IF NEW.status = 'completed' AND NEW.target_id IS NOT NULL THEN
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

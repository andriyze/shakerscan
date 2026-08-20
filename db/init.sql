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
    -- Host-level identity for web targets and full subject identity for Model Intake
    -- artifacts (auto-maintained by trg_targets_canonical_key below).
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

-- Canonical de-dupe: a web target is the host asset, while a Model Intake target is
-- the exact artifact subject. Concrete web scheme/port origins stay on scans.
CREATE OR REPLACE FUNCTION targets_set_canonical_key() RETURNS trigger AS $$
DECLARE
    raw TEXT;
    authority TEXT;
    host_part TEXT;
BEGIN
    raw := regexp_replace(lower(btrim(COALESCE(NEW.url, ''))), '^https?://', '');
    IF lower(COALESCE(NEW.discovery_source, '')) = 'model-intake' THEN
        NEW.canonical_key := 'artifact:' || rtrim(raw, '/');
    ELSE
        authority := regexp_replace(raw, '[/?#].*$', '');
        authority := regexp_replace(authority, '^.*@', '');
        IF authority ~ '^\[[^]]+\]' THEN
            host_part := substring(authority FROM '^\[([^]]+)\]');
        ELSE
            host_part := regexp_replace(authority, ':[0-9]+$', '');
        END IF;
        NEW.canonical_key := 'web:' || rtrim(host_part, '.');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_targets_canonical_key
    BEFORE INSERT OR UPDATE OF url, discovery_source ON targets
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
    executing_node_id UUID,
    execution_context JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Status
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, running, completed, failed
    progress INTEGER DEFAULT 0,  -- 0-100
    current_phase TEXT,  -- dns, tls, http, discovery, active, ai

    -- Scan configuration
    options JSONB DEFAULT '{}',
    scan_type TEXT DEFAULT 'quick',  -- quick, standard, thorough, full
    scan_generation TEXT NOT NULL DEFAULT 'legacy',
    policy_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    budget_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    budget_used_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    coverage_status TEXT,
    coverage_json JSONB NOT NULL DEFAULT '{}'::jsonb,
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
    CONSTRAINT scans_run_kind_check CHECK (run_kind IN (
        'web_dast','ai_api','ai_widget','ai_rag','ai_trace','ai_mcp',
        'model_intake','device_posture','device_probe','device_web_dast'
    )),
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
-- CONNECTED DEVICES - Network-connected device posture assets
-- ============================================================
CREATE TABLE device_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    device_class TEXT NOT NULL DEFAULT 'generic',
    environment TEXT NOT NULL DEFAULT 'production',
    rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_builtin BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO device_policies (name, description, device_class, rules, is_builtin)
VALUES (
    'connected-device-default-v1',
    'Safe baseline: forbid cleartext administration, flag unknown services, and require secure SSH.',
    'generic',
    '[
      {"action":"deny","transport":"tcp","ports":[23,2323],"service":"any","severity":"critical","reason":"Cleartext remote administration is forbidden."},
      {"action":"deny","transport":"tcp","ports":[21],"service":"any","severity":"high","reason":"Cleartext file transfer is forbidden."},
      {"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false},"severity":"high"},
      {"action":"allow","transport":"tcp","service":"http","encrypted":false,"severity":"medium"},
      {"action":"allow","transport":"tcp","service":"https","encrypted":true},
      {"action":"review","transport":"any","service":"unknown","severity":"medium","reason":"An unclassified listening service requires review."}
    ]'::jsonb,
    true
)
ON CONFLICT (name) DO NOTHING;

INSERT INTO device_policies (name, description, device_class, rules, is_builtin)
VALUES
(
    'connected-device-default-v2',
    'Fail-closed generic baseline: block cleartext administration, require hardened SSH, review cleartext web and unknown services.',
    'generic',
    '[
      {"action":"deny","transport":"tcp","ports":[23,2323],"service":"any","severity":"critical","reason":"Cleartext remote administration is forbidden."},
      {"action":"deny","transport":"tcp","ports":[21],"service":"any","severity":"high","reason":"Cleartext file transfer is forbidden."},
      {"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false,"publickey_auth":true},"severity":"high"},
      {"action":"allow","transport":"tcp","service":"https","encrypted":true},
      {"action":"review","transport":"tcp","service":"http","encrypted":false,"severity":"medium","reason":"Cleartext device management should be isolated or upgraded to HTTPS."},
      {"action":"review","transport":"any","service":"unknown","severity":"medium","reason":"An unclassified listening service requires review."}
    ]'::jsonb,
    true
),
(
    'media-device-baseline-v1',
    'Smart TV, streaming, and conference display service baseline.',
    'media',
    '[
      {"action":"deny","transport":"tcp","ports":[21,23,2323],"service":"any","severity":"critical","reason":"Legacy cleartext administration is forbidden."},
      {"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false,"publickey_auth":true},"severity":"high"},
      {"action":"allow","transport":"tcp","service":"https","encrypted":true},
      {"action":"review","transport":"tcp","service":"http","encrypted":false,"severity":"medium","reason":"Cleartext media-device web management requires network isolation."},
      {"action":"allow","transport":"udp","ports":[1900],"service":"upnp"},
      {"action":"allow","transport":"udp","ports":[5353],"service":"mdns"},
      {"action":"review","transport":"any","service":"unknown","severity":"medium","reason":"Unexpected media-device service."}
    ]'::jsonb,
    true
),
(
    'camera-baseline-v1',
    'IP camera and video endpoint baseline.',
    'camera',
    '[
      {"action":"deny","transport":"tcp","ports":[21,23,2323],"service":"any","severity":"critical","reason":"Legacy cleartext administration is forbidden."},
      {"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false,"publickey_auth":true},"severity":"high"},
      {"action":"allow","transport":"tcp","service":"https","encrypted":true},
      {"action":"review","transport":"tcp","service":"http","encrypted":false,"severity":"high","reason":"Camera management traffic is unencrypted."},
      {"action":"review","transport":"tcp","service":"rtsp","severity":"medium","reason":"Confirm RTSP authentication and network isolation."},
      {"action":"review","transport":"any","service":"unknown","severity":"high","reason":"Unexpected camera service."}
    ]'::jsonb,
    true
),
(
    'printer-baseline-v1',
    'Printer and multifunction-device baseline.',
    'printer',
    '[
      {"action":"deny","transport":"tcp","ports":[21,23,2323],"service":"any","severity":"high","reason":"Legacy cleartext administration is forbidden."},
      {"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false,"publickey_auth":true},"severity":"high"},
      {"action":"allow","transport":"tcp","service":"https","encrypted":true},
      {"action":"review","transport":"tcp","service":"http","encrypted":false,"severity":"medium","reason":"Printer management is unencrypted."},
      {"action":"review","transport":"tcp","ports":[631,9100],"service":"any","severity":"low","reason":"Confirm print service access is limited to print networks."},
      {"action":"review","transport":"udp","ports":[161],"service":"snmp","severity":"medium","reason":"Confirm SNMPv3 and restricted management access."},
      {"action":"review","transport":"any","service":"unknown","severity":"medium","reason":"Unexpected printer service."}
    ]'::jsonb,
    true
),
(
    'network-appliance-baseline-v1',
    'Router, access point, NAS, and network appliance baseline.',
    'router',
    '[
      {"action":"deny","transport":"tcp","ports":[21,23,2323],"service":"any","severity":"critical","reason":"Legacy cleartext administration is forbidden."},
      {"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false,"publickey_auth":true},"severity":"high"},
      {"action":"allow","transport":"tcp","service":"https","encrypted":true},
      {"action":"review","transport":"tcp","service":"http","encrypted":false,"severity":"high","reason":"Network appliance management is unencrypted."},
      {"action":"allow","transport":"any","ports":[53],"service":"domain"},
      {"action":"review","transport":"udp","ports":[161],"service":"snmp","severity":"medium","reason":"Confirm SNMPv3 and management-plane isolation."},
      {"action":"review","transport":"any","service":"unknown","severity":"high","reason":"Unexpected network appliance service."}
    ]'::jsonb,
    true
)
ON CONFLICT (name) DO NOTHING;

CREATE TABLE device_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    primary_locator TEXT NOT NULL,
    device_class TEXT NOT NULL DEFAULT 'generic',
    manufacturer TEXT,
    model TEXT,
    firmware_version TEXT,
    stable_identity TEXT,
    identity_confidence TEXT NOT NULL DEFAULT 'low',
    environment TEXT NOT NULL DEFAULT 'production',
    policy_id UUID REFERENCES device_policies(id) ON DELETE SET NULL,
    sensor_affinity TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_scanned_at TIMESTAMPTZ,
    last_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    last_score INTEGER,
    last_grade TEXT,
    active_findings_count INTEGER NOT NULL DEFAULT 0,
    locator_generation INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT device_targets_identity_confidence_check CHECK (identity_confidence IN ('low','medium','high','verified'))
);
CREATE UNIQUE INDEX idx_device_targets_active_locator
ON device_targets(primary_locator) WHERE is_active=true;

CREATE TABLE device_interfaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
    interface_type TEXT NOT NULL DEFAULT 'network',
    locator_type TEXT NOT NULL DEFAULT 'ip',
    locator TEXT NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    network_zone TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT device_interfaces_locator_unique UNIQUE (device_target_id, interface_type, locator_type, locator)
);

CREATE TABLE device_locator_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
    previous_locator TEXT,
    locator TEXT NOT NULL,
    locator_type TEXT NOT NULL,
    change_reason TEXT,
    change_source TEXT NOT NULL DEFAULT 'operator',
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_device_locator_history_device
ON device_locator_history(device_target_id, changed_at DESC);

INSERT INTO device_locator_history (
    device_target_id, previous_locator, locator, locator_type, change_reason, change_source
)
SELECT id, NULL, primary_locator,
       CASE WHEN primary_locator ~ '^([0-9]{1,3}\.){3}[0-9]{1,3}$' OR primary_locator LIKE '%:%' THEN 'ip' ELSE 'hostname' END,
       'Initial registered locator', 'registration'
FROM device_targets;

CREATE TABLE device_credential_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    auth_kind TEXT NOT NULL,
    username TEXT,
    secret_value TEXT NOT NULL,
    secret_preview TEXT,
    login_path TEXT,
    port INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT device_credential_profiles_kind_check CHECK (auth_kind IN (
        'ssh_password','ssh_private_key','web_authorization_header','web_cookie','web_form'
    )),
    CONSTRAINT device_credential_profiles_name_unique UNIQUE (device_target_id, name)
);
CREATE INDEX idx_device_credential_profiles_active
ON device_credential_profiles(device_target_id, is_active, expires_at);

CREATE TABLE device_request_collections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'postman_collection',
    document_sha256 TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL,
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT device_request_collections_format_check CHECK (format IN ('postman_collection','har','openapi')),
    CONSTRAINT device_request_collections_name_unique UNIQUE (device_target_id, name)
);
CREATE INDEX idx_device_request_collections_active
ON device_request_collections(device_target_id, is_active, updated_at DESC);

CREATE TABLE request_collections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    device_target_id UUID REFERENCES device_targets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    format TEXT NOT NULL,
    schema_version TEXT NOT NULL DEFAULT 'request-collection/v2',
    encrypted_payload TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    safe_request_count INTEGER NOT NULL DEFAULT 0,
    potentially_mutating_request_count INTEGER NOT NULL DEFAULT 0,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT request_collections_target_check CHECK (
        (target_id IS NOT NULL AND device_target_id IS NULL) OR
        (device_target_id IS NOT NULL AND target_id IS NULL)
    ),
    CONSTRAINT request_collections_target_name_unique UNIQUE NULLS NOT DISTINCT (target_id, device_target_id, name)
);
CREATE INDEX idx_request_collections_web ON request_collections(target_id, updated_at DESC) WHERE target_id IS NOT NULL AND is_active=true;
CREATE INDEX idx_request_collections_device ON request_collections(device_target_id, updated_at DESC) WHERE device_target_id IS NOT NULL AND is_active=true;

CREATE TABLE request_collection_requests (
    collection_id UUID NOT NULL REFERENCES request_collections(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    folder TEXT,
    name TEXT,
    method TEXT NOT NULL,
    redacted_url TEXT,
    normalized_path TEXT,
    body_mode TEXT,
    auth_type TEXT,
    safe_method BOOLEAN NOT NULL DEFAULT false,
    supported BOOLEAN NOT NULL DEFAULT true,
    PRIMARY KEY (collection_id, request_id)
);
CREATE INDEX idx_request_collection_requests_page ON request_collection_requests(collection_id, ordinal);

CREATE TABLE device_credential_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
    credential_profile_id UUID NOT NULL REFERENCES device_credential_profiles(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    outcome TEXT NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT device_credential_attempts_outcome_check CHECK (outcome IN ('succeeded','rejected','error')),
    CONSTRAINT device_credential_attempts_scan_profile_unique UNIQUE (scan_id, credential_profile_id)
);
CREATE INDEX idx_device_credential_attempts_profile_time
ON device_credential_attempts(credential_profile_id, attempted_at DESC);

ALTER TABLE scans
ADD COLUMN device_target_id UUID REFERENCES device_targets(id) ON DELETE SET NULL;

CREATE TABLE device_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    interface_id UUID REFERENCES device_interfaces(id) ON DELETE SET NULL,
    transport TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    state TEXT NOT NULL DEFAULT 'open',
    service_name TEXT NOT NULL DEFAULT 'unknown',
    product TEXT,
    version TEXT,
    cpe TEXT,
    encrypted BOOLEAN,
    web_origin TEXT,
    policy_disposition TEXT,
    policy_reason TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT device_services_identity_unique UNIQUE (device_target_id, transport, port),
    CONSTRAINT device_services_transport_check CHECK (transport IN ('tcp','udp')),
    CONSTRAINT device_services_state_check CHECK (state IN ('open','open|filtered','not_observed')),
    CONSTRAINT device_services_policy_disposition_check CHECK (
        policy_disposition IS NULL OR policy_disposition IN ('allow','deny','review','require','not_evaluated')
    )
);

CREATE TABLE device_agent_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
    objective TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'awaiting_planner',
    planner_mode TEXT NOT NULL DEFAULT 'agent',
    safety_profile TEXT NOT NULL DEFAULT 'safe_remote',
    max_turns INTEGER NOT NULL DEFAULT 12 CHECK (max_turns BETWEEN 1 AND 30),
    approval_receipt_id UUID,
    state JSONB NOT NULL DEFAULT '{}'::jsonb,
    planning_token UUID,
    stop_reason TEXT,
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT device_agent_runs_status_check CHECK (
        status IN ('awaiting_planner','planning','completed','cancelled','failed')
    ),
    CONSTRAINT device_agent_runs_safety_check CHECK (
        safety_profile IN ('observe_only','safe_remote','authenticated_active','lab_invasive')
    ),
    CONSTRAINT device_agent_runs_planner_mode_check CHECK (planner_mode IN ('agent'))
);

CREATE INDEX idx_device_agent_runs_device
ON device_agent_runs(device_target_id, created_at DESC);

CREATE INDEX idx_device_agent_runs_status
ON device_agent_runs(status, updated_at DESC);

CREATE UNIQUE INDEX idx_device_agent_runs_one_active_per_device
ON device_agent_runs(device_target_id)
WHERE status IN ('awaiting_planner','planning');

CREATE TABLE device_agent_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id UUID NOT NULL REFERENCES device_agent_runs(id) ON DELETE CASCADE,
    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    tool_tier INTEGER NOT NULL CHECK (tool_tier BETWEEN 0 AND 3),
    fragility_cost INTEGER NOT NULL DEFAULT 0 CHECK (fragility_cost BETWEEN 0 AND 100),
    rationale TEXT,
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    outcome TEXT NOT NULL CHECK (outcome IN ('completed','blocked','failed')),
    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_device_agent_actions_run
ON device_agent_actions(run_id, created_at);
CREATE INDEX idx_device_agent_actions_device_day
ON device_agent_actions(device_target_id, created_at DESC);

-- Canonical Hunt V2 runtime. The external AI owns planning; this table stores only authority,
-- budgets, durable observations, capability receipts, candidates, and the final debrief.
CREATE TABLE hunt_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_kind TEXT NOT NULL CHECK (target_kind IN ('web','api','device','network')),
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    device_target_id UUID REFERENCES device_targets(id) ON DELETE CASCADE,
    objective TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active' CHECK (
        status IN ('created','active','awaiting_planner','completed','cancelled','failed','budget_exhausted')
    ),
    budget_profile TEXT NOT NULL DEFAULT 'balanced' CHECK (budget_profile IN ('fast','balanced','thorough')),
    policy_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    budget_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    budget_used_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_pack JSONB NOT NULL DEFAULT '{}'::jsonb,
    notes JSONB NOT NULL DEFAULT '[]'::jsonb,
    final_debrief JSONB NOT NULL DEFAULT '{}'::jsonb,
    approval_receipt_id UUID,
    stop_reason TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT hunt_runs_target_check CHECK (
        (target_kind IN ('web','api','network') AND target_id IS NOT NULL AND device_target_id IS NULL) OR
        (target_kind='device' AND device_target_id IS NOT NULL AND target_id IS NULL)
    )
);
CREATE INDEX idx_hunt_runs_web ON hunt_runs(target_id, created_at DESC) WHERE target_id IS NOT NULL;
CREATE INDEX idx_hunt_runs_device ON hunt_runs(device_target_id, created_at DESC) WHERE device_target_id IS NOT NULL;
CREATE INDEX idx_hunt_runs_status ON hunt_runs(status, updated_at DESC);

CREATE TABLE hunt_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    capability_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running','completed','blocked','failed','partial')),
    input_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    receipt_id UUID,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX idx_hunt_actions_run ON hunt_actions(hunt_run_id, started_at);

-- ============================================================
-- FINDINGS - Vulnerabilities discovered
-- ============================================================
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    ai_target_id UUID REFERENCES ai_targets(id) ON DELETE CASCADE,
    device_target_id UUID REFERENCES device_targets(id) ON DELETE CASCADE,

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

CREATE OR REPLACE FUNCTION refresh_device_active_findings_count()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE device_targets d
    SET active_findings_count=(
        SELECT COUNT(*) FROM findings f
        WHERE f.device_target_id=d.id AND f.status='active'
    ), updated_at=NOW()
    WHERE d.id IN (OLD.device_target_id, NEW.device_target_id);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_refresh_device_active_findings_count
AFTER INSERT OR UPDATE OF status, device_target_id OR DELETE ON findings
FOR EACH ROW EXECUTE FUNCTION refresh_device_active_findings_count();

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
    retention_delete_preview_id UUID,
    retention_delete_pending_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT evidence_objects_finding_type_unique UNIQUE (finding_id, object_type)
);
CREATE INDEX idx_evidence_objects_finding ON evidence_objects(finding_id);
CREATE INDEX idx_evidence_objects_scan ON evidence_objects(scan_id);
CREATE INDEX idx_evidence_objects_retention_pending ON evidence_objects(retention_delete_pending_at)
    WHERE retention_delete_pending_at IS NOT NULL;

-- General scan artifacts shared by every worker node. The object store holds
-- bytes; this table is the durable, queryable index and integrity contract.
CREATE TABLE scan_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    parent_scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    shard_index INTEGER,
    executing_node_id UUID,
    artifact_type TEXT NOT NULL,
    artifact_key TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    storage_uri TEXT NOT NULL,
    storage_backend TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'available'
        CHECK (status IN ('available','deleting','upload_failed','missing','deleted')),
    retention_class TEXT NOT NULL DEFAULT 'standard',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT scan_artifacts_identity_unique UNIQUE (scan_id, artifact_type, artifact_key)
);
CREATE INDEX idx_scan_artifacts_scan ON scan_artifacts(scan_id, created_at DESC);
CREATE INDEX idx_scan_artifacts_retention ON scan_artifacts(expires_at)
    WHERE status = 'available' AND expires_at IS NOT NULL;

-- One-use, target-scoped retention previews bind destructive cleanup to the
-- exact server-computed evidence snapshot the operator reviewed.
CREATE TABLE evidence_retention_previews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL,
    criteria_json JSONB NOT NULL,
    candidate_snapshot_json JSONB NOT NULL,
    preview_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready',
    approval_receipt_id UUID,
    scope_receipt_id TEXT,
    operation_id UUID,
    result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    execution_started_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT evidence_retention_previews_status_check
        CHECK (status IN ('ready','executing','consumed','stale'))
);
CREATE INDEX idx_evidence_retention_previews_target
    ON evidence_retention_previews(target_id, created_at DESC);
CREATE INDEX idx_evidence_retention_previews_ready
    ON evidence_retention_previews(expires_at) WHERE status = 'ready';
CREATE UNIQUE INDEX idx_evidence_retention_previews_approval_once
    ON evidence_retention_previews(approval_receipt_id) WHERE approval_receipt_id IS NOT NULL;

-- An executing preview is the durable recovery record for pending evidence rows.
-- RESTRICT prevents target cascades (including canonical target de-duplication)
-- from deleting that record until the pending rows are finalized or cleared.
ALTER TABLE evidence_objects
    ADD CONSTRAINT evidence_objects_retention_delete_preview_fk
    FOREIGN KEY (retention_delete_preview_id)
    REFERENCES evidence_retention_previews(id)
    ON DELETE RESTRICT;

-- ============================================================
-- EXPORT EVENTS - Durable content-free export/audit records
-- ============================================================
CREATE TABLE export_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    export_kind TEXT NOT NULL,
    command TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed',
    risk_tier TEXT NOT NULL DEFAULT 'read_only',
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    scan_id UUID,
    finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    bundle_hash TEXT,
    manifest_hash TEXT,
    object_count INTEGER NOT NULL DEFAULT 0,
    filters JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence_object_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    scan_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    replay_plan JSONB NOT NULL DEFAULT '{}'::jsonb,
    operator_message TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT export_events_status_check
        CHECK (status IN ('completed','partial','degraded','failed')),
    CONSTRAINT export_events_risk_check
        CHECK (risk_tier IN ('read_only','passive','active','intrusive','credential','dangerous'))
);
CREATE INDEX idx_export_events_created_at ON export_events(created_at DESC);
CREATE INDEX idx_export_events_target ON export_events(target_id, created_at DESC) WHERE target_id IS NOT NULL;
CREATE INDEX idx_export_events_scan ON export_events(scan_id, created_at DESC) WHERE scan_id IS NOT NULL;
CREATE INDEX idx_export_events_finding ON export_events(finding_id, created_at DESC) WHERE finding_id IS NOT NULL;

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
-- SCHEDULES - Recurring target actions (optional feature)
-- ============================================================
CREATE TABLE schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Target
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    name TEXT,

    -- Schedule configuration
    frequency TEXT NOT NULL,  -- daily, weekly
    day_of_week INTEGER,  -- 0-6 (Monday-Sunday) for weekly
    time_of_day TEXT DEFAULT '02:00',  -- HH:MM in UTC
    timezone TEXT DEFAULT 'UTC',
    jitter_minutes INTEGER DEFAULT 30,

    -- Action configuration
    schedule_kind TEXT DEFAULT 'normal_scan',  -- normal_scan, asm_improve, evidence_retention_sweep
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
CREATE INDEX idx_scans_device_target_created ON scans(device_target_id, created_at DESC) WHERE device_target_id IS NOT NULL;
CREATE UNIQUE INDEX idx_scans_one_active_device_traffic
ON scans(device_target_id)
WHERE device_target_id IS NOT NULL
  AND run_kind IN ('device_posture','device_probe')
  AND status IN ('pending','queued','running','cancelling');
CREATE INDEX idx_scans_run_kind ON scans(run_kind);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
CREATE INDEX idx_scans_executing_node ON scans(executing_node_id, created_at DESC)
    WHERE executing_node_id IS NOT NULL;
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
CREATE UNIQUE INDEX idx_findings_device_fingerprint ON findings(device_target_id, fingerprint) WHERE device_target_id IS NOT NULL;
CREATE INDEX idx_device_targets_active_updated ON device_targets(is_active, updated_at DESC);
CREATE INDEX idx_device_services_target_seen ON device_services(device_target_id, last_seen_at DESC);
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
  AND COALESCE(run_kind, 'web_dast') NOT IN ('device_posture', 'device_probe', 'device_web_dast')
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
    (SELECT COUNT(*) FROM targets WHERE is_active = true AND COALESCE(discovery_source, 'manual') <> 'model-intake') as total_targets,
    (SELECT COUNT(*) FROM scans WHERE status = 'completed' AND (scan_role IS NULL OR scan_role <> 'shard') AND COALESCE(run_kind, 'web_dast') NOT IN ('device_posture', 'device_probe', 'device_web_dast')) as total_scans,
    (SELECT COUNT(*) FROM scans WHERE status = 'running' AND (scan_role IS NULL OR scan_role <> 'shard') AND COALESCE(run_kind, 'web_dast') NOT IN ('device_posture', 'device_probe', 'device_web_dast')) as running_scans,
    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND COALESCE(source, 'scan') <> 'device') as active_findings,
    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND severity = 'critical' AND COALESCE(source, 'scan') <> 'device') as critical_findings,
    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND severity = 'high' AND COALESCE(source, 'scan') <> 'device') as high_findings,
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
    edit_history JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT finding_exceptions_status_check
        CHECK (status IN ('active','approved','accepted_risk','revoked','expired'))
);
CREATE INDEX IF NOT EXISTS idx_finding_exceptions_target_status ON finding_exceptions(target_id, status);
CREATE INDEX IF NOT EXISTS idx_finding_exceptions_finding ON finding_exceptions(finding_id);

-- Model Intake reusable operator trust anchors. Admission requests cannot
-- select these records; only the trusted control plane may resolve them by
-- purpose, environment, and policy.
CREATE TABLE IF NOT EXISTS model_intake_trust_anchors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    public_key_pem TEXT,
    public_key_sha256 TEXT,
    policy_profile TEXT,
    purpose TEXT NOT NULL DEFAULT 'publisher_signature',
    environment TEXT NOT NULL DEFAULT 'production',
    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    issuer_constraint TEXT,
    subject_constraint TEXT,
    builder_id_constraint TEXT,
    source TEXT NOT NULL DEFAULT 'operator',
    version TEXT NOT NULL DEFAULT '1',
    owner TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT model_intake_trust_anchor_material_check
        CHECK (
            (public_key_pem IS NOT NULL AND btrim(public_key_pem) <> '')
            OR (public_key_sha256 IS NOT NULL AND btrim(public_key_sha256) <> '')
        ),
    CONSTRAINT model_intake_trust_anchor_purpose_check CHECK (purpose IN (
        'publisher_signature','upstream_attestation','runtime_runner','evaluation_runner',
        'data_plane_runner','approval_signer','admission_signer'
    )),
    CONSTRAINT model_intake_trust_anchor_environment_check
        CHECK (environment IN ('development','test','staging','production'))
);
CREATE INDEX IF NOT EXISTS idx_model_intake_trust_anchors_active
    ON model_intake_trust_anchors(is_active, purpose, environment, policy_profile);

CREATE TABLE IF NOT EXISTS model_intake_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    requested_by TEXT NOT NULL,
    requested_environment TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    source_reference_hash TEXT NOT NULL,
    expected_artifact_sha256 TEXT,
    intended_use JSONB NOT NULL DEFAULT '{}'::jsonb,
    declared_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    state TEXT NOT NULL DEFAULT 'submitted',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT model_intake_submission_environment_check
        CHECK (requested_environment IN ('development','test','staging','production')),
    CONSTRAINT model_intake_submission_state_check CHECK (state IN (
        'submitted','scanning','evidence_ready','evidence_frozen','awaiting_approval',
        'policy_decided','admitted','promoted','blocked','cancelled'
    ))
);
CREATE INDEX IF NOT EXISTS idx_model_intake_submissions_state
    ON model_intake_submissions(state, created_at DESC);

CREATE TABLE IF NOT EXISTS model_intake_submission_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    previous_state TEXT NOT NULL,
    new_state TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_model_intake_submission_events_submission
    ON model_intake_submission_events(submission_id, created_at DESC);

CREATE TABLE IF NOT EXISTS model_intake_subjects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
    subject_kind TEXT NOT NULL,
    immutable_uri TEXT,
    sha256 TEXT NOT NULL,
    size_bytes BIGINT,
    manifest_sha256 TEXT,
    source_revision TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT model_intake_subject_unique UNIQUE (submission_id, subject_kind, sha256)
);

CREATE TABLE IF NOT EXISTS model_intake_evidence_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    provenance_class TEXT NOT NULL,
    producer_id TEXT NOT NULL,
    producer_version TEXT NOT NULL,
    builder_id TEXT NOT NULL,
    invocation_id TEXT NOT NULL,
    subject_bindings JSONB NOT NULL,
    input_manifest_sha256 TEXT,
    payload_sha256 TEXT NOT NULL,
    payload_json JSONB,
    object_storage_uri TEXT,
    signature_envelope JSONB,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    supersedes_id UUID REFERENCES model_intake_evidence_records(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT model_intake_evidence_invocation_unique UNIQUE (producer_id, invocation_id),
    CONSTRAINT model_intake_evidence_provenance_check CHECK (provenance_class IN (
        'DECLARED','PROVIDER_RESOLVED','GENERATED_STATIC','GENERATED_RUNTIME',
        'GENERATED_EVALUATION','GENERATED_DATA_PLANE','HUMAN_APPROVAL',
        'POLICY_DECISION','DEPLOYMENT_OBSERVED'
    ))
);
CREATE INDEX IF NOT EXISTS idx_model_intake_evidence_submission
    ON model_intake_evidence_records(submission_id, evidence_type, created_at DESC);

CREATE TABLE IF NOT EXISTS model_intake_runner_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK (operation IN ('calibration','runtime','conversion')),
    state TEXT NOT NULL CHECK (state IN ('pending','running','completed','failed')),
    remote_job_id UUID NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL,
    request_json JSONB NOT NULL,
    result_json JSONB,
    error_json JSONB,
    evidence_record_id UUID REFERENCES model_intake_evidence_records(id) ON DELETE SET NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_model_intake_runner_jobs_submission
    ON model_intake_runner_jobs(submission_id, created_at DESC);

CREATE TABLE IF NOT EXISTS model_intake_agent_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
    objective TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('awaiting_planner','completed','cancelled')),
    max_iterations INTEGER NOT NULL CHECK (max_iterations BETWEEN 1 AND 30),
    iteration INTEGER NOT NULL DEFAULT 0,
    action_budget INTEGER NOT NULL CHECK (action_budget BETWEEN 1 AND 100),
    actions_used INTEGER NOT NULL DEFAULT 0,
    transcript_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    final_assessment_json JSONB,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_model_intake_agent_sessions_submission
    ON model_intake_agent_sessions(submission_id, created_at DESC);

CREATE TABLE IF NOT EXISTS model_intake_agent_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES model_intake_agent_sessions(id) ON DELETE CASCADE,
    iteration INTEGER NOT NULL,
    action_name TEXT NOT NULL,
    arguments_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('completed','rejected','error')),
    result_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_model_intake_agent_actions_session
    ON model_intake_agent_actions(session_id, created_at);

CREATE TABLE IF NOT EXISTS model_intake_evidence_manifests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    manifest_sha256 TEXT NOT NULL UNIQUE,
    evidence_ids JSONB NOT NULL,
    manifest_json JSONB NOT NULL,
    deployment_bundle_json JSONB NOT NULL,
    subject_bundle_sha256 TEXT NOT NULL,
    frozen_at TIMESTAMPTZ NOT NULL,
    frozen_by TEXT NOT NULL,
    supersedes_id UUID REFERENCES model_intake_evidence_manifests(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT model_intake_evidence_manifest_version_unique UNIQUE (submission_id, version)
);

CREATE TABLE IF NOT EXISTS model_intake_approval_receipts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
    evidence_manifest_id UUID NOT NULL REFERENCES model_intake_evidence_manifests(id) ON DELETE CASCADE,
    receipt_sha256 TEXT NOT NULL UNIQUE,
    receipt_json JSONB NOT NULL,
    approval_type TEXT NOT NULL,
    decision TEXT NOT NULL,
    approved_by_subject TEXT NOT NULL,
    approved_by_role TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS model_intake_policy_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
    evidence_manifest_id UUID NOT NULL REFERENCES model_intake_evidence_manifests(id) ON DELETE CASCADE,
    decision_sha256 TEXT NOT NULL UNIQUE,
    decision_json JSONB NOT NULL,
    decision TEXT NOT NULL,
    policy_provider TEXT NOT NULL,
    policy_bundle_sha256 TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS model_intake_deployment_bindings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
    admission_id UUID,
    deployment_bundle_sha256 TEXT NOT NULL,
    environment TEXT NOT NULL,
    observed_bundle_sha256 TEXT,
    verifier_status TEXT NOT NULL DEFAULT 'not_observed',
    deployment_reference TEXT,
    observed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS model_intake_admissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    submission_id UUID REFERENCES model_intake_submissions(id) ON DELETE SET NULL,
    artifact_sha256 TEXT NOT NULL,
    repository_snapshot_sha256 TEXT,
    statement_sha256 TEXT NOT NULL UNIQUE,
    admission_package JSONB NOT NULL,
    decision TEXT NOT NULL,
    status TEXT NOT NULL,
    schema_version TEXT NOT NULL DEFAULT 'model-intake-admission/v1',
    deployment_bundle_sha256 TEXT,
    evidence_manifest_sha256 TEXT,
    policy_decision_sha256 TEXT,
    target_environment TEXT,
    idempotency_key_sha256 TEXT UNIQUE,
    policy_profile TEXT,
    policy_version TEXT,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    reassessment_due_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    revocation_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT model_intake_admission_status_check
        CHECK (status IN ('active','denied','reassessment_required','revoked','expired','superseded'))
);
CREATE INDEX IF NOT EXISTS idx_model_intake_admissions_subject
    ON model_intake_admissions(artifact_sha256, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_model_intake_admissions_reassessment
    ON model_intake_admissions(status, reassessment_due_at);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'model_intake_deployment_bindings_admission_id_fkey'
          AND conrelid = 'model_intake_deployment_bindings'::regclass
    ) THEN
        ALTER TABLE model_intake_deployment_bindings
        ADD CONSTRAINT model_intake_deployment_bindings_admission_id_fkey
        FOREIGN KEY (admission_id) REFERENCES model_intake_admissions(id) ON DELETE SET NULL;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS model_intake_admission_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admission_id UUID NOT NULL REFERENCES model_intake_admissions(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    trigger_type TEXT,
    actor TEXT,
    reason TEXT,
    previous_status TEXT,
    new_status TEXT,
    evidence_digest TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_model_intake_admission_events_admission
    ON model_intake_admission_events(admission_id, created_at DESC);

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

-- Owned-fleet identity and enrollment foundation. Raw enrollment tokens and
-- node credentials are returned once and never stored; only domain-separated
-- hashes live in Postgres.
CREATE TABLE IF NOT EXISTS nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    hostname TEXT,
    role TEXT NOT NULL CHECK (role IN ('control_plane', 'worker')),
    overlay_ip INET UNIQUE,
    wireguard_public_key TEXT UNIQUE,
    egress_ip INET,
    region TEXT,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    build_fingerprint TEXT,
    worker_image_digest TEXT,
    active_worker_image_digest TEXT,
    agent_version TEXT,
    desired_state_version INTEGER NOT NULL DEFAULT 1 CHECK (desired_state_version > 0),
    desired_state_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_state_version INTEGER NOT NULL DEFAULT 0 CHECK (applied_state_version >= 0),
    last_error TEXT,
    desired_worker_count INTEGER NOT NULL DEFAULT 0 CHECK (desired_worker_count BETWEEN 0 AND 128),
    active_worker_count INTEGER NOT NULL DEFAULT 0 CHECK (active_worker_count BETWEEN 0 AND 128),
    capacity JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'joining'
        CHECK (status IN ('joining', 'healthy', 'stale', 'draining', 'disabled')),
    drain BOOLEAN NOT NULL DEFAULT false,
    rollout_in_progress BOOLEAN NOT NULL DEFAULT false,
    last_heartbeat_at TIMESTAMPTZ,
    connection_bundle_delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE scans
    ADD CONSTRAINT scans_executing_node_fk
    FOREIGN KEY (executing_node_id) REFERENCES nodes(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_nodes_status_heartbeat ON nodes(status, last_heartbeat_at DESC);

CREATE TABLE IF NOT EXISTS fleet_node_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('operator','node','system','broker')),
    severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warning','error')),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fleet_node_events_node_created
    ON fleet_node_events(node_id, created_at DESC);

CREATE TABLE IF NOT EXISTS broker_job_leases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    queue_name TEXT NOT NULL,
    stream_key TEXT NOT NULL,
    message_id TEXT NOT NULL,
    consumer_name TEXT NOT NULL,
    lease_token_hash TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    budget_reservation JSONB NOT NULL DEFAULT '{}'::jsonb,
    job_id TEXT,
    scan_id UUID,
    status TEXT NOT NULL DEFAULT 'leased'
        CHECK (status IN ('leased','submitted','ingesting','completed','failed','cancelled','lost')),
    delivery_attempts INTEGER NOT NULL DEFAULT 1,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ingest_enqueued_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (stream_key, message_id)
);
CREATE INDEX IF NOT EXISTS idx_broker_job_leases_node_status
    ON broker_job_leases(node_id, status, lease_expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_broker_job_leases_active_worker
    ON broker_job_leases(node_id, worker_id) WHERE status = 'leased';

CREATE TABLE IF NOT EXISTS broker_job_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lease_id UUID NOT NULL UNIQUE REFERENCES broker_job_leases(id) ON DELETE CASCADE,
    result_sha256 TEXT NOT NULL,
    result JSONB NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ingested_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS node_join_tokens (
    token_hash TEXT PRIMARY KEY,
    token_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    role TEXT NOT NULL CHECK (role = 'worker'),
    transport TEXT NOT NULL CHECK (transport IN ('overlay', 'broker')),
    expires_at TIMESTAMPTZ NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 128),
    use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count BETWEEN 0 AND max_uses),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_node_join_tokens_expires ON node_join_tokens(expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS node_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    credential_hash TEXT NOT NULL UNIQUE,
    credential_version INTEGER NOT NULL DEFAULT 1 CHECK (credential_version > 0),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT node_credentials_node_version_unique UNIQUE (node_id, credential_version)
);
CREATE INDEX IF NOT EXISTS idx_node_credentials_active ON node_credentials(node_id, credential_version DESC)
    WHERE revoked_at IS NULL;

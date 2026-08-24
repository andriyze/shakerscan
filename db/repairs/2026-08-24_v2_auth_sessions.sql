-- Durable encrypted authentication sessions for canonical Hunt workers.
BEGIN;

CREATE TABLE IF NOT EXISTS auth_sessions (
    id UUID PRIMARY KEY,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('scan','hunt')),
    owner_id UUID NOT NULL,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('web','api')),
    target_id UUID NOT NULL,
    target_binding_digest TEXT NOT NULL CHECK (
        target_binding_digest ~ '^[0-9a-f]{64}$'
    ),
    profile_id UUID NOT NULL REFERENCES credential_profiles(id) ON DELETE CASCADE,
    profile_version INTEGER NOT NULL CHECK (profile_version > 0),
    principal_slot TEXT NOT NULL CHECK (
        principal_slot IN ('primary','secondary','service')
    ),
    principal_label TEXT,
    auth_kind TEXT NOT NULL CHECK (
        auth_kind IN ('form_login','oauth_client_credentials','oauth_password')
    ),
    compatible_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(compatible_capabilities) = 'array'
    ),
    encrypted_headers TEXT NOT NULL CHECK (
        encrypted_headers LIKE 'enc:fernet:%'
    ),
    status TEXT NOT NULL DEFAULT 'active' CHECK (
        status IN ('active','revoked','expired')
    ),
    established_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_after TIMESTAMPTZ NOT NULL,
    last_refreshed_at TIMESTAMPTZ,
    refresh_count INTEGER NOT NULL DEFAULT 0 CHECK (refresh_count >= 0),
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    evidence_receipt_digest TEXT NOT NULL CHECK (
        evidence_receipt_digest ~ '^[0-9a-f]{64}$'
    ),
    evidence_receipt_id UUID,
    source_action_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT auth_sessions_expiry_check CHECK (
        established_at < expires_at
        AND refresh_after >= established_at
        AND refresh_after < expires_at
    )
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_owner_active
    ON auth_sessions(owner_kind, owner_id, principal_slot, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_profile_active
    ON auth_sessions(profile_id, profile_version, status, expires_at);

CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_auth_sessions_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;

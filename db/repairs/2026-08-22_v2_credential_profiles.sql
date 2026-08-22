-- Canonical encrypted credential profiles shared by Scan and Hunt.
-- Runtime startup installs the same idempotent schema under the global migration lock.

BEGIN;

CREATE TABLE IF NOT EXISTS credential_profiles (
    id UUID PRIMARY KEY,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('web','api','network','device')),
    target_id UUID NOT NULL,
    name TEXT NOT NULL,
    auth_kind TEXT NOT NULL CHECK (auth_kind IN (
        'authorization_header','bearer_token','api_key_header','cookie','basic_auth',
        'form_login','oauth_client_credentials','oauth_password','custom_headers','query_parameter',
        'ssh_password','ssh_private_key','ssh_private_key_with_passphrase'
    )),
    principal_label TEXT,
    principal_slot TEXT NOT NULL CHECK (principal_slot IN ('primary','secondary','service','ssh')),
    configuration_json JSONB NOT NULL CHECK (jsonb_typeof(configuration_json) = 'object'),
    current_version INTEGER NOT NULL DEFAULT 1 CHECK (current_version > 0),
    record_version INTEGER NOT NULL DEFAULT 1 CHECK (record_version > 0),
    is_active BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT credential_profiles_target_name_unique
        UNIQUE (target_kind, target_id, name),
    CONSTRAINT credential_profiles_id_target_unique
        UNIQUE (id, target_kind, target_id),
    CONSTRAINT credential_profiles_id_auth_unique
        UNIQUE (id, auth_kind),
    CONSTRAINT credential_profiles_expiry_check
        CHECK (expires_at IS NULL OR expires_at > created_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_profiles_target_name_ci
    ON credential_profiles(target_kind, target_id, lower(name));
CREATE INDEX IF NOT EXISTS idx_credential_profiles_target_active
    ON credential_profiles(target_kind, target_id, is_active, expires_at);

CREATE TABLE IF NOT EXISTS credential_profile_versions (
    profile_id UUID NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    auth_kind TEXT NOT NULL,
    encrypted_secret TEXT NOT NULL CHECK (encrypted_secret LIKE 'enc:fernet:%'),
    encrypted_metadata TEXT NOT NULL CHECK (encrypted_metadata LIKE 'enc:fernet:%'),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (profile_id, version),
    CONSTRAINT credential_profile_versions_profile_auth_fk
        FOREIGN KEY (profile_id, auth_kind)
        REFERENCES credential_profiles(id, auth_kind) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS credential_profile_bindings (
    id UUID PRIMARY KEY,
    profile_id UUID NOT NULL REFERENCES credential_profiles(id) ON DELETE CASCADE,
    binding_kind TEXT NOT NULL CHECK (binding_kind IN ('target','scan','hunt')),
    binding_id TEXT NOT NULL,
    allowed_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(allowed_capabilities) = 'array'),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT credential_profile_bindings_unique
        UNIQUE (profile_id, binding_kind, binding_id)
);
CREATE INDEX IF NOT EXISTS idx_credential_profile_bindings_consumer
    ON credential_profile_bindings(binding_kind, binding_id, is_active);

CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_credential_profiles_v1')
ON CONFLICT (name) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='credential_profiles_auth_kind_check'
          AND conrelid='credential_profiles'::regclass
          AND pg_get_constraintdef(oid) NOT LIKE '%query_parameter%'
    ) THEN
        ALTER TABLE credential_profiles DROP CONSTRAINT credential_profiles_auth_kind_check;
        ALTER TABLE credential_profiles ADD CONSTRAINT credential_profiles_auth_kind_check
            CHECK (auth_kind IN (
                'authorization_header','bearer_token','api_key_header','cookie','basic_auth',
                'form_login','oauth_client_credentials','oauth_password','custom_headers','query_parameter',
                'ssh_password','ssh_private_key','ssh_private_key_with_passphrase'
            ));
    END IF;
END
$$;

INSERT INTO app_schema_migrations(name)
VALUES ('v2_credential_query_parameter_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;

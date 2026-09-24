"""Additive schema repair for canonical Hunt device authentication and investigations."""

HUNT_SESSION_SCHEMA_SQL = r"""
ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS auth_sessions_target_kind_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_target_kind_check
    CHECK (target_kind IN ('web','api','network','device'));
ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS auth_sessions_auth_kind_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_auth_kind_check
    CHECK (auth_kind IN ('form_login','oauth_client_credentials','oauth_password','json_login'));
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS service_origin TEXT;
"""

HUNT_SERVICE_SCHEMA_SQL = HUNT_SESSION_SCHEMA_SQL + r"""
ALTER TABLE application_graph_nodes ADD COLUMN IF NOT EXISTS device_target_id UUID
    REFERENCES device_targets(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX IF NOT EXISTS app_graph_device_node_unique
    ON application_graph_nodes(device_target_id, node_type, node_key);
INSERT INTO app_schema_migrations(name) VALUES ('v2_hunt_service_assets_v1')
    ON CONFLICT (name) DO NOTHING;
"""

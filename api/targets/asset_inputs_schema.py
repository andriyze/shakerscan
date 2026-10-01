"""Compatibility projections over shared credential and request-collection records."""

INPUTS_MIGRATION = "unified_target_asset_inputs_v1"

INPUTS_SCHEMA_SQL = r"""
ALTER TABLE credential_profiles ADD COLUMN IF NOT EXISTS service_port INTEGER
    CHECK (service_port BETWEEN 1 AND 65535);

-- Prefer an explicit consumer grant, including a revoked grant, over inheritance.
-- Inheritance uses recorded, current asset membership, never DNS/IP coincidence.
CREATE OR REPLACE FUNCTION target_credential_grant(profile uuid, consumer uuid)
RETURNS SETOF credential_profile_bindings LANGUAGE sql STABLE AS $$
    SELECT b.* FROM credential_profiles p JOIN credential_profile_bindings b
      ON b.profile_id=p.id AND b.binding_kind='target'
    WHERE p.id=profile AND (
        b.binding_id=consumer::text
        OR b.binding_id=target_asset_access_owner(consumer)::text
        OR (target_asset_access_owner(p.target_id)=target_asset_access_owner(consumer)
            AND b.binding_id=p.target_id::text)
    )
    ORDER BY CASE WHEN b.binding_id=consumer::text THEN 0
                  WHEN b.binding_id=target_asset_access_owner(consumer)::text THEN 1 ELSE 2 END
    LIMIT 1
$$;

CREATE OR REPLACE FUNCTION target_collection_visible(collection uuid, consumer uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT COALESCE((
        SELECT b.is_active FROM request_collection_bindings b
        WHERE b.collection_id=collection AND b.target_id=consumer
        ORDER BY b.updated_at DESC,b.id LIMIT 1
    ), (
        SELECT target_asset_access_owner(c.target_id)=target_asset_access_owner(consumer)
            OR EXISTS (SELECT 1 FROM request_collection_bindings b
                       WHERE b.collection_id=c.id AND b.is_active
                         AND b.target_id=target_asset_access_owner(consumer))
        FROM request_collections c WHERE c.id=collection
    ), false)
$$;
"""

INPUTS_VIEW_SQL = r"""
CREATE VIEW device_credential_profiles AS
SELECT p.id, d.target_id AS device_target_id, d.target_id,
       p.target_id AS home_target_id, p.name,
       CASE p.auth_kind
         WHEN 'ssh_password' THEN 'ssh_password'
         WHEN 'ssh_private_key' THEN 'ssh_private_key'
         WHEN 'ssh_private_key_with_passphrase' THEN 'ssh_private_key'
         WHEN 'cookie' THEN 'web_cookie'
         WHEN 'form_login' THEN 'web_form'
         ELSE 'web_authorization_header'
       END AS auth_kind,
       p.auth_kind AS canonical_auth_kind,
       NULL::text AS username, v.encrypted_secret AS secret_value,
       NULL::text AS secret_preview, NULL::text AS login_path, p.service_port AS port,
       p.expires_at, (p.is_active AND b.is_active AND b.revoked_at IS NULL) AS is_active,
       '{}'::jsonb AS metadata_json, p.current_version,p.record_version,
       b.allowed_capabilities,p.created_at,p.updated_at
FROM target_device_profiles d CROSS JOIN credential_profiles p
JOIN LATERAL target_credential_grant(p.id,d.target_id) b ON true
JOIN credential_profile_versions v ON v.profile_id=p.id AND v.version=p.current_version;

CREATE VIEW device_request_collections AS
SELECT c.id,d.target_id AS device_target_id,d.target_id,c.target_id AS home_target_id,
       c.name,c.format,c.payload_sha256 AS document_sha256,c.encrypted_payload,
       c.metadata_json || jsonb_build_object(
           'request_count',c.request_count,
           'state_changing_request_count',c.potentially_mutating_request_count,
           'document_sha256',c.payload_sha256
       ) AS summary_json,
       c.is_active,c.created_at,c.updated_at
FROM target_device_profiles d JOIN request_collections c
  ON target_collection_visible(c.id,d.target_id);
"""

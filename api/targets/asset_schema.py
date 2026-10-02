"""One target inventory; legacy device routes project host targets and their profile."""

ASSET_MIGRATION = "unified_target_assets_v1"

ASSET_SCHEMA_SQL = r"""
ALTER TABLE targets ADD COLUMN IF NOT EXISTS asset_owner_id UUID REFERENCES targets(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_targets_asset_owner ON targets(asset_owner_id);
ALTER TABLE targets ADD CONSTRAINT targets_asset_not_self CHECK (asset_owner_id IS NULL OR asset_owner_id <> id);

CREATE OR REPLACE FUNCTION target_asset_locator(value text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE authority text; locator text;
BEGIN
    IF value !~* '^(https?|host)://' THEN RETURN NULL; END IF;
    authority := split_part(split_part(split_part(regexp_replace(value, '^[A-Za-z]+://', ''), '/', 1), '?', 1), '#', 1);
    IF authority LIKE '%@%' THEN RETURN NULL; END IF;
    IF left(authority, 1) = '[' THEN
        locator := split_part(substring(authority FROM 2), ']', 1);
    ELSE
        locator := split_part(authority, ':', 1);
    END IF;
    locator := lower(rtrim(locator, '.'));
    IF locator = '' THEN RETURN NULL; END IF;
    BEGIN
        RETURN host(locator::inet);
    EXCEPTION WHEN invalid_text_representation THEN
        RETURN locator;
    END;
END $$;

CREATE OR REPLACE FUNCTION target_asset_url(locator text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT 'host://' || CASE WHEN strpos(locator, ':') > 0 THEN '[' || locator || ']' ELSE locator END
$$;

CREATE TABLE target_device_profiles (
    target_id UUID PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
    device_class TEXT NOT NULL DEFAULT 'generic',
    manufacturer TEXT, model TEXT, firmware_version TEXT, stable_identity TEXT,
    identity_confidence TEXT NOT NULL DEFAULT 'low'
        CHECK (identity_confidence IN ('low','medium','high','verified')),
    environment TEXT NOT NULL DEFAULT 'production',
    policy_id UUID REFERENCES device_policies(id) ON DELETE SET NULL,
    sensor_affinity TEXT,
    last_scanned_at TIMESTAMPTZ,
    last_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    last_score INTEGER, last_grade TEXT,
    active_findings_count INTEGER NOT NULL DEFAULT 0,
    locator_generation INTEGER NOT NULL DEFAULT 1 CHECK (locator_generation >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION target_asset_owner(value uuid) RETURNS uuid
LANGUAGE sql STABLE STRICT AS $$
    SELECT COALESCE(asset_owner_id, id) FROM targets WHERE id=value
$$;

-- A historical relationship is not authority to send credentials to a reused locator.
CREATE OR REPLACE FUNCTION target_asset_access_owner(value uuid) RETURNS uuid
LANGUAGE sql STABLE STRICT AS $$
    SELECT CASE WHEN owner.id IS NOT NULL AND owner.is_active AND member.is_active
                      AND target_asset_locator(owner.url)=target_asset_locator(member.url)
                THEN owner.id ELSE member.id END
    FROM targets member LEFT JOIN targets owner ON owner.id=member.asset_owner_id
    WHERE member.id=value
$$;
"""

ASSET_VIEW_SQL = r"""
CREATE VIEW device_targets AS
SELECT t.id, t.name, target_asset_locator(t.url) AS primary_locator,
       p.device_class, p.manufacturer, p.model, p.firmware_version,
       p.stable_identity, p.identity_confidence, p.environment, p.policy_id,
       p.sensor_affinity, t.metadata_json, p.last_scanned_at, p.last_scan_id,
       p.last_score, p.last_grade, p.active_findings_count, p.locator_generation,
       t.is_active, t.created_at, GREATEST(t.updated_at, p.updated_at) AS updated_at
FROM targets t JOIN target_device_profiles p ON p.target_id=t.id;

CREATE OR REPLACE FUNCTION write_device_target_view() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE owner_id uuid; locator text; saved targets%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM targets WHERE id=OLD.id;
        RETURN OLD;
    END IF;
    locator := target_asset_locator(target_asset_url(NEW.primary_locator));
    IF locator IS NULL THEN RAISE EXCEPTION 'device locator is invalid' USING ERRCODE='22023'; END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT id INTO owner_id FROM targets WHERE canonical_key='host:' || locator FOR UPDATE;
        IF owner_id IS NOT NULL AND EXISTS (SELECT 1 FROM target_device_profiles WHERE target_id=owner_id) THEN
            RAISE EXCEPTION 'device profile already exists for this target' USING ERRCODE='23505';
        END IF;
        INSERT INTO targets (id,url,name,discovery_source,metadata_json,is_active,created_at,updated_at)
        VALUES (COALESCE(owner_id,NEW.id,gen_random_uuid()),target_asset_url(locator),COALESCE(NEW.name,locator),
                'host',COALESCE(NEW.metadata_json,'{}'::jsonb),COALESCE(NEW.is_active,true),NOW(),NOW())
        ON CONFLICT (canonical_key) DO UPDATE SET
            name=EXCLUDED.name, metadata_json=targets.metadata_json || EXCLUDED.metadata_json,
            is_active=EXCLUDED.is_active,updated_at=NOW()
        RETURNING * INTO saved;
        NEW.id := saved.id;
        INSERT INTO target_device_profiles (
            target_id,device_class,manufacturer,model,firmware_version,stable_identity,
            identity_confidence,environment,policy_id,sensor_affinity,locator_generation
        ) VALUES (NEW.id,COALESCE(NEW.device_class,'generic'),NEW.manufacturer,NEW.model,
            NEW.firmware_version,NEW.stable_identity,COALESCE(NEW.identity_confidence,'low'),
            COALESCE(NEW.environment,'production'),NEW.policy_id,NEW.sensor_affinity,
            COALESCE(NEW.locator_generation,1));
    ELSE
        IF NEW.id <> OLD.id THEN RAISE EXCEPTION 'target identity is immutable' USING ERRCODE='22023'; END IF;
        UPDATE targets SET name=NEW.name,url=target_asset_url(locator),metadata_json=NEW.metadata_json,
            is_active=NEW.is_active,updated_at=NOW() WHERE id=OLD.id RETURNING * INTO saved;
        UPDATE target_device_profiles SET device_class=NEW.device_class,manufacturer=NEW.manufacturer,
            model=NEW.model,firmware_version=NEW.firmware_version,stable_identity=NEW.stable_identity,
            identity_confidence=NEW.identity_confidence,environment=NEW.environment,policy_id=NEW.policy_id,
            sensor_affinity=NEW.sensor_affinity,last_scanned_at=NEW.last_scanned_at,last_scan_id=NEW.last_scan_id,
            last_score=NEW.last_score,last_grade=NEW.last_grade,active_findings_count=NEW.active_findings_count,
            locator_generation=NEW.locator_generation,updated_at=NOW() WHERE target_id=OLD.id;
    END IF;
    SELECT * INTO NEW FROM device_targets WHERE id=saved.id;
    RETURN NEW;
END $$;
CREATE TRIGGER device_target_compatibility_write
INSTEAD OF INSERT OR UPDATE OR DELETE ON device_targets
FOR EACH ROW EXECUTE FUNCTION write_device_target_view();

CREATE OR REPLACE FUNCTION attach_target_asset_owner() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE locator text; owner_id uuid;
BEGIN
    IF NEW.url !~* '^https?://' OR NEW.discovery_source='model-intake' THEN RETURN NEW; END IF;
    locator := target_asset_locator(NEW.url);
    IF locator IS NULL THEN RETURN NEW; END IF;
    INSERT INTO targets(url,name,discovery_source,root_domain,metadata_json)
    VALUES(target_asset_url(locator),locator,'host',NEW.root_domain,
           jsonb_build_object('environment',COALESCE(NEW.metadata_json->>'environment',NEW.metadata_json->>'cohort','production')))
    ON CONFLICT(canonical_key) DO UPDATE SET url=targets.url
    RETURNING id INTO owner_id;
    UPDATE targets SET asset_owner_id=owner_id WHERE id=NEW.id AND asset_owner_id IS DISTINCT FROM owner_id;
    RETURN NEW;
END $$;
CREATE TRIGGER target_asset_membership
AFTER INSERT OR UPDATE OF url ON targets
FOR EACH ROW EXECUTE FUNCTION attach_target_asset_owner();

CREATE OR REPLACE FUNCTION enforce_device_target_alias() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.device_target_id IS NOT NULL THEN
        IF NEW.target_id IS NULL THEN NEW.target_id := NEW.device_target_id;
        ELSIF NEW.target_id <> NEW.device_target_id
              AND target_asset_owner(NEW.target_id) IS DISTINCT FROM NEW.device_target_id THEN
            RAISE EXCEPTION 'device and target references name different assets' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;

-- Observed application origins become service records under the asset, not another inventory.
CREATE OR REPLACE FUNCTION link_device_service_origin() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE locator text;
BEGIN
    IF NEW.web_origin IS NULL OR NEW.web_origin !~* '^https?://' THEN RETURN NEW; END IF;
    SELECT target_asset_locator(url) INTO locator FROM targets WHERE id=NEW.device_target_id;
    IF locator IS NULL OR target_asset_locator(NEW.web_origin) IS DISTINCT FROM locator THEN RETURN NEW; END IF;
    INSERT INTO targets(url,name,discovery_source,asset_owner_id)
    VALUES(NEW.web_origin,NEW.web_origin,'device-service',NEW.device_target_id)
    ON CONFLICT(canonical_key) DO NOTHING;
    RETURN NEW;
END $$;
CREATE TRIGGER device_service_asset_origin
AFTER INSERT OR UPDATE OF web_origin ON device_services
FOR EACH ROW EXECUTE FUNCTION link_device_service_origin();
"""

"""Canonical target constraints shared by conversion and versioned repairs."""
from typing import Any

async def _install_host_key(conn: Any) -> None:
    """Install host canonicalization explicitly; never rewrite stored SQL source text."""
    await conn.execute(r"""
        CREATE OR REPLACE FUNCTION targets_set_canonical_key() RETURNS trigger AS $$
        DECLARE raw TEXT; authority TEXT; host_part TEXT; port_part TEXT; scheme_part TEXT;
        BEGIN
            raw := lower(btrim(COALESCE(NEW.url, '')));
            IF lower(COALESCE(NEW.discovery_source, '')) = 'host' THEN
                host_part := regexp_replace(raw, '^host://', '');
                host_part := regexp_replace(host_part, '[/?#].*$', '');
                host_part := btrim(host_part, '[]');
                IF host_part = '' THEN RAISE EXCEPTION 'invalid host target locator'; END IF;
                NEW.url := CASE WHEN position(':' in host_part) > 0
                    THEN 'host://[' || host_part || ']' ELSE 'host://' || host_part END;
                NEW.canonical_key := 'host:' || host_part;
                IF NOT NEW.is_active THEN
                    NEW.url := NEW.url || '#retired=' || NEW.id::text;
                    NEW.canonical_key := NEW.canonical_key || ':retired:' || NEW.id::text;
                END IF;
                RETURN NEW;
            END IF;
            scheme_part := substring(raw FROM '^(https?)://');
            raw := regexp_replace(raw, '^https?://', '');
            IF lower(COALESCE(NEW.discovery_source, '')) = 'model-intake' THEN
                NEW.canonical_key := 'artifact:' || rtrim(raw, '/');
            ELSE
                authority := regexp_replace(raw, '[/?#].*$', '');
                authority := regexp_replace(authority, '^.*@', '');
                IF authority ~ '^\[[^]]+\]' THEN
                    host_part := substring(authority FROM '^\[([^]]+)\]');
                    port_part := substring(authority FROM '^\[[^]]+\]:([0-9]+)$');
                ELSE
                    host_part := regexp_replace(authority, ':[0-9]+$', '');
                    port_part := substring(authority FROM ':([0-9]+)$');
                END IF;
                IF port_part IS NULL OR (scheme_part='https' AND port_part='443')
                   OR (scheme_part='http' AND port_part='80')
                   OR (scheme_part IS NULL AND port_part IN ('80','443')) THEN
                    port_part := NULL;
                END IF;
                NEW.canonical_key := 'web:' || rtrim(host_part, '.') || COALESCE(':' || port_part, '');
            END IF;
            RETURN NEW;
        END; $$ LANGUAGE plpgsql;
        DROP TRIGGER IF EXISTS trg_targets_canonical_key ON targets;
        CREATE TRIGGER trg_targets_canonical_key
            BEFORE INSERT OR UPDATE OF url, discovery_source, is_active ON targets
            FOR EACH ROW EXECUTE FUNCTION targets_set_canonical_key();
    """)

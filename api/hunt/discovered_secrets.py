"""Discovered secrets: values ShakerScan found on a target, kept for later investigations by
reference (``secret://<id>``), never shown to a planner.

A Hunt capability output withholds credential-shaped values behind ``[withheld:n]`` markers and
seals them on its action row for that Hunt only (runtime/hunt_http_exchange.py). This store keeps
each such value per target, encrypted under the same key as credential profiles, so a later Hunt of
the same target can send it by reference in an ``http.request`` binding: the worker resolves the
reference at send time, under the action's authority and scope, and records the use.

Rules:
- The value is stored once per target (deduplicated by a keyed digest), only as Fernet ciphertext,
  and never written to any other table, log, receipt or output. Without the stable installation
  key nothing is stored.
- A reference resolves only for a live Hunt of the secret's own target, while the row is
  ``active`` and unexpired. Using it on another target needs an operator grant (not in this
  version: refused with ``secret_target_mismatch``).
- Repeated sightings refresh ``last_seen_at``, ``seen_count`` and the expiry; a revoked row stays
  revoked (an operator decision), an expired one becomes active again.
- Every resolution is appended to ``discovered_secret_uses`` with the action and destination host.

Kept free of route imports so the startup migration can install the schema.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Iterable, Mapping
import uuid

KINDS = ("password", "api_key", "bearer_token", "jwt", "private_key", "connection_url", "cookie", "other")
STATES = ("active", "revoked_by_operator", "expired", "superseded")
SOURCE_KINDS = ("hunt_action", "scan_finding", "retest")
DEFAULT_TTL_DAYS = 30
MAX_TTL_DAYS = 365
MAX_VALUE_CHARS = 8_192
MAX_LABEL_CHARS = 120
MAX_LIST = 200
MAX_PER_SIGHTING = 64
# Rows kept per target; past it the least recently seen inactive, then active, rows go first.
MAX_PER_TARGET = 2_000
# An expired or revoked row's ciphertext is deleted this long after it stopped being usable.
RETAIN_AFTER_EXPIRY_DAYS = 30

SECRET_REF_PATTERN = (
    r"^secret://[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
SECRET_REF_RE = re.compile(SECRET_REF_PATTERN)

# Refusals a planner or operator sees; never the value, never which part failed beyond this.
SECRET_REFERENCE_INVALID = "secret_reference_invalid"
SECRET_UNAVAILABLE = "secret_unavailable"
SECRET_TARGET_MISMATCH = "secret_target_mismatch"
SECRET_NOT_ACTIVE = "secret_not_active"
SECRET_EXPIRED = "secret_expired"


def _values(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


# Additive and idempotent: installed by the unified startup migration
# (api/targets/asset_migration.py) and, with the same definition, by db/init.sql.
DISCOVERED_SECRETS_SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS discovered_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    value_ciphertext TEXT NOT NULL CHECK (value_ciphertext LIKE 'enc:fernet:%'),
    value_digest TEXT NOT NULL CHECK (value_digest ~ '^[0-9a-f]{{64}}$'),
    kind TEXT NOT NULL CHECK (kind IN ({_values(KINDS)})),
    label TEXT NOT NULL DEFAULT '' CHECK (length(label) <= {MAX_LABEL_CHARS}),
    length INTEGER NOT NULL CHECK (length BETWEEN 1 AND {MAX_VALUE_CHARS}),
    source JSONB NOT NULL CHECK (jsonb_typeof(source) = 'object'
        AND source->>'kind' IN ({_values(SOURCE_KINDS)})),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    seen_count INTEGER NOT NULL DEFAULT 1 CHECK (seen_count > 0),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ({_values(STATES)})),
    state_changed_by TEXT CHECK (state_changed_by IS NULL OR length(state_changed_by) <= 200),
    state_changed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT discovered_secrets_target_value_unique UNIQUE (target_id, value_digest)
);
CREATE INDEX IF NOT EXISTS idx_discovered_secrets_target
    ON discovered_secrets(target_id, last_seen_at DESC);
CREATE TABLE IF NOT EXISTS discovered_secret_uses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id UUID NOT NULL REFERENCES discovered_secrets(id) ON DELETE CASCADE,
    hunt_run_id UUID REFERENCES hunt_runs(id) ON DELETE SET NULL,
    action_id UUID REFERENCES hunt_actions(id) ON DELETE SET NULL,
    destination_host TEXT NOT NULL DEFAULT '' CHECK (length(destination_host) <= 255),
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_discovered_secret_uses_secret
    ON discovered_secret_uses(secret_id, used_at DESC);
CREATE INDEX IF NOT EXISTS idx_discovered_secret_uses_run
    ON discovered_secret_uses(hunt_run_id);
"""


class DiscoveredSecretError(ValueError):
    """A refused reference; ``reason`` is one of the SECRET_* codes, safe to show."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _secret_store() -> Any:
    try:
        import secret_store
    except ModuleNotFoundError:  # package layout in host-side tests
        from .. import secret_store
    return secret_store


def value_digest(value: str) -> str | None:
    """HMAC-SHA256 under this installation's derived key: the per-target deduplication key.
    ``None`` without a stable key (nothing is stored then). Not shown anywhere: the scrypt
    fingerprint (capabilities/secret_material.py) stays the public identity of a value."""
    key = _secret_store().derived_installation_key("discovered-secret-dedup")
    if not key:
        return None
    return hmac.new(key, str(value).encode("utf-8"), hashlib.sha256).hexdigest()


_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*$")
_URL_CREDENTIAL_RE = re.compile(r"^[a-z][a-z0-9+.-]{1,20}://[^/\s:@]+:[^@\s]+@", re.IGNORECASE)
_API_KEY_PREFIXES = (
    "sk_live_", "sk_test_", "rk_live_", "pk_live_", "AKIA", "ASIA", "ghp_", "gho_", "ghs_",
    "github_pat_", "glpat-", "xoxb-", "xoxp-", "AIza", "SG.", "sk-",
)


def classify(value: str, label: str = "") -> str:
    """The kind of a value, by its shape (and the field name it was found under, when known)."""
    text = str(value).strip()
    name = label.lower()
    if text.startswith("-----BEGIN") and "PRIVATE KEY" in text:
        return "private_key"
    if _JWT_RE.fullmatch(text):
        return "jwt"
    if _URL_CREDENTIAL_RE.match(text):
        return "connection_url"
    if text.startswith(_API_KEY_PREFIXES):
        return "api_key"
    if text.lower().startswith("bearer "):
        return "bearer_token"
    if "cookie" in name or "session" in name:
        return "cookie"
    if "pass" in name or "pwd" in name:
        return "password"
    if "token" in name:
        return "bearer_token"
    if "key" in name or "secret" in name:
        return "api_key"
    return "other"


def _target_uuid(target_id: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(target_id))
    except (TypeError, ValueError):
        return None


async def record_discovered(
    conn: Any, *, target_id: Any, values: Iterable[tuple[str, str]], source: Mapping[str, Any],
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> dict[str, int]:
    """Upsert ``(value, label)`` pairs found on a target: ``{"stored": new, "refreshed": seen}``.

    Runs inside the caller's transaction, under a savepoint: a failure here (a device target
    with no ``targets`` row, no encryption key) never undoes what the caller wrote. Values outside
    1..MAX_VALUE_CHARS are skipped; at most MAX_PER_SIGHTING per call."""
    counts = {"stored": 0, "refreshed": 0}
    target = _target_uuid(target_id)
    if target is None or str(source.get("kind")) not in SOURCE_KINDS:
        return counts
    store = _secret_store()
    clean_source = {
        key: str(source[key])[:200] for key in ("kind", "id", "hunt_id", "resource", "location")
        if source.get(key) is not None
    }
    ttl = max(1, min(int(ttl_days), MAX_TTL_DAYS))
    try:
        async with conn.transaction():
            if not await conn.fetchval("SELECT 1 FROM targets WHERE id=$1", target):
                return counts
            for value, label in list(values)[:MAX_PER_SIGHTING]:
                text = str(value)
                if not 1 <= len(text) <= MAX_VALUE_CHARS:
                    continue
                digest = value_digest(text)
                if digest is None:
                    return counts
                # A sighting extends the expiry and revives an expired row only while no operator
                # has decided about the row (revoked, or set its expiry): that decision stands.
                refreshed = await conn.fetchval(
                    """UPDATE discovered_secrets SET last_seen_at=NOW(), seen_count=seen_count+1,
                        expires_at=CASE WHEN state_changed_by IS NULL
                            THEN GREATEST(expires_at, NOW() + make_interval(days => $3)) ELSE expires_at END,
                        state=CASE WHEN state='expired' AND state_changed_by IS NULL THEN 'active'
                            ELSE state END
                    WHERE target_id=$1 AND value_digest=$2 RETURNING id""",
                    target, digest, ttl,
                )
                if refreshed:
                    counts["refreshed"] += 1
                    continue
                try:
                    ciphertext = store.encrypt_secret(text)
                except Exception:
                    return counts  # no encryption key: never stored in clear
                if not str(ciphertext or "").startswith("enc:fernet:"):
                    return counts
                clean_label = str(label or "")[:MAX_LABEL_CHARS]
                inserted = await conn.fetchval(
                    """INSERT INTO discovered_secrets(target_id, value_ciphertext, value_digest, kind,
                        label, length, source, expires_at)
                    VALUES($1,$2,$3,$4,$5,$6,$7::jsonb, NOW() + make_interval(days => $8))
                    ON CONFLICT (target_id, value_digest) DO NOTHING RETURNING id""",
                    target, ciphertext, digest, classify(text, clean_label), clean_label, len(text),
                    json.dumps(clean_source), ttl,
                )
                counts["stored" if inserted else "refreshed"] += 1
            if counts["stored"]:
                await _cap_target(conn, target)
    except Exception:
        return {"stored": 0, "refreshed": 0}
    return counts


async def _cap_target(conn: Any, target: uuid.UUID) -> None:
    await conn.execute(
        """DELETE FROM discovered_secrets WHERE id IN (
            SELECT id FROM discovered_secrets WHERE target_id=$1
            ORDER BY (state='active' AND expires_at > NOW()) DESC, last_seen_at DESC, id
            OFFSET $2)""",
        target, MAX_PER_TARGET,
    )


async def values_used_by_hunt(conn: Any, hunt_run_id: Any, *, limit: int = 64) -> list[str]:
    """The values this Hunt sent by ``secret://`` reference, most recent first: the worker
    withholds them wherever a later response of the Hunt echoes them, as it does for the values
    the Hunt sealed itself. Worker-private; an unreadable row contributes nothing."""
    rows = await conn.fetch(
        """SELECT s.value_ciphertext FROM discovered_secrets s
        JOIN (SELECT secret_id, max(used_at) AS used_at FROM discovered_secret_uses
              WHERE hunt_run_id=$1 GROUP BY secret_id) u ON u.secret_id=s.id
        ORDER BY u.used_at DESC LIMIT $2""",
        uuid.UUID(str(hunt_run_id)), max(1, int(limit)),
    )
    values = []
    for row in rows:
        try:
            values.append(str(_secret_store().decrypt_secret(str(row["value_ciphertext"]))))
        except Exception:
            continue
    return values


async def reference_for(conn: Any, *, target_id: Any, value: str) -> str | None:
    """The ``secret://`` reference of a value kept for a target, or None."""
    target = _target_uuid(target_id)
    digest = value_digest(value)
    if target is None or digest is None:
        return None
    found = await conn.fetchval(
        "SELECT id FROM discovered_secrets WHERE target_id=$1 AND value_digest=$2", target, digest)
    return f"secret://{found}" if found else None


def parse_reference(reference: Any) -> uuid.UUID:
    text = str(reference or "")
    if not SECRET_REF_RE.fullmatch(text):
        raise DiscoveredSecretError(
            SECRET_REFERENCE_INVALID, "secret reference must be secret://<id>")
    return uuid.UUID(text.removeprefix("secret://"))


async def resolve_for_hunt(
    conn: Any, *, reference: Any, target_id: Any, hunt_run_id: Any, action_id: Any,
    destination_host: str = "",
) -> str:
    """The value behind ``secret://<id>`` for a Hunt action on ``target_id``, recording the use.

    The caller has already checked that the Hunt is live and holds the action's reservation.
    Every refusal names a reason code and carries no value."""
    secret_id = parse_reference(reference)
    row = await conn.fetchrow(
        "SELECT target_id, value_ciphertext, state, expires_at FROM discovered_secrets WHERE id=$1",
        secret_id,
    )
    if row is None:
        raise DiscoveredSecretError(SECRET_UNAVAILABLE, "secret reference is unavailable")
    if str(row["target_id"]) != str(_target_uuid(target_id)):
        raise DiscoveredSecretError(
            SECRET_TARGET_MISMATCH,
            "secret reference belongs to another target; an operator grant is required")
    if row["state"] != "active":
        raise DiscoveredSecretError(SECRET_NOT_ACTIVE, f"secret reference is {row['state']}")
    if row["expires_at"] <= datetime.now(timezone.utc):
        raise DiscoveredSecretError(SECRET_EXPIRED, "secret reference has expired")
    try:
        value = _secret_store().decrypt_secret(str(row["value_ciphertext"]))
    except Exception:
        raise DiscoveredSecretError(SECRET_UNAVAILABLE, "secret reference is unavailable") from None
    await conn.execute(
        """INSERT INTO discovered_secret_uses(secret_id, hunt_run_id, action_id, destination_host)
        VALUES($1,$2,$3,$4)""",
        secret_id, uuid.UUID(str(hunt_run_id)), uuid.UUID(str(action_id)),
        str(destination_host or "")[:255],
    )
    return str(value)


def _public(row: Mapping[str, Any]) -> dict[str, Any]:
    source = row["source"]
    if isinstance(source, str):
        source = json.loads(source)
    return {
        "ref": f"secret://{row['id']}",
        "kind": row["kind"],
        "label": row["label"],
        "length": row["length"],
        "source": {key: source.get(key) for key in ("kind", "id", "hunt_id") if source.get(key)},
        "first_seen_at": row["first_seen_at"].isoformat(),
        "last_seen_at": row["last_seen_at"].isoformat(),
        "seen_count": row["seen_count"],
        "state": row["state"],
        "expires_at": row["expires_at"].isoformat(),
        "uses": row["uses"],
        "last_used_at": row["last_used_at"].isoformat() if row["last_used_at"] else None,
    }


async def list_for_target(
    conn: Any, target_id: Any, *, usable_only: bool = False, limit: int = MAX_LIST,
) -> list[dict[str, Any]]:
    """Metadata only (reference, kind, label, length, source, sightings, state, uses), newest
    sighting first. ``usable_only``: active and unexpired, what a Hunt can bind."""
    target = _target_uuid(target_id)
    if target is None:
        return []
    rows = await conn.fetch(
        f"""SELECT s.id, s.kind, s.label, s.length, s.source, s.first_seen_at, s.last_seen_at,
            s.seen_count, s.state, s.expires_at,
            (SELECT count(*) FROM discovered_secret_uses u WHERE u.secret_id=s.id) AS uses,
            (SELECT max(used_at) FROM discovered_secret_uses u WHERE u.secret_id=s.id) AS last_used_at
        FROM discovered_secrets s WHERE s.target_id=$1
        {"AND s.state='active' AND s.expires_at > NOW()" if usable_only else ""}
        ORDER BY s.last_seen_at DESC, s.id LIMIT $2""",
        target, max(1, min(int(limit), MAX_LIST)),
    )
    return [_public(row) for row in rows]


async def set_state(
    conn: Any, *, target_id: Any, secret_id: Any, state: str, actor: str,
) -> bool:
    """An operator's revoke (``revoked_by_operator``) or reactivation (``active``)."""
    if state not in {"active", "revoked_by_operator"}:
        raise ValueError("state must be active or revoked_by_operator")
    updated = await conn.fetchval(
        """UPDATE discovered_secrets SET state=$3, state_changed_by=$4, state_changed_at=NOW()
        WHERE id=$1 AND target_id=$2 AND state IN ('active','revoked_by_operator','expired')
        RETURNING id""",
        uuid.UUID(str(secret_id)), _target_uuid(target_id), state, str(actor)[:200],
    )
    return bool(updated)


async def set_expiry(
    conn: Any, *, target_id: Any, secret_id: Any, days: int, actor: str,
) -> bool:
    """Expire ``days`` from now (1..MAX_TTL_DAYS)."""
    days = int(days)
    if not 1 <= days <= MAX_TTL_DAYS:
        raise ValueError(f"days must be between 1 and {MAX_TTL_DAYS}")
    updated = await conn.fetchval(
        """UPDATE discovered_secrets SET expires_at=NOW() + make_interval(days => $3),
            state_changed_by=$4, state_changed_at=NOW()
        WHERE id=$1 AND target_id=$2 RETURNING id""",
        uuid.UUID(str(secret_id)), _target_uuid(target_id), days, str(actor)[:200],
    )
    return bool(updated)


async def purge_target(conn: Any, *, target_id: Any) -> int:
    """Delete every discovered secret of a target (and, by cascade, its use records)."""
    result = await conn.execute(
        "DELETE FROM discovered_secrets WHERE target_id=$1", _target_uuid(target_id))
    return int(str(result).rsplit(" ", 1)[-1] or 0)


async def expire_due(conn: Any) -> dict[str, int]:
    """The sweeper: mark active rows past their expiry ``expired`` (resolution checks the time
    itself), and delete the ciphertext of rows unusable for RETAIN_AFTER_EXPIRY_DAYS."""
    expired = await conn.execute(
        "UPDATE discovered_secrets SET state='expired' WHERE state='active' AND expires_at <= NOW()")
    deleted = await conn.execute(
        """DELETE FROM discovered_secrets WHERE state <> 'active'
        AND GREATEST(expires_at, COALESCE(state_changed_at, expires_at))
            <= NOW() - make_interval(days => $1)""",
        RETAIN_AFTER_EXPIRY_DAYS,
    )
    return {"expired": int(str(expired).rsplit(" ", 1)[-1] or 0),
            "deleted": int(str(deleted).rsplit(" ", 1)[-1] or 0)}

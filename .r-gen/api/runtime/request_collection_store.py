"""Durable V2 request-collection environments, bindings, and selections."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Any, Mapping, Sequence
import urllib.parse


REQUEST_COLLECTION_RUNTIME_MIGRATION = "v2_request_collection_runtime_v1"
REPLAY_POLICIES = frozenset({
    "discovery_only",
    "safe_reads",
    "safe_authentication",
    "confirmed_active",
})
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


REQUEST_COLLECTION_RUNTIME_SCHEMA_SQL = r"""
ALTER TABLE request_collection_requests
ADD COLUMN IF NOT EXISTS tags_json JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE request_collection_requests
ADD COLUMN IF NOT EXISTS content_type TEXT;
ALTER TABLE request_collection_requests
ADD COLUMN IF NOT EXISTS body_field_names_json JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE TABLE IF NOT EXISTS request_collection_environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id UUID NOT NULL REFERENCES request_collections(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL CHECK (encrypted_payload LIKE 'enc:fernet:%'),
    payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    variable_count INTEGER NOT NULL DEFAULT 0 CHECK (variable_count >= 0),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata_json) = 'object'),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT request_collection_environments_name_unique
        UNIQUE (collection_id, name),
    CONSTRAINT request_collection_environments_identity_unique
        UNIQUE (id, collection_id)
);
CREATE INDEX IF NOT EXISTS idx_request_collection_environments_active
ON request_collection_environments(collection_id, is_active, lower(name));

CREATE TABLE IF NOT EXISTS request_collection_bindings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id UUID NOT NULL REFERENCES request_collections(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('web','api','device')),
    target_id UUID NOT NULL,
    allowed_origins JSONB NOT NULL
        CHECK (jsonb_typeof(allowed_origins) = 'array' AND jsonb_array_length(allowed_origins) > 0),
    environment_id UUID,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT request_collection_bindings_target_unique
        UNIQUE (collection_id, target_kind, target_id),
    CONSTRAINT request_collection_bindings_identity_unique
        UNIQUE (id, collection_id),
    CONSTRAINT request_collection_bindings_environment_fk
        FOREIGN KEY (environment_id, collection_id)
        REFERENCES request_collection_environments(id, collection_id)
);
CREATE INDEX IF NOT EXISTS idx_request_collection_bindings_target
ON request_collection_bindings(target_kind, target_id, is_active);

CREATE TABLE IF NOT EXISTS request_collection_selections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id UUID NOT NULL REFERENCES request_collections(id) ON DELETE CASCADE,
    binding_id UUID NOT NULL,
    name TEXT NOT NULL,
    replay_policy TEXT NOT NULL CHECK (
        replay_policy IN ('discovery_only','safe_reads','safe_authentication','confirmed_active')
    ),
    selector_json JSONB NOT NULL CHECK (jsonb_typeof(selector_json) = 'object'),
    selection_digest TEXT NOT NULL CHECK (selection_digest ~ '^[0-9a-f]{64}$'),
    selected_request_count INTEGER NOT NULL DEFAULT 0 CHECK (selected_request_count >= 0),
    selected_mutating_count INTEGER NOT NULL DEFAULT 0 CHECK (selected_mutating_count >= 0),
    is_active BOOLEAN NOT NULL DEFAULT true,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT request_collection_selections_binding_fk
        FOREIGN KEY (binding_id, collection_id)
        REFERENCES request_collection_bindings(id, collection_id)
        ON DELETE CASCADE
);
ALTER TABLE request_collection_selections
DROP CONSTRAINT IF EXISTS request_collection_selections_name_unique;
ALTER TABLE request_collection_selections
ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
-- The legacy schema had only is_active, so an inactive row may have been
-- explicitly revoked. Preserve the safe meaning across the upgrade. New
-- superseded revisions are retired without revoked_at by the versioned API.
UPDATE request_collection_selections
SET revoked_at = COALESCE(revoked_at, updated_at, NOW())
WHERE is_active=false AND revoked_at IS NULL;
ALTER TABLE request_collection_selections
DROP CONSTRAINT IF EXISTS request_collection_selections_replay_policy_check;
ALTER TABLE request_collection_selections
ADD CONSTRAINT request_collection_selections_replay_policy_check CHECK (
    replay_policy IN ('discovery_only','safe_reads','safe_authentication','confirmed_active')
);
CREATE INDEX IF NOT EXISTS idx_request_collection_selections_active
ON request_collection_selections(collection_id, binding_id, is_active, lower(name));
WITH ranked_current_selections AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY binding_id, lower(name)
               ORDER BY updated_at DESC, created_at DESC, id DESC
           ) AS current_rank
    FROM request_collection_selections
    WHERE is_active=true AND revoked_at IS NULL
)
UPDATE request_collection_selections selection
SET is_active=false, updated_at=NOW()
FROM ranked_current_selections ranked
WHERE selection.id=ranked.id AND ranked.current_rank > 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_request_collection_selections_current_name
ON request_collection_selections(binding_id, lower(name))
WHERE is_active=true AND revoked_at IS NULL;

INSERT INTO request_collection_bindings (
    collection_id, target_kind, target_id, allowed_origins
)
SELECT rc.id,
       'web',
       rc.target_id,
       jsonb_build_array(lower(substring(t.url FROM '^(https?://[^/?#]+)')))
FROM request_collections rc
JOIN targets t ON t.id=rc.target_id
WHERE rc.target_id IS NOT NULL
  AND substring(t.url FROM '^(https?://[^/?#]+)') IS NOT NULL
ON CONFLICT (collection_id, target_kind, target_id) DO NOTHING;

INSERT INTO app_schema_migrations(name)
VALUES ('v2_request_collection_runtime_v1')
ON CONFLICT (name) DO NOTHING;
"""


class RequestCollectionContractError(ValueError):
    """A collection environment, binding, or selection is unsafe or ambiguous."""


def canonical_collection_origin(value: Any) -> str:
    candidate = str(value or "").strip()
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise RequestCollectionContractError(
            "collection binding origins must be absolute HTTP(S) origins"
        )
    if (
        parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RequestCollectionContractError(
            "collection binding origins cannot contain credentials, paths, queries, or fragments"
        )
    host = parsed.hostname.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        authority_host = host
    else:
        authority_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    try:
        port = parsed.port
    except ValueError as exc:
        raise RequestCollectionContractError(
            "collection binding origin port is invalid"
        ) from exc
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    authority = (
        authority_host
        if port in {None, default_port}
        else f"{authority_host}:{port}"
    )
    return f"{parsed.scheme.lower()}://{authority}"


def canonical_collection_origins(values: Sequence[Any]) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise RequestCollectionContractError(
            "collection binding requires at least one allowed origin"
        )
    if len(values) > 32:
        raise RequestCollectionContractError(
            "collection binding accepts at most 32 allowed origins"
        )
    return tuple(sorted(set(canonical_collection_origin(value) for value in values)))


def _bounded_strings(
    values: Sequence[Any], *, name: str, maximum: int, item_limit: int,
) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise RequestCollectionContractError(f"{name} must be a list")
    if len(values) > maximum:
        raise RequestCollectionContractError(f"{name} accepts at most {maximum} values")
    normalized = tuple(sorted(set(
        str(value or "").strip() for value in values if str(value or "").strip()
    )))
    if any(len(value) > item_limit for value in normalized):
        raise RequestCollectionContractError(f"{name} contains an oversized value")
    return normalized


@dataclass(frozen=True)
class RequestCollectionSelection:
    request_ids: tuple[str, ...] = ()
    folders: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    path_regex: str | None = None
    tags: tuple[str, ...] = ()
    safe_methods_only: bool = True
    max_requests: int = 500
    disposable_credentials: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_ids", _bounded_strings(
            self.request_ids, name="request_ids", maximum=2_000, item_limit=128,
        ))
        object.__setattr__(self, "folders", _bounded_strings(
            self.folders, name="folders", maximum=200, item_limit=500,
        ))
        methods = tuple(
            value.upper() for value in _bounded_strings(
                self.methods, name="methods", maximum=20, item_limit=16,
            )
        )
        if any(not re.fullmatch(r"[A-Z]{3,16}", method) for method in methods):
            raise RequestCollectionContractError("selection methods are invalid")
        object.__setattr__(self, "methods", methods)
        object.__setattr__(self, "tags", _bounded_strings(
            self.tags, name="tags", maximum=200, item_limit=120,
        ))
        if self.path_regex is not None:
            path_regex = str(self.path_regex).strip()
            if not path_regex or len(path_regex) > 500:
                raise RequestCollectionContractError("selection path_regex is invalid")
            if re.search(
                r"\\[1-9]|\(\?(?:[=!]|<[=!]|P=|\()|\([^)]*[+*][^)]*\)[+*{]",
                path_regex,
            ):
                raise RequestCollectionContractError(
                    "selection path_regex contains unsupported backtracking constructs"
                )
            try:
                re.compile(path_regex)
            except re.error as exc:
                raise RequestCollectionContractError(
                    "selection path_regex is invalid"
                ) from exc
            object.__setattr__(self, "path_regex", path_regex)
        if not isinstance(self.safe_methods_only, bool):
            raise RequestCollectionContractError(
                "selection safe_methods_only must be a boolean"
            )
        if not isinstance(self.disposable_credentials, bool):
            raise RequestCollectionContractError(
                "selection disposable_credentials must be a boolean"
            )
        try:
            maximum = int(self.max_requests)
        except (TypeError, ValueError) as exc:
            raise RequestCollectionContractError(
                "selection max_requests must be between 1 and 2000"
            ) from exc
        if isinstance(self.max_requests, bool) or not 1 <= maximum <= 2_000:
            raise RequestCollectionContractError(
                "selection max_requests must be between 1 and 2000"
            )
        object.__setattr__(self, "max_requests", maximum)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "RequestCollectionSelection":
        item = dict(value or {})
        unknown = set(item) - {
            "request_ids", "folders", "methods", "path_regex", "tags",
            "safe_methods_only", "max_requests", "limit",
            "disposable_credentials",
        }
        if unknown:
            raise RequestCollectionContractError(
                f"selection contains unsupported fields: {', '.join(sorted(unknown))}"
            )
        return cls(
            request_ids=tuple(item.get("request_ids") or ()),
            folders=tuple(item.get("folders") or ()),
            methods=tuple(item.get("methods") or ()),
            path_regex=item.get("path_regex"),
            tags=tuple(item.get("tags") or ()),
            safe_methods_only=item.get("safe_methods_only", True),
            max_requests=item.get("max_requests", item.get("limit", 500)),
            disposable_credentials=item.get("disposable_credentials", False),
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "request_ids": list(self.request_ids),
            "folders": list(self.folders),
            "methods": list(self.methods),
            "path_regex": self.path_regex,
            "tags": list(self.tags),
            "safe_methods_only": self.safe_methods_only,
            "max_requests": self.max_requests,
            "disposable_credentials": self.disposable_credentials,
        }


def request_collection_selection_digest(
    *,
    collection_id: Any,
    payload_sha256: str,
    binding_id: Any,
    allowed_origins: Sequence[Any],
    selector: RequestCollectionSelection,
    replay_policy: str,
    environment_sha256: str | None = None,
) -> str:
    policy = str(replay_policy or "").strip().lower()
    if policy not in REPLAY_POLICIES:
        raise RequestCollectionContractError("collection replay policy is invalid")
    payload_digest = str(payload_sha256 or "").strip().lower()
    if not _DIGEST_RE.fullmatch(payload_digest):
        raise RequestCollectionContractError("collection payload digest is invalid")
    environment_digest = str(environment_sha256 or "").strip().lower() or None
    if environment_digest is not None and not _DIGEST_RE.fullmatch(environment_digest):
        raise RequestCollectionContractError("collection environment digest is invalid")
    if policy not in {"confirmed_active", "safe_authentication"} and not selector.safe_methods_only:
        raise RequestCollectionContractError(
            "only confirmed_active selections may include state-changing methods"
        )
    if policy == "safe_authentication" and (
        not selector.disposable_credentials
        or selector.safe_methods_only
        or selector.max_requests > 5
        or selector.methods != ("POST",)
        or not selector.request_ids
    ):
        raise RequestCollectionContractError(
            "safe_authentication requires exact POST request IDs, disposable credentials, and a five-request ceiling"
        )
    material = {
        "schema_version": "request-collection-selection/v2",
        "collection_id": str(collection_id),
        "payload_sha256": payload_digest,
        "binding_id": str(binding_id),
        "allowed_origins": list(canonical_collection_origins(allowed_origins)),
        "environment_sha256": environment_digest,
        "selector": selector.public_dict(),
        "replay_policy": policy,
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class PostgresRequestCollectionStore:
    async def ensure_schema(self, conn: Any) -> None:
        await conn.execute(REQUEST_COLLECTION_RUNTIME_SCHEMA_SQL)

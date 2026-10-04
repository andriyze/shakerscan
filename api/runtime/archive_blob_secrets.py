"""Raw HTTP archive payloads are encrypted at rest and decrypted only when a raw view reads them.

Recorded traffic keeps request and response headers and bodies verbatim so raw HAR export and
replay stay possible, which means it carries Authorization headers, cookies and tokens. Each
payload is encrypted with the credential key before it reaches the evidence store, so neither
the inline JSONB nor an externalized file holds it in clear. The row keeps the plaintext digest,
so content-addressed deduplication is unchanged.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Callable, Mapping

try:
    from secret_store import SecretStoreUnavailable, decrypt_secret, encrypt_secret, encryption_enabled
    from evidence_storage import local_evidence_path, serialize_evidence_content
except ModuleNotFoundError:  # package import layout
    from api.secret_store import SecretStoreUnavailable, decrypt_secret, encrypt_secret, encryption_enabled
    from api.evidence_storage import local_evidence_path, serialize_evidence_content

SCHEMA = "http-archive-blob/encrypted-v1"
MIGRATION = "v2_http_archive_blob_encryption_v1"
_LOG = logging.getLogger(__name__)
_EMPTY = {"content_sha256": None, "size_bytes": 0, "storage_uri": None, "content": None, "externalized": False}


def envelope(raw: str) -> dict[str, str]:
    return {"schema_version": SCHEMA, "ciphertext": encrypt_secret(raw)}


def is_envelope(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("schema_version") == SCHEMA and "ciphertext" in value


def encrypting_store(store: Callable[[Any], Mapping[str, Any]]) -> Callable[[Any], dict[str, Any]]:
    """Wrap an evidence store so it persists only the encrypted payload.

    Without a stable key the payload is not stored at all: the transaction keeps its metadata
    and the raw view shows it as unavailable, rather than keeping a credential in clear.
    """
    def put(content: Any) -> dict[str, Any]:
        raw, sha, size = serialize_evidence_content(content)
        if raw is None:
            return dict(_EMPTY)
        try:
            sealed = envelope(raw)
        except SecretStoreUnavailable:
            _LOG.warning("Credential encryption is unavailable; a raw HTTP payload was not archived")
            return dict(_EMPTY)
        stored = dict(store(sealed))
        stored.update(content_sha256=sha, size_bytes=size)
        return stored
    return put


def reveal(value: Any) -> Any:
    """The stored serialized payload for an archive row, or the value unchanged if never sealed.

    A payload whose key is gone reads as absent, never as ciphertext.
    """
    decoded = value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return value
    if not is_envelope(decoded):
        return value
    try:
        return decrypt_secret(decoded["ciphertext"])
    except SecretStoreUnavailable:
        return None


def _sealed_file(path: Path) -> bool:
    """Rewrite an externalized plaintext payload as its envelope, atomically."""
    try:
        text = path.read_text(encoding="utf-8")
        if is_envelope(json.loads(text)):
            return False
        tmp = path.with_name(f".{path.name}.sealing")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(envelope(json.dumps(json.loads(text), sort_keys=True, default=str))))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        return True
    except (OSError, ValueError) as exc:
        _LOG.warning("Could not encrypt archived payload %s: %s", path.name, type(exc).__name__)
        return False


async def encrypt_stored_blobs(conn: Any, *, results_dir: Path | None = None, batch: int = 500) -> int:
    """Encrypt raw payloads archived before they were sealed. Runs once per database.

    Inline payloads are rewritten in place. A local externalized payload is rewritten only when
    archive rows are its sole users, since the evidence store is content-addressed.
    """
    if await conn.fetchval("SELECT 1 FROM app_schema_migrations WHERE name=$1", MIGRATION):
        return 0
    if not encryption_enabled():
        return 0  # retried on the next start, once the key is available
    base = results_dir or Path(os.environ.get("RESULTS_DIR", "/results"))
    sealed, last = 0, None
    while True:
        rows = await conn.fetch(
            """SELECT id, content::text AS content FROM evidence_objects
               WHERE object_type='http_archive_blob' AND content IS NOT NULL
                 AND NOT (jsonb_typeof(content)='object' AND COALESCE(content->>'schema_version','')=$1)
                 AND ($2::uuid IS NULL OR id > $2)
               ORDER BY id LIMIT $3""", SCHEMA, last, batch)
        if not rows:
            break
        for row in rows:
            raw = json.dumps(json.loads(row["content"]), sort_keys=True, default=str)
            await conn.execute("UPDATE evidence_objects SET content=$2::jsonb WHERE id=$1",
                               row["id"], json.dumps(envelope(raw)))
            sealed += 1
        last = rows[-1]["id"]
    files = await conn.fetch(
        """SELECT DISTINCT e.storage_uri FROM evidence_objects e
           WHERE e.object_type='http_archive_blob' AND e.content IS NULL AND e.storage_uri LIKE 'local:%'
             AND NOT EXISTS (SELECT 1 FROM evidence_objects o
                             WHERE o.storage_uri=e.storage_uri AND o.object_type<>'http_archive_blob')""")
    for row in files:
        path = local_evidence_path(base, row["storage_uri"])
        if path is not None and path.is_file() and _sealed_file(path):
            sealed += 1
    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1) ON CONFLICT DO NOTHING", MIGRATION)
    return sealed

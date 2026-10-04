"""Raw HTTP archive payloads are encrypted at rest and decrypted only when a raw view reads them.

Recorded traffic keeps request and response headers and bodies verbatim so raw HAR export and
replay stay possible, which means it carries Authorization headers, cookies and tokens. Each
payload is encrypted with the credential key before it is stored, so neither the inline JSONB nor
an externalized file or object holds it in clear.

For a sealed payload ``content_sha256`` identifies the plaintext, so content-addressed
deduplication is unchanged; tamper detection comes from the Fernet token's authentication.
Whether a payload is kept inline is decided by its plaintext size, as before, so encryption
overhead never pushes a readable payload out to external storage.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Callable, Mapping

try:
    from secret_store import SecretStoreUnavailable, decrypt_secret, encrypt_secret, encryption_enabled
    import evidence_storage as _evidence
except ModuleNotFoundError:  # package import layout
    from api.secret_store import SecretStoreUnavailable, decrypt_secret, encrypt_secret, encryption_enabled
    import api.evidence_storage as _evidence

SCHEMA = "http-archive-blob/encrypted-v1"
MIGRATION = "v2_http_archive_blob_encryption_v1"
PAYLOAD_FIELDS = ("request_headers", "request_body", "response_headers", "response_body")
_LOG = logging.getLogger(__name__)
_EMPTY = {"content_sha256": None, "size_bytes": 0, "storage_uri": None, "content": None, "externalized": False}


def envelope(raw: str) -> dict[str, str]:
    return {"schema_version": SCHEMA, "ciphertext": encrypt_secret(raw)}


def is_envelope(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("schema_version") == SCHEMA and "ciphertext" in value


def plaintext_digest(content: Any) -> str | None:
    """The deduplication identity of a payload: the digest of its stored serialization."""
    return _evidence.serialize_evidence_content(content)[1]


def encrypting_store(store: Callable[[Any], Mapping[str, Any]]) -> Callable[[Any], dict[str, Any]]:
    """Wrap an evidence store so it persists only the encrypted payload.

    A payload small enough to stay inline in plaintext stays inline sealed; only a payload that
    was already too large is externalized. Without a stable key the payload is not stored at all:
    the caller records it as unavailable rather than keeping a credential in clear.
    """
    def put(content: Any) -> dict[str, Any]:
        raw, sha, size = _evidence.serialize_evidence_content(content)
        if raw is None:
            return dict(_EMPTY)
        try:
            sealed = envelope(raw)
        except SecretStoreUnavailable:
            _LOG.warning("Credential encryption is unavailable; a raw HTTP payload was not archived")
            return dict(_EMPTY)
        if size <= _evidence.evidence_inline_max_bytes():
            return {"content_sha256": sha, "size_bytes": size, "storage_uri": _evidence.INLINE_STORAGE_URI,
                    "content": json.dumps(sealed, sort_keys=True), "externalized": False}
        stored = dict(store(sealed))
        stored.update(content_sha256=sha, size_bytes=size)
        return stored
    return put


def reveal_payload(value: Any) -> tuple[Any, bool]:
    """(stored serialized payload, unavailable). Unsealed rows pass through unchanged; a sealed
    payload whose key is not this install's reads as absent and is reported unavailable."""
    decoded = value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return value, False
    if not is_envelope(decoded):
        return value, False
    try:
        return decrypt_secret(decoded["ciphertext"]), False
    except SecretStoreUnavailable:
        return None, True


def reveal(value: Any) -> Any:
    return reveal_payload(value)[0]


def _seal_text(text: str) -> str | None:
    """The envelope for an externalized plaintext payload, or None when it is already sealed."""
    if is_envelope(json.loads(text)):
        return None
    return json.dumps(envelope(json.dumps(json.loads(text), sort_keys=True, default=str)), sort_keys=True)


def _seal_local(path: Path) -> str:
    try:
        sealed = _seal_text(path.read_text(encoding="utf-8"))
        if sealed is None:
            return "already"
        tmp = path.with_name(f".{path.name}.sealing")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(sealed)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        return "sealed"
    except (OSError, ValueError) as exc:
        _LOG.warning("Could not encrypt archived payload %s: %s", path.name, type(exc).__name__)
        return "failed"


def _seal_remote(storage_uri: str) -> str:
    parsed = _evidence._parse_s3_storage_uri(storage_uri)
    if parsed is None:
        return "failed"
    bucket, key = parsed
    try:
        sealed = _seal_text(_evidence._s3_request("GET", bucket, key).decode("utf-8"))
        if sealed is None:
            return "already"
        _evidence._s3_request("PUT", bucket, key, body=sealed.encode("utf-8"), content_type="application/json")
        return "sealed"
    except Exception as exc:  # noqa: BLE001 - reported and retried on the next start
        _LOG.warning("Could not encrypt archived remote payload: %s", type(exc).__name__)
        return "failed"


async def encrypt_stored_blobs(conn: Any, *, results_dir: Path | None = None, batch: int = 500) -> int:
    """Encrypt raw payloads archived before they were sealed.

    Inline payloads are rewritten in place; local and S3-compatible externalized payloads are
    rewritten in place when archive rows are their sole users (the evidence store is
    content-addressed). The step is marked complete only when nothing failed or was skipped, so
    a temporary storage or permission failure is retried on the next start.
    """
    if await conn.fetchval("SELECT 1 FROM app_schema_migrations WHERE name=$1", MIGRATION):
        return 0
    if not encryption_enabled():
        return 0  # retried on the next start, once the key is available
    base = results_dir or Path(os.environ.get("RESULTS_DIR", "/results"))
    sealed, failed, last = 0, 0, None
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
    externalized = await conn.fetch(
        """SELECT DISTINCT e.storage_uri FROM evidence_objects e
           WHERE e.object_type='http_archive_blob' AND e.content IS NULL
             AND (e.storage_uri LIKE $1 OR e.storage_uri LIKE $2)
             AND NOT EXISTS (SELECT 1 FROM evidence_objects o
                             WHERE o.storage_uri=e.storage_uri AND o.object_type<>'http_archive_blob')""",
        _evidence.LOCAL_STORAGE_PREFIX + "%", _evidence.S3_STORAGE_PREFIX + "%")
    for row in externalized:
        uri = row["storage_uri"]
        if uri.startswith(_evidence.S3_STORAGE_PREFIX):
            outcome = _seal_remote(uri)
        else:
            path = _evidence.local_evidence_path(base, uri)
            outcome = _seal_local(path) if path is not None and path.is_file() else "missing"
        sealed += outcome == "sealed"
        failed += outcome == "failed"
    if failed:
        _LOG.warning("%d archived payloads could not be encrypted; retrying on the next start", failed)
    else:
        await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1) ON CONFLICT DO NOTHING", MIGRATION)
    return sealed

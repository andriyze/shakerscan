"""Bind a recorded operation to its existing public retry reservation transaction."""

import json
import uuid
from contextvars import ContextVar

retry_identity: ContextVar[tuple[str, str, str, str] | None] = ContextVar(
    "public_retry_identity", default=None
)


async def bind_scan_acceptance(conn, scan_id):
    """Call inside the Scan insertion transaction; recording does not prove enqueue."""
    identity = retry_identity.get()
    if identity is None:
        return
    method, path, key_hash, request_hash = identity
    if method != "POST" or path != "/scans":
        return
    identifier = str(uuid.UUID(str(scan_id)))
    receipt = json.dumps({
        "schema": "public-dispatch-acceptance/v1", "kind": "scan",
        "id": identifier, "status": "recorded",
    }, sort_keys=True, separators=(",", ":")).encode()
    result = await conn.execute(
        "UPDATE public_api_idempotency SET response_body=$5, updated_at=NOW() "
        "WHERE method=$1 AND path=$2 AND key_sha256=$3 AND request_sha256=$4 "
        "AND state='processing' AND response_body IS NULL",
        method, path, key_hash, request_hash, receipt,
    )
    if result != "UPDATE 1":
        raise RuntimeError("public Scan retry reservation could not bind acceptance")

"""Read-only, exact-request lookup over existing Scan retry records."""

import hashlib
import json
import re
import uuid

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/scans/dispatch-receipts/lookup", openapi_extra={"parameters": [
    {"name": "Idempotency-Key", "in": "header", "required": True,
     "schema": {"type": "string", "minLength": 8, "maxLength": 200}},
    {"name": "X-ShakerScan-Request-SHA256", "in": "header", "required": True,
     "schema": {"type": "string", "pattern": "^[0-9a-f]{64}$"}},
]})
async def scan_dispatch_receipt(request: Request):
    keys = request.headers.getlist("idempotency-key")
    hashes = request.headers.getlist("x-shakerscan-request-sha256")
    if (
        request.url.query
        or len(keys) != 1
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,199}", keys[0])
        or len(hashes) != 1
        or not re.fullmatch(r"[0-9a-f]{64}", hashes[0])
    ):
        raise HTTPException(400, "Provide one retry key and exact request-body SHA-256 header")
    pool = getattr(request.app.state, "db_pool", None)
    if pool is None:
        raise HTTPException(503, "Scan retry store is unavailable")
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT request_sha256,state,response_status,response_body "
            "FROM public_api_idempotency WHERE method='POST' AND path='/scans' AND key_sha256=$1",
            hashlib.sha256(keys[0].encode()).hexdigest(),
        )
    headers = {"cache-control": "no-store"}
    base = {"schema": "public-scan-dispatch-receipt/v1"}
    if not row:
        # Absence does not prove non-execution, e.g. after restoring older metadata.
        return JSONResponse({**base, "state": "unknown", "reason": "receipt_missing"},
                            status_code=404, headers=headers)
    if row["request_sha256"] != hashes[0]:
        return JSONResponse({**base, "state": "unknown", "reason": "request_mismatch"},
                            status_code=409, headers=headers)
    try:
        value = json.loads(row["response_body"] or b"null")
        if not isinstance(value, dict):
            raise TypeError
        if row["state"] == "processing":
            if (value.get("schema"), value.get("kind"), value.get("status")) != (
                "public-dispatch-acceptance/v1", "scan", "recorded"
            ):
                raise ValueError
            identifier = value.get("id")
        elif row["state"] == "completed" and 200 <= (row["response_status"] or 0) < 300:
            identifier = value.get("scan_id") or value.get("id")
            if value.get("scan_id") and value.get("id") and value["scan_id"] != value["id"]:
                raise ValueError
        else:
            raise ValueError
        identifier = str(uuid.UUID(str(identifier)))
    except (ValueError, TypeError, UnicodeError):
        return JSONResponse({**base, "state": "unknown", "reason": "acceptance_unconfirmed"},
                            status_code=202, headers=headers)
    return JSONResponse({**base, "state": "recorded", "scan_id": identifier}, headers=headers)

"""One bounded identity observation shared by setup validation and Scan actions."""
import asyncio
from datetime import datetime, timezone
import time

from capabilities.http import execute_bound_http_request
from .evaluation import MAX_HEALTH_RESPONSE_BYTES, evaluate_health_response


async def observe_identity(config, *, target, headers, principal_slot, revision,
                           credential_version, credential_record_version, generation, attempt):
    responses = []
    attempt["started"] = True
    started = time.monotonic()
    try:
        async with asyncio.timeout(config.validation_policy.timeout_seconds):
            await execute_bound_http_request(config.credential_destinations[0],
                {"method": "GET", "path": config.validation_policy.path, "follow_redirects": False},
                target=target, trusted_headers=headers, allow_identity_headers=True,
                principal_slot=principal_slot, timeout_seconds=config.validation_policy.timeout_seconds,
                response_body_limit=MAX_HEALTH_RESPONSE_BYTES + 1, private_response_sink=responses.append)
    finally:
        attempt["elapsed"] = time.monotonic() - started
    response = responses[0] if responses else None
    return evaluate_health_response(config, revision=revision, credential_version=credential_version,
        credential_record_version=credential_record_version, checked_at=datetime.now(timezone.utc),
        process_generation=generation, status_code=response.status_code if response else None,
        body=response.body() if response else b"", content_type=response.headers().get("content-type", "") if response else "",
        response_url=response.final_url if response else None,
        location=response.headers().get("location") if response else None)

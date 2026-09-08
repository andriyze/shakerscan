"""Opt-in transport for scheduler admission through an operator-owned gateway.

The managed runner persists occurrence identity across leases/restarts before
invoking this adapter. Never fall back to local execution after a managed failure.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx


@dataclass(frozen=True)
class DispatchOutcome:
    state: str
    code: str
    scan_id: str | None = None


def occurrence_key(schedule_id: str, occurrence_id: str) -> str:
    """Use a durable occurrence UUID, never the mutable next_run/lease timestamp."""
    identity = f"{UUID(schedule_id)}:{UUID(occurrence_id)}"
    return "schedule:" + hashlib.sha256(identity.encode()).hexdigest()


class ManagedScheduleDispatcher:
    def __init__(self, origin: str, token: str, *, transport=None):
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Managed dispatch requires an operator-configured HTTPS origin"
            )
        if not token or any(ord(c) <= 32 or ord(c) >= 127 for c in token):
            raise ValueError("Invalid managed dispatch credential")
        self._origin = origin.rstrip("/")
        self._token = token
        self._transport = transport

    @property
    def origin(self):
        return self._origin

    async def dispatch(
        self, schedule_id: str, occurrence_id: str, payload: dict[str, Any]
    ) -> DispatchOutcome:
        key = occurrence_key(schedule_id, occurrence_id)
        # Caller supplies a validated public Scan request, with opaque credential
        # references only. The gateway independently enforces target and limits.
        try:
            async with asyncio.timeout(20):
                async with httpx.AsyncClient(
                    transport=self._transport,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=15,
                    cookies=None,
                ) as client:
                    async with client.stream(
                        "POST",
                        self._origin + "/scans",
                        json=payload,
                        headers={
                            "Authorization": "Bearer " + self._token,
                            "Idempotency-Key": key,
                            "Accept": "application/json",
                        },
                    ) as response:
                        if response.status_code in {401, 403, 404, 422}:
                            return DispatchOutcome("denied", "admission_denied")
                        if response.status_code not in {200, 202}:
                            return DispatchOutcome("retry", "admission_unconfirmed")
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > 16384:
                                return DispatchOutcome("retry", "invalid_receipt")
                        data = json.loads(body)
                        if not isinstance(data, dict) or data.get("status") not in {
                            "queued",
                            "pending",
                            "running",
                            "completed",
                        }:
                            return DispatchOutcome("retry", "invalid_receipt")
                        identifier = str(UUID(data["scan_id"]))
                        return DispatchOutcome("accepted", "admitted", identifier)
        except (httpx.HTTPError, TimeoutError, ValueError, TypeError, KeyError):
            # Never return response bodies/exception strings: they can contain
            # operator tokens, target secrets, or internal host details.
            return DispatchOutcome("retry", "admission_unconfirmed")

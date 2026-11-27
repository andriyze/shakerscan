"""The engine asks before it makes accounts on a target (``allow_account_creation``).

The sweep finds a registration route; making accounts there is the operator's decision. When the
Hunt was started without ``allow_account_creation``, the engine raises an ordinary permission
request (``capability.enable``, flag ``account-creation``): a person's launch bound
(``--allow capability:account-creation``) grants it at once, otherwise it waits for a person
(``shakerscan approve <id>``, the Hunt page). The grant turns the flag on the Hunt's policy through
the same path a planner's request takes, so revoking it works the same way too.
"""
from __future__ import annotations

import json
from typing import Any
import uuid

from .permission_admission import PARKABLE_RUN_STATUSES
from .permission_grants import hunt_finished, try_preauthorized_grant
from .permission_reasons import KIND_CAPABILITY_ENABLE
from .permission_store import raise_request

REASON_CODE = "capability_requires_account_creation"
SUBJECT = {"capability": "http.request", "flag": "account-creation"}
DISPLAY = {"why": ("The engine found a registration route and would register two accounts there and use "
                   "the application as them; every account and write is listed in the debrief.")}


async def request_account_creation(pool: Any, hunt_id: Any, *, routes: list[str] | None = None) -> str:
    """``granted`` (the flag is on, or a launch bound just turned it on), ``pending`` (a person
    decides), or ``unavailable`` (the Hunt ended, or no request can be raised)."""
    hunt_uuid = uuid.UUID(str(hunt_id))
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", hunt_uuid)
            if row is None:
                return "unavailable"
            run = dict(row)
            policy = run.get("policy_json")
            policy = json.loads(policy) if isinstance(policy, str) else dict(policy or {})
            if policy.get("allow_account_creation"):
                return "granted"
            if str(run.get("status")) not in PARKABLE_RUN_STATUSES or hunt_finished(run):
                return "unavailable"
            display = {**DISPLAY, **({"routes": list(routes)[:4]} if routes else {})}
            request, _created = await raise_request(
                conn, run=run, kind=KIND_CAPABILITY_ENABLE, reason_code=REASON_CODE, subject=SUBJECT,
                display=display, actor="engine", source="sweep")
            if request is None:
                return "unavailable"
            if await try_preauthorized_grant(conn, run, request) is not None:
                return "granted"
            return "pending"


__all__ = ["REASON_CODE", "SUBJECT", "request_account_creation"]

"""Read a completed runner job's signed receipt for the automatic review.

A runner job that *ran to completion* still carries the guest's verdict (``PASS``, ``FAIL``,
``TIMEOUT``...) and the phase that failed. The review must surface that verdict, not a generic
"conversion completed without ..." line that hides the real cause inside the receipt.
"""

from __future__ import annotations

import json
import re
from typing import Any

PASS_ONLY = frozenset({"PASS"})
# A calibration receipt reads FAIL by design: there is no known-answer digest to match yet and
# the guest records the observed one. Only an execution that never produced a digest fails it.
CALIBRATION_ACCEPTED = frozenset({"PASS", "FAIL"})


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, (str, bytes, bytearray)):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _receipt_payload(job: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    result = _json_object(job.get("result_json"))
    payload = result.get("payload") if isinstance(result.get("payload"), dict) else {}
    observations = payload.get("observations") if isinstance(payload.get("observations"), dict) else {}
    return payload, observations


def observed_embedding_digest(job: dict[str, Any]) -> str | None:
    """The bounded embedding digest the guest observed, when the receipt carries a valid one."""
    _payload, observations = _receipt_payload(job)
    digest = str(observations.get("embedding_output_sha256") or "").lower()
    return digest if re.fullmatch(r"[0-9a-f]{64}", digest) else None


def runner_outcome(job: dict[str, Any]) -> tuple[str, str | None]:
    """Return the receipt's verdict and its first phase failure, for a completed job."""
    payload, observations = _receipt_payload(job)
    status = str(payload.get("status") or "").upper() or "UNKNOWN"
    errors = observations.get("errors") if isinstance(observations.get("errors"), list) else []
    first = next((item for item in errors if isinstance(item, dict) and item.get("message")), None)
    if not first:
        return status, None
    return status, (
        f"phase {first.get('phase') or 'unknown'} failed with {first.get('type') or 'error'}: "
        f"{str(first.get('message'))[:500]}"
    )


def require_runner_receipt(
    job: dict[str, Any], *, step: str, accepted: frozenset[str] = PASS_ONLY,
) -> None:
    """Raise a RuntimeError naming the verdict and failing phase unless the receipt is accepted."""
    outcome, detail = runner_outcome(job)
    if outcome in accepted:
        return
    what = "did not pass" if accepted == PASS_ONLY else "did not complete"
    raise RuntimeError(
        f"{step} {what} (runner receipt {outcome}): {detail or 'see the signed runner receipt'}"
    )

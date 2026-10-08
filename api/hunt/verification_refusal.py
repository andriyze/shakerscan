"""A deterministic verification refused before any request reached the target.

The web verifier (``_verify_suspected_finding_workflow`` in api.py) validates the candidate, its
proof route, the approval receipt and the proof contract before it dispatches the two-run family
proof, and it turns every HTTPException from the dispatch itself into a returned verdict. An
HTTPException that escapes it was therefore raised before any target traffic. The Hunt marks such a
refusal so settlement can release the whole reservation instead of charging the conservative full
hold that an uncertain, possibly-executed verification needs.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from fastapi import HTTPException


class VerificationRefused(HTTPException):
    """The verifier refused the request; no request reached the target."""


@contextmanager
def refused_before_traffic() -> Iterator[None]:
    """Re-raise a verifier's guard refusal as ``VerificationRefused`` with the same answer."""
    try:
        yield
    except VerificationRefused:
        raise
    except HTTPException as exc:
        raise VerificationRefused(
            status_code=exc.status_code, detail=exc.detail, headers=exc.headers,
        ) from exc


def raise_returned_refusal(result: Any) -> None:
    """Raise a credential refusal the verifier returned as a verdict, when nothing was sent (D33).

    The verifier turns every HTTPException from its dispatch into a returned verdict. A Hunt
    credential refusal raised while the dispatch resolves principals (auth_bypass resolves them
    there, not in preflight) comes back the same way, and the Hunt reported it as a successful,
    fully charged verification. The dispatch says whether its only possible earlier traffic, a
    create-surface probe, ran; only an explicit ``target_traffic_sent: false`` is a refusal.
    """
    error = result.get("error") if isinstance(result, Mapping) else None
    if (
        isinstance(error, Mapping)
        and error.get("error") == "hunt_credential_refused"
        and error.get("target_traffic_sent") is False
    ):
        raise VerificationRefused(status_code=422, detail=dict(error))


__all__ = ["VerificationRefused", "raise_returned_refusal", "refused_before_traffic"]

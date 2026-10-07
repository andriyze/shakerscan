"""A deterministic verification refused before any request reached the target.

The web verifier (``_verify_suspected_finding_workflow`` in api.py) validates the candidate, its
proof route, the approval receipt and the proof contract before it dispatches the two-run family
proof, and it turns every HTTPException from the dispatch itself into a returned verdict. An
HTTPException that escapes it was therefore raised before any target traffic. The Hunt marks such a
refusal so settlement can release the whole reservation instead of charging the conservative full
hold that an uncertain, possibly-executed verification needs.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

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


__all__ = ["VerificationRefused", "refused_before_traffic"]

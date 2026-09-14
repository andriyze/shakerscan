"""Route a hash-route DOM XSS proof to the pinned browser instead of Dalfox.

A DOM cross-site scripting flaw on a single-page-application client route lives entirely
in the URL fragment. The server never receives the fragment, and Dalfox (the Hunt's
``xss.verify`` scanner) drops it, so a fragment-parameter proof can never settle there.
The registry declares the Playwright browser prover as an alternate runtime for
``xss.verify``; this selects it when the execution target names exactly one fragment
parameter and no server query, which is precisely the DOM-XSS case. Every server-visible
parameter keeps the Dalfox scanner.
"""
from __future__ import annotations

import hashlib
import urllib.parse
from dataclasses import replace
from typing import Any

try:
    from capabilities.browser import (
        BrowserCapabilityInputError,
        XSSBrowserProofAdapter,
    )
    from hunt.capability_executor import CapabilityAdapterResult
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package import in host-side tests
    from ..capabilities.browser import (
        BrowserCapabilityInputError,
        XSSBrowserProofAdapter,
    )
    from ..runtime.models import TargetBinding
    from .capability_executor import CapabilityAdapterResult


_BENIGN_BLOCK_REASONS = frozenset({"cross_origin"})


def _normalize_hunt_browser_xss_result(
    result: CapabilityAdapterResult,
) -> CapabilityAdapterResult:
    """Keep verified proofs complete, but do not hide incomplete negative attempts.

    The pinned browser intentionally blocks off-origin subresources. Those blocks do not
    invalidate either a verified same-origin DOM proof or a complete negative result. Other
    block reasons mean the browser did not exercise the full admitted attempt. A verified
    proof remains success because the vulnerability is already established; an unverified
    attempt becomes partial (or cancelled) so Hunt coverage does not overclaim completeness.
    """
    if result.status != "success":
        return result

    verified = any(
        item.get("kind") == "xss_browser_proof"
        and item.get("proof_state") == "verified"
        for item in result.observations
        if isinstance(item, dict)
    )
    if verified:
        return result

    reasons = {
        str(item.get("reason") or "")
        for item in result.observations
        if isinstance(item, dict) and item.get("kind") == "browser_request_blocked"
    }
    material = tuple(sorted(reason for reason in reasons - _BENIGN_BLOCK_REASONS if reason))
    if not material:
        return result

    errors = tuple(
        dict.fromkeys(
            (*result.errors, *(f"browser_request_blocked:{reason}" for reason in material))
        )
    )
    if "cancelled" in material:
        return replace(result, status="cancelled", partial=False, errors=errors)
    return replace(result, status="partial", partial=True, errors=errors)


class HuntXSSBrowserProofAdapter(XSSBrowserProofAdapter):
    """The pinned browser prover under the registry-authorized Hunt xss.verify identity."""

    capability_name = "xss.verify"

    async def execute(self, *, heartbeat, cancelled) -> CapabilityAdapterResult:
        result = await super().execute(heartbeat=heartbeat, cancelled=cancelled)
        return _normalize_hunt_browser_xss_result(result)


def hunt_browser_xss_proof_adapter(
    *,
    capability_name: str,
    spec: Any,
    target: TargetBinding,
    execution_target: str,
    action_id: str,
) -> HuntXSSBrowserProofAdapter | None:
    """Return a pinned-browser XSS prover when xss.verify names a hash-route parameter.

    Returns None to leave the Dalfox scanner in place; a prepared adapter is only
    returned when the browser can actually attempt the proof.
    """
    if capability_name != "xss.verify":
        return None
    parsed = urllib.parse.urlsplit(execution_target)
    if parsed.query or not parsed.fragment:
        return None
    fragment = urllib.parse.urlsplit(parsed.fragment)
    fragment_params = urllib.parse.parse_qsl(
        fragment.query, keep_blank_values=True, max_num_fields=50,
    )
    if len(fragment_params) != 1:
        return None
    parameter_name = fragment_params[0][0]
    if not parameter_name:
        return None
    candidate_id = hashlib.sha256(
        f"{action_id}:{parameter_name}".encode()
    ).hexdigest()
    try:
        prepared = HuntXSSBrowserProofAdapter.prepare(
            target=target,
            execution_url=execution_target,
            candidate_id=candidate_id,
            parameter_name=parameter_name,
        )
    except BrowserCapabilityInputError:
        # The fragment authority is ambiguous or off-origin; let the scanner path
        # produce the honest not-proven result rather than inventing a browser run.
        return None
    return HuntXSSBrowserProofAdapter(prepared)


__all__ = [
    "HuntXSSBrowserProofAdapter",
    "hunt_browser_xss_proof_adapter",
]

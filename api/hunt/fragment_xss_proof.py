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
from typing import Any

try:
    from capabilities.browser import (
        BrowserCapabilityInputError,
        XSSBrowserProofAdapter,
    )
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package import in host-side tests
    from ..capabilities.browser import (
        BrowserCapabilityInputError,
        XSSBrowserProofAdapter,
    )
    from ..runtime.models import TargetBinding


def hunt_browser_xss_proof_adapter(
    *,
    capability_name: str,
    spec: Any,
    target: TargetBinding,
    execution_target: str,
    action_id: str,
) -> XSSBrowserProofAdapter | None:
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
        prepared = XSSBrowserProofAdapter.prepare(
            target=target,
            execution_url=execution_target,
            candidate_id=candidate_id,
            parameter_name=parameter_name,
        )
    except BrowserCapabilityInputError:
        # The fragment authority is ambiguous or off-origin; let the scanner path
        # produce the honest not-proven result rather than inventing a browser run.
        return None
    adapter = XSSBrowserProofAdapter(prepared)
    # The prover's native capability is xss.browser_prove_batch, but here it executes the
    # xss.verify action. The dispatcher and executor refuse any adapter whose capability
    # name differs from the action's, so present the action's name; the registry already
    # authorizes this (adapter, version) as an xss.verify runtime via alternate_adapters.
    adapter.capability_name = capability_name
    return adapter


__all__ = ["hunt_browser_xss_proof_adapter"]

"""The input the Scan's browser XSS proof sends, derived from its candidate, and its oracle.

The proof places one inert script in the tested parameter: it sets an attribute and logs a marker
named after the candidate, and the browser proof looks for that marker. The finding keeps the
candidate and the payload's digest, so a retest of a verified finding can send exactly the same
input and check that it is still the one the proof sent.

The oracle is the same for the Scan's proof and for a retest of its finding: after the page's
DOMContentLoaded and a short settle, the payload ran when the page's root element carries the
attribute with the marker as its value, or a console or dialog message is exactly the marker.
Anything else a page logs (its own messages, the input echoed back) is not a proof.
"""

from __future__ import annotations

import hashlib
from typing import Any

# The attribute the payload sets on the root element.
XSS_PROOF_ATTRIBUTE = "data-shakerscan-proof"
# How long the proof waits after DOMContentLoaded for the payload to run, and its navigation limit.
XSS_PROOF_SETTLE_SECONDS = 1.5
XSS_PROOF_TIMEOUT_MS = 20_000


def xss_proof_marker(candidate_id: str) -> str:
    return f"shakerscan_xss_{str(candidate_id)[:12]}"


def xss_proof_payload(candidate_id: str) -> str:
    marker = xss_proof_marker(candidate_id)
    return (
        '<img src=x onerror="document.documentElement.setAttribute('
        f"'{XSS_PROOF_ATTRIBUTE}','{marker}');console.log('{marker}')\">"
    )


def xss_proof_signal(value: Any, marker: str) -> bool:
    """Whether a console or dialog message, or the attribute's value, is exactly the marker."""
    return bool(marker) and str(value or "") == marker


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

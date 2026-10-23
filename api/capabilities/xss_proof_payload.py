"""The input the Scan's browser XSS proof sends, derived from its candidate.

The proof places one inert script in the tested parameter: it sets an attribute and logs a marker
named after the candidate, and the browser proof looks for that marker. The finding keeps the
candidate and the payload's digest, so a retest of a verified finding can send exactly the same
input and check that it is still the one the proof sent.
"""

from __future__ import annotations

import hashlib


def xss_proof_marker(candidate_id: str) -> str:
    return f"shakerscan_xss_{str(candidate_id)[:12]}"


def xss_proof_payload(candidate_id: str) -> str:
    marker = xss_proof_marker(candidate_id)
    return (
        '<img src=x onerror="document.documentElement.setAttribute('
        f"'data-shakerscan-proof','{marker}');console.log('{marker}')\">"
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

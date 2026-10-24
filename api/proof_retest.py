"""The exact request a Scan's proof sent, rebuilt from the finding it recorded.

A verified SQL injection, NoSQL injection or browser-executed XSS finding is retested by the check
that proved it, sent again with the request it proved. That request is rebuilt only when the
finding keeps everything it needs:

* the SQL and NoSQL proofs record the route (``/product``), the tested field (``field_path``) and
  the method. When the proof was built from a crawled endpoint (no recorded private request), its
  request was a GET of that route on the target's origin with only the tested query parameter,
  set to ``1`` (``execution_url_for_endpoint``), and it is rebuilt exactly as that. The origin is
  the one the finding recorded, else the origin of the finding's own target (``_site``);
* the browser proof records the page URL with the tested value masked, the parameter
  (``parameter_name``) and where the input went, and its payload is derived from its candidate;
  the payload is rebuilt and accepted only when its digest matches the one the finding kept.

Anything else -- a recorded private request whose values the finding does not keep, a request
body, a path segment, a templated route (``/products/{int}``), a masked value the request needs,
a payload placed in a fragment or on another page -- cannot be sent the way the proof sent it, so
the finding is checked again by a new Scan (``retest_by_rescan_only``) and the gap says why.

A queued retest is sent exactly as it was admitted: the worker rebuilds the request from the
finding on the site of the URL the API admitted, and sends nothing when the rebuilt request is not
that URL (the finding changed after the retest was queued).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping
import urllib.parse

try:
    from capabilities.xss_proof_payload import sha256_text, xss_proof_payload
except ModuleNotFoundError:  # package import in host-side tests
    from .capabilities.xss_proof_payload import sha256_text, xss_proof_payload


# The tool a proven finding carries -> the Scan capability whose check proved it. The two request
# differentials keep no route at all (their URL is the origin only), so they are never rebuilt.
PROOF_RETEST_TOOLS: dict[str, str] = {
    "shakerscan_sqli_proof": "sqli.prove_batch",
    "shakerscan_nosqli_verify": "nosqli.verify_batch",
    "shakerscan_browser_proof": "xss.browser_prove_batch",
    "request_sqli_differential": "sqli.request_verify_batch",
    "request_xss_differential": "xss.request_verify_batch",
}
_ROUTELESS_TOOLS = frozenset({"request_sqli_differential", "request_xss_differential"})

# The value ``execution_url_for_endpoint`` gives the tested query parameter of a crawled endpoint.
SYNTHETIC_QUERY_VALUE = "1"
_PATH_FIELD = re.compile(r"path_\d+\Z")
_MASKED_VALUES = frozenset({"<redacted>", "[redacted]"})

# Why a proven finding's request cannot be sent again as its proof sent it. Each message ends by
# saying what to do instead.
_AGAIN = " Run a new Scan to check it again."
PROOF_RETEST_GAPS: dict[str, str] = {
    "private_request": (
        "The proof sent a request recorded during the Scan, and the finding keeps its shape, not "
        "its values, so a retest cannot send the same request." + _AGAIN
    ),
    "request_shape": (
        "The proof sent its input in a request body, or the finding does not record the method, "
        "so a retest cannot send the same request." + _AGAIN
    ),
    "path_segment": (
        "The injection point is a URL path segment, and a retest sends its input only in a query "
        "parameter." + _AGAIN
    ),
    "templated_path": (
        "The finding keeps the route with a placeholder segment (such as {int}), not the value the "
        "proof sent, so a retest cannot rebuild the request." + _AGAIN
    ),
    "no_parameter": (
        "The finding does not name the parameter the proof tested, so a retest cannot rebuild the "
        "request." + _AGAIN
    ),
    "no_route": (
        "The finding keeps the site it was found on but not the request's route, so a retest "
        "cannot rebuild the request." + _AGAIN
    ),
    "no_origin": (
        "The finding keeps a path but no site to send it to, so a retest cannot rebuild the "
        "request." + _AGAIN
    ),
    "masked_value": (
        "The finding keeps the URL with a masked value the request needs, so a retest cannot send "
        "the same request." + _AGAIN
    ),
    "not_query": (
        "The proof placed its input somewhere other than one query parameter of the page it "
        "loaded (a fragment, a body, or a page where stored input ran), so a retest cannot send "
        "the same request." + _AGAIN
    ),
    "payload_unknown": (
        "The finding does not keep the payload the browser proof ran, so a retest cannot send the "
        "same input." + _AGAIN
    ),
    # Only a queued retest (the worker's view) can meet this one.
    "not_admitted": (
        "The finding changed after this retest was queued: the request rebuilt from it is not the "
        "one the retest was admitted for, so nothing was sent. Retest the finding again."
    ),
}


@dataclass(frozen=True)
class ProofRetestRequest:
    """What a retest sends: the proof's own check (``capability``) over this exact GET."""

    capability: str
    url: str
    method: str
    param: str
    payload: str | None = None
    # The proof's candidate: its route, request class and id (the SQL and NoSQL checks derive
    # their invalid control and sentinel values from the id, as they did during the Scan).
    route: str = ""
    request_class: str = "safe_read"
    candidate_id: str = ""


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def proof_retest_tool(record: Mapping[str, Any]) -> str | None:
    """The record's tool when a Scan proof produced it, else None."""
    tool = str(record.get("tool") or "").strip().lower()
    return tool if tool in PROOF_RETEST_TOOLS else None


def _origin(value: Any) -> str | None:
    """``scheme://host[:port]`` of an absolute HTTP(S) URL, or None."""
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not host or parsed.username or parsed.password:
        return None
    if any(char in parsed.netloc for char in "\\ \t\r\n"):
        return None
    shown = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme.lower()}://{shown}" + (f":{port}" if port else "")


def _site(record: Mapping[str, Any]) -> Any:
    """The URL whose origin a stored route is joined to when the proof recorded no origin.

    A queued retest (a retest row joined with its finding) keeps the URL the API admitted
    (``original_url``): its site, else -- a retest queued with a bare route -- the site of the Scan
    that found the finding (``source_scan_target_url``). Never the retest's own ``target_url``,
    which holds a caller's ``target``. A finding row: its target's URL (``target_url``).
    """
    admitted = record.get("original_url")
    if _origin(admitted):
        return admitted
    return record.get("source_scan_target_url") or record.get("target_url")


def _masked(value: str) -> bool:
    return urllib.parse.unquote(value).strip().lower() in _MASKED_VALUES


def _differential_request(
    tool: str, record: Mapping[str, Any], evidence: Mapping[str, Any],
) -> tuple[ProofRetestRequest | None, str | None]:
    if tool in _ROUTELESS_TOOLS:
        return None, "no_route"
    if str(evidence.get("request_ref_id") or "").strip():
        return None, "private_request"
    if str(evidence.get("method") or "").strip().upper() != "GET":
        return None, "request_shape"
    field = str(evidence.get("field_path") or evidence.get("parameter_name") or "").strip()
    if not field:
        return None, "no_parameter"
    if _PATH_FIELD.fullmatch(field):
        return None, "path_segment"
    stored = str(record.get("url") or record.get("finding_url") or "").strip()
    try:
        parsed = urllib.parse.urlsplit(stored)
    except ValueError:
        return None, "no_route"
    if not parsed.path.startswith("/"):
        return None, "no_route"
    if parsed.query or parsed.fragment:
        return None, "request_shape"
    if "{" in parsed.path or "}" in parsed.path:
        return None, "templated_path"
    origin = (
        _origin(stored) if parsed.scheme
        else _origin(evidence.get("origin")) or _origin(_site(record))
    )
    if origin is None:
        return None, "no_origin"
    url = origin + parsed.path + "?" + urllib.parse.urlencode([(field, SYNTHETIC_QUERY_VALUE)])
    return ProofRetestRequest(
        PROOF_RETEST_TOOLS[tool], url, "GET", field, route=parsed.path,
        request_class=str(evidence.get("request_class") or "safe_read"),
        candidate_id=str(evidence.get("candidate_id") or ""),
    ), None


def _browser_request(
    record: Mapping[str, Any], evidence: Mapping[str, Any],
) -> tuple[ProofRetestRequest | None, str | None]:
    sink = _json_object(evidence.get("execution_sink"))
    param = str(evidence.get("parameter_name") or sink.get("parameter") or "").strip()
    if not param:
        return None, "no_parameter"
    url = str(evidence.get("request_url") or record.get("url") or record.get("finding_url") or "").strip()
    if _origin(url) is None:
        return None, "no_origin"
    location = str(evidence.get("injection_location") or sink.get("location") or "query").strip().lower()
    parsed = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    related = [str(item) for item in evidence.get("related_request_urls") or () if str(item)]
    if (
        location != "query" or parsed.fragment
        or sum(1 for name, _value in pairs if name == param) != 1
        or any(item != url for item in related)
    ):
        return None, "not_query"
    if any(_masked(value) for name, value in pairs if name != param):
        return None, "masked_value"
    candidate = str(evidence.get("candidate_id") or "").strip()
    payload = xss_proof_payload(candidate) if candidate else ""
    if not payload or sha256_text(payload) != str(evidence.get("payload_sha256") or "").strip().lower():
        return None, "payload_unknown"
    return ProofRetestRequest(
        PROOF_RETEST_TOOLS["shakerscan_browser_proof"], url, "GET", param, payload,
        route=parsed.path, candidate_id=candidate,
    ), None


def proof_retest_request(record: Mapping[str, Any]) -> tuple[ProofRetestRequest | None, str | None]:
    """``(request, None)`` when a proven finding's request can be sent again exactly, ``(None,
    gap)`` when it cannot (``PROOF_RETEST_GAPS``), and ``(None, None)`` for any other finding.

    ``record`` is a finding row (``target_url``: its target's URL), or a retest row joined with its
    finding (its URL as ``finding_url``, the URL the API admitted as ``original_url``). A retest row
    whose rebuilt request is not the URL it was admitted for gets ``not_admitted``.
    """
    tool = proof_retest_tool(record)
    if tool is None:
        return None, None
    evidence = _json_object(record.get("evidence"))
    if tool == "shakerscan_browser_proof":
        request, gap = _browser_request(record, evidence)
    else:
        request, gap = _differential_request(tool, record, evidence)
    admitted = str(record.get("original_url") or "").strip()
    if request is not None and _origin(admitted) and request.url != admitted:
        return None, "not_admitted"
    return request, gap


def proof_retest_gap(record: Mapping[str, Any]) -> str | None:
    """Why a proven finding's request cannot be sent again, or None."""
    return proof_retest_request(record)[1]

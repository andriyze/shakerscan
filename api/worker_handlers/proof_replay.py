"""A proven Scan finding's retest: the proof's own check, sent again with the request it proved.

``run_finding_retest`` hands a retest of a verified SQL injection, NoSQL injection or
browser-executed XSS finding here. The request is rebuilt by ``proof_retest.proof_retest_request``;
when it cannot be rebuilt exactly nothing is sent and the retest is inconclusive with the reason.
Otherwise the same check runs again:

* SQL and NoSQL injection: the Scan's own adapters (``sqli.prove_batch``, ``nosqli.verify_batch``)
  over that request, through the retest's HTTP client, so the retest's session headers, request
  limits and destination guard apply to every request;
* XSS: the same payload, in a headless browser, after one ordinary request shows the page answers.

The verdict follows the check: reproduced is still vulnerable; not reproduced, with every request
answered, is likely fixed; a refusal, a failed request or a missing browser is inconclusive, and
the finding stays open. Nothing here escalates to the AI tier.
"""

from __future__ import annotations

import math
import time
from typing import Any, Awaitable, Callable, Mapping
import urllib.parse

try:
    from proof_retest import PROOF_RETEST_GAPS, ProofRetestRequest, proof_retest_request
    from retest_contract import auth_context_to_headers, parse_json_field
    from worker_handlers.retest_outcome import _internal_retest_scope_authorized, classify_retest_outcome
except ModuleNotFoundError:  # package import in host-side tests
    from ..proof_retest import PROOF_RETEST_GAPS, ProofRetestRequest, proof_retest_request
    from ..retest_contract import auth_context_to_headers, parse_json_field
    from .retest_outcome import _internal_retest_scope_authorized, classify_retest_outcome


# The Scan reserves at most this much for one candidate's proof (the error, boolean and timing
# pairs of the SQL check; one field's four requests, twice over, for the NoSQL check).
_BUDGETS: dict[str, dict[str, int]] = {
    "sqli.prove_batch": {"http_requests": 14, "tool_wall_seconds": 90},
    "nosqli.verify_batch": {"http_requests": 8, "tool_wall_seconds": 60},
}
_REFUSALS = frozenset({"authentication_required", "target_refused"})
_LIKELY_FIXED = "The check that proved the finding sent the same request again and did not reproduce it."


def _result(
    *, status: str, result_status: str, verdict: str, reason: str, started: float,
    request: ProofRetestRequest | None, replay_commands: list[str], ladder: list[str],
    confidence: float | None = None, proof: Mapping[str, Any] | None = None,
    artifacts: Mapping[str, Any] | None = None, error: str | None = None,
) -> dict[str, Any]:
    return {
        "status": status, "result_status": result_status, "verdict": verdict,
        "verdict_reason": reason, "error_message": error, "confidence": confidence,
        "proof": dict(proof) if proof is not None else None,
        "replay_commands": replay_commands,
        "artifacts": {
            "check": request.capability if request else None,
            "replayed_url": request.url if request else None,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            **dict(artifacts or {}),
        },
        "message": reason, "attempt_ladder": ladder, "attempts_exhausted": True,
        "deterministic_exhausted": True, "has_ai_step": False,
        "retry_class": "none" if error is None else "transient", "retryable": False,
        "verification_mode": "deterministic",
    }


def _error_code(response: Mapping[str, Any]) -> str | None:
    if int(response.get("status_code") or 0):
        return None
    error = str(response.get("error") or "").lower()
    if "destination_out_of_scope" in error:
        return "destination_out_of_scope"
    if "request limit" in error:
        return "request_limit_exceeded"
    if "timed out" in error or "timeout" in error:
        return "timeout"
    return "transport_error"


class RetestFetchTransport:
    """``ReplayTransport`` over the retest's HTTP client (``fetch_with_capture``)."""

    def __init__(self, fetch: Callable[..., Awaitable[Mapping[str, Any]]]) -> None:
        self._fetch = fetch

    async def send(self, request: Any, *, target: Any, timeout_seconds: float, follow_redirects: bool) -> Any:
        try:
            from runtime.request_replay_executor import MAX_REPLAY_RESPONSE_BODY_BYTES, ReplayTransportResult
        except ModuleNotFoundError:  # package import in host-side tests
            from ..runtime.request_replay_executor import MAX_REPLAY_RESPONSE_BODY_BYTES, ReplayTransportResult
        response = await self._fetch(
            request.url, method=request.method,
            data=request.body.decode("utf-8") if request.body else None,
            headers=dict(request.headers) or None,
            timeout=max(1, math.ceil(timeout_seconds)), follow_redirects=follow_redirects,
        )
        status = int(response.get("status_code") or 0)
        error = _error_code(response)
        return ReplayTransportResult(
            status_code=status if 100 <= status <= 599 else None,
            connected_address=None,
            final_url=str(response.get("final_url") or request.url),
            response_headers={str(k).lower(): str(v) for k, v in dict(response.get("headers") or {}).items()},
            response_body=str(response.get("body") or "").encode("utf-8", "replace")[:MAX_REPLAY_RESPONSE_BODY_BYTES],
            elapsed_ms=max(0, min(86_400_000, int(float(response.get("elapsed_ms") or 0)))),
            error_code=error, timed_out=error == "timeout",
        )


def _adapter(request: ProofRetestRequest, target_id: str, transport: Any) -> Any:
    try:
        from capabilities.nosqli_verify import NoSQLiVerifyAdapter
        from capabilities.sqli_proof import SQLiProofAdapter
        from runtime.capability_registry import CAPABILITY_REGISTRY
        from runtime.models import TargetBinding
        from scanner_tools.request_replay import ReplayRequest
    except ModuleNotFoundError:  # package import in host-side tests
        from ..capabilities.nosqli_verify import NoSQLiVerifyAdapter
        from ..capabilities.sqli_proof import SQLiProofAdapter
        from ..runtime.capability_registry import CAPABILITY_REGISTRY
        from ..runtime.models import TargetBinding
        from scanner.scanner_tools.request_replay import ReplayRequest
    parsed = urllib.parse.urlsplit(request.url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    binding = TargetBinding(
        target_id=target_id, target_kind="web", canonical_host=parsed.hostname,
        allowed_origins=(origin,),
    )
    replay = ReplayRequest(
        request_id=f"retest:{request.candidate_id or 'candidate'}", ordinal=0, name="retest",
        folder="", method=request.method, url=request.url, headers=(), body=b"", body_mode="none",
        auth_type="none", has_sensitive_material=False,
    )
    # The candidate the Scan built from its crawled endpoint: no private request, the tested
    # field and route, and the class of request it was.
    candidate = {
        "candidate_id": request.candidate_id, "method": request.method,
        "field_path": request.param, "parameter_name": request.param,
        "canonical_path": request.route, "request_class": request.request_class,
        "request_ref_id": None, "body_field_names": [],
    }
    adapter_type = SQLiProofAdapter if request.capability == "sqli.prove_batch" else NoSQLiVerifyAdapter
    return adapter_type(
        specification=CAPABILITY_REGISTRY.require(request.capability), target=binding,
        request=replay, candidate=candidate, transport=transport,
        requested_budget=_BUDGETS[request.capability],
    )


async def _differential_check(
    request: ProofRetestRequest, *, target_id: str, fetch: Callable[..., Awaitable[Mapping[str, Any]]],
    cancelled: Callable[[], bool],
) -> tuple[str, dict[str, Any]]:
    """``(outcome, proof)``: ``reproduced``, ``not_reproduced``, a refusal token or ``failed``."""
    async def heartbeat() -> None:
        return None

    adapter = _adapter(request, target_id, RetestFetchTransport(fetch))
    result = await adapter.execute(heartbeat=heartbeat, cancelled=cancelled)
    observations = [dict(item) for item in result.observations]
    verified = next((item for item in observations if item.get("proof_state") == "verified"), None)
    shown = verified or (observations[-1] if observations else {})
    proof = {
        key: shown.get(key) for key in (
            "proof_contract", "technique", "repetitions", "response_pairs",
            "database_error_signatures", "operator", "field_path", "method",
        ) if shown.get(key) not in (None, [], "")
    }
    proof["errors"] = list(result.errors)
    if verified is not None:
        return "reproduced", proof
    refusal = next((str(item.get("inconclusive_reason")) for item in observations
                    if item.get("finding_verdict") == "inconclusive"), None)
    if refusal in _REFUSALS:
        return refusal, proof
    if result.status != "success" or result.errors or not observations:
        return "failed", proof
    return "not_reproduced", proof


async def _browser_check(
    request: ProofRetestRequest, *, poe: Any, auth_headers: Mapping[str, str] | None,
) -> tuple[str, dict[str, Any]]:
    """The proof's own payload in a headless browser, after one ordinary request of the page."""
    parsed = urllib.parse.urlsplit(request.url)
    pairs = [(name, "shakerscan" if name == request.param else value)
             for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
    ordinary = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(pairs)))
    baseline = await poe.fetch_with_capture(ordinary, timeout=12)
    if not int(baseline.get("status_code") or 0):
        return "failed", {"errors": [_error_code(baseline)]}
    refused = poe.baseline_refusal(ordinary, baseline)
    if refused:
        return refused, {"baseline_status": int(baseline.get("status_code") or 0)}
    if not await poe.headless_browser_available():
        return "no_browser", {}
    proof = await poe.prove_xss_headless(
        request.url, request.param, request.payload or "", headers=dict(auth_headers or {}) or None,
    )
    shown = {"technique": getattr(proof, "technique", None), "evidence_type": getattr(proof, "evidence_type", None)}
    return ("reproduced" if getattr(proof, "proven", False) else "not_reproduced"), {
        key: value for key, value in shown.items() if value}


async def run_proof_retest(
    verification: Mapping[str, Any], inputs: Mapping[str, Any], *, poe: Any,
    replay_commands: list[str], ladder: list[str], cancelled: Callable[[], bool],
) -> dict[str, Any] | None:
    """The retest of a proven Scan finding, or None for any other finding.

    ``poe`` is the scanner's proof module (``fetch_with_capture``, ``baseline_refusal``,
    ``headless_browser_available``, ``prove_xss_headless``, the session calls). The retest's
    session headers are the ones the finding's Scan was given (``auth_context``).
    """
    request, gap = proof_retest_request(verification)
    if request is None and gap is None:
        return None
    started = time.monotonic()
    common = {"started": started, "request": request, "replay_commands": replay_commands, "ladder": ladder}
    if request is None:
        return _result(status="completed", result_status="inconclusive", verdict="inconclusive",
                       reason=PROOF_RETEST_GAPS[str(gap)], artifacts={"skipped_reason": gap}, **common)
    auth_context = parse_json_field(verification.get("auth_context"))
    auth_headers = auth_context_to_headers(auth_context) if auth_context else None
    session = f"retest-{verification.get('id') or 'proof'}"
    try:
        poe.start_scan_session(session, auth_headers=dict(auth_headers or {}) or None)
    except Exception:
        pass
    try:
        if request.capability == "xss.browser_prove_batch":
            outcome, proof = await _browser_check(request, poe=poe, auth_headers=auth_headers)
        else:
            outcome, proof = await _differential_check(
                request, target_id=str(verification.get("target_id") or "retest"),
                fetch=poe.fetch_with_capture, cancelled=cancelled,
            )
    except Exception as exc:  # the check could not run: nothing reproduced, nothing fixed
        result_status, verdict, reason = classify_retest_outcome(
            proof=None, proven=False, confidence=None, inputs=dict(inputs), error_message=str(exc))
        return _result(status="failed", result_status=result_status, verdict=verdict, reason=reason,
                       error=f"Retest execution failed: {exc}", **common)
    finally:
        try:
            poe.end_scan_session(session)
        except Exception:
            pass
    artifacts = {"outcome": outcome}
    if outcome == "reproduced":
        return _result(status="completed", result_status="still_vulnerable", verdict="exploited",
                       reason="The check that proved the finding sent the same request again and reproduced it.",
                       confidence=0.95, proof=proof, artifacts=artifacts, **common)
    if outcome == "no_browser":
        return _result(status="completed", result_status="inconclusive", verdict="inconclusive",
                       reason="This worker has no headless browser, so the browser check that proved "
                              "the finding could not run; the finding stays open.",
                       proof=proof, artifacts=artifacts, **common)
    if outcome == "failed":
        return _result(status="completed", result_status="inconclusive", verdict="inconclusive",
                       reason="The retest's requests did not all get an answer, so nothing was "
                              "reproduced or ruled out; the finding stays open.",
                       proof=proof, artifacts=artifacts, **common)
    result_status, verdict, reason = classify_retest_outcome(
        proof={"evidence_type": outcome if outcome in _REFUSALS else ""}, proven=False,
        confidence=None, inputs={**dict(inputs), "original_url": request.url},
        internal_target_authorized=_internal_retest_scope_authorized(dict(verification), request.url),
    )
    if verdict == "likely_fixed":
        reason = _LIKELY_FIXED
    return _result(status="completed", result_status=result_status, verdict=verdict, reason=reason,
                   confidence=0.9 if verdict == "likely_fixed" else None, proof=proof,
                   artifacts=artifacts, **common)


__all__ = ["RetestFetchTransport", "run_proof_retest"]

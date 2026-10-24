"""A proven Scan finding's retest: the proof's own check, sent again with the request it proved.

``run_finding_retest`` hands a retest of a verified SQL injection, NoSQL injection or
browser-executed XSS finding here. The request is rebuilt by ``proof_retest.proof_retest_request``;
when it cannot be rebuilt exactly nothing is sent and the retest is inconclusive with the reason.
Otherwise the same check runs again:

* SQL and NoSQL injection: the Scan's own adapters (``sqli.prove_batch``, ``nosqli.verify_batch``)
  over that request, through the retest's HTTP client, so the retest's session headers, request
  limits and destination guard apply to every request;
* XSS: the same payload in a headless browser, after one ordinary request shows the page answers,
  judged by the browser proof's own oracle (``capabilities.xss_proof_payload``): the page's root
  element carries the proof attribute with the candidate's marker, or a console or dialog message
  is exactly that marker. The page is loaded as the proof loads it (DOMContentLoaded, then the same
  settle), only same-origin GET, HEAD and OPTIONS requests leave it, and it runs under the
  retest's destination guard with its session headers confined to the finding's origin.

The verdict follows the check: reproduced is still vulnerable; not reproduced, with every request
answered, is likely fixed; a refusal, a failed request, an unavailable service (``_unavailable``),
a missing browser or one that does not answer is inconclusive, and the finding stays open. Nothing
here escalates to the AI tier.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import time
from typing import Any, Awaitable, Callable, Mapping
import urllib.parse

try:
    from capabilities.xss_proof_payload import (
        XSS_PROOF_ATTRIBUTE, XSS_PROOF_SETTLE_SECONDS, XSS_PROOF_TIMEOUT_MS, xss_proof_marker,
        xss_proof_signal,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from ..capabilities.xss_proof_payload import (
        XSS_PROOF_ATTRIBUTE, XSS_PROOF_SETTLE_SECONDS, XSS_PROOF_TIMEOUT_MS, xss_proof_marker,
        xss_proof_signal,
    )
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
# Answers that say the service, not a fix, decided what the check saw. One of these anywhere (down,
# overloaded, rate-limiting) leaves the check's comparisons meaningless; so does a missing page or
# a server error when every request met one. A check that reproduces still proves the finding.
_UNAVAILABLE = frozenset({408, 429, 502, 503, 504})
_MISSING = frozenset({404, 410})


def _unavailable(statuses: Any) -> int | None:
    """The status that makes a check's answers unusable, or None."""
    answered = [int(item) for item in statuses if item]
    blocking = next((item for item in answered if item in _UNAVAILABLE), None)
    if blocking is not None:
        return blocking
    if answered and all(item in _MISSING or item >= 500 for item in answered):
        return answered[0]
    return None


def _unavailable_reason(status: int) -> str:
    if status == 429:
        what = f"asked the retest to slow down (HTTP {status})"
    elif status in _UNAVAILABLE:
        what = f"was unavailable (HTTP {status})"
    elif status in _MISSING:
        what = f"answered every request with HTTP {status} (no such page)"
    else:
        what = f"answered every request with a server error (HTTP {status})"
    return (f"The target {what}, so the check that proved the finding could not compare its "
            "answers: nothing was reproduced or ruled out, and the finding stays open.")


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
        # Every answer's status (0 when none came), for ``_unavailable``.
        self.statuses: list[int] = []

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
        self.statuses.append(status)
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

    transport = RetestFetchTransport(fetch)
    adapter = _adapter(request, target_id, transport)
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
    unavailable = _unavailable(transport.statuses)
    if unavailable is not None:
        proof["unavailable_status"] = unavailable
        return "unavailable", proof
    return "not_reproduced", proof


# What the browser proof lets a page send: same-origin reads, at most this many requests.
_BROWSER_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_BROWSER_MAX_REQUESTS = 50
_BROWSER_CLOSE_SECONDS = 10.0


def _url_origin(url: str) -> tuple[str, str, int | None] | None:
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError:
        return None
    return (parsed.scheme.lower(), (parsed.hostname or "").lower(), port)


def _payload_url(request: ProofRetestRequest, value: str) -> str:
    """The page with the tested parameter set to ``value``, as the browser proof builds it."""
    parsed = urllib.parse.urlsplit(request.url)
    pairs = [(name, value if name == request.param else item)
             for name, item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(pairs, doseq=True)))


async def _marker_check(
    url: str, marker: str, *, poe: Any, headers: Mapping[str, str] | None, cancelled: Callable[[], bool],
) -> tuple[str, dict[str, Any]]:
    """Load the payload page once and apply the browser proof's oracle to it."""
    try:
        context = await poe.proof_browser_context(url, headers=dict(headers or {}) or None)
    except TimeoutError:  # the proof module's BrowserUnresponsive: it has let that browser go
        return "browser_unresponsive", {}
    if context is None:
        return "no_browser", {}
    origin = _url_origin(url)
    signals: list[str] = []
    blocked = 0
    sent = 0

    async def route(handled: Any) -> None:
        nonlocal blocked, sent
        request = handled.request
        if (
            cancelled() or _url_origin(request.url) != origin
            or str(request.method).upper() not in _BROWSER_SAFE_METHODS or sent >= _BROWSER_MAX_REQUESTS
        ):
            blocked += 1
            await handled.abort("blockedbyclient")
            return
        sent += 1
        await handled.continue_()

    async def dialog(opened: Any) -> None:
        if xss_proof_signal(opened.message, marker):
            signals.append("dialog")
        await opened.dismiss()

    def console(message: Any) -> None:
        if xss_proof_signal(message.text, marker):
            signals.append("console")

    try:
        try:
            page = await poe.proof_browser_page(context, route=route)
        except TimeoutError:  # BrowserUnresponsive, as above
            return "browser_unresponsive", {}
        page.on("dialog", dialog)
        page.on("console", console)
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=XSS_PROOF_TIMEOUT_MS)
        except Exception as exc:  # no page to judge: nothing reproduced, nothing ruled out
            return "failed", {"errors": [type(exc).__name__]}
        await asyncio.sleep(XSS_PROOF_SETTLE_SECONDS)
        dom = xss_proof_signal(await page.get_attribute("html", XSS_PROOF_ATTRIBUTE), marker)
        status = int(response.status) if response is not None else 0
        final_url = page.url
        response_headers = dict(response.headers) if response is not None else {}
    finally:
        # Bounded: a context whose browser stopped answering must not hold the retest here.
        with contextlib.suppress(Exception):
            await asyncio.wait_for(context.close(), _BROWSER_CLOSE_SECONDS)
    technique = (
        "headless_xss_dialog" if "dialog" in signals else "headless_xss_console" if signals
        else "headless_xss_dom" if dom else None
    )
    proof = {
        "technique": technique, "dom_marker_executed": dom, "navigation_status": status,
        "blocked_requests": blocked,
    }
    if technique:
        return "reproduced", proof
    if _url_origin(final_url) != origin:
        return "left_origin", proof
    refused = poe.baseline_refusal(url, {"status_code": status, "headers": response_headers, "final_url": final_url})
    if refused:
        return refused, proof
    return "not_reproduced", proof


async def _browser_check(
    request: ProofRetestRequest, *, poe: Any, auth_headers: Mapping[str, str] | None,
    cancelled: Callable[[], bool],
) -> tuple[str, dict[str, Any]]:
    """The proof's own payload and oracle in a headless browser, after one ordinary request."""
    ordinary = _payload_url(request, "shakerscan")
    baseline = await poe.fetch_with_capture(ordinary, timeout=12)
    status = int(baseline.get("status_code") or 0)
    if not status:
        return "failed", {"errors": [_error_code(baseline)]}
    refused = poe.baseline_refusal(ordinary, baseline)
    if refused:
        return refused, {"baseline_status": status}
    if status in _UNAVAILABLE:
        return "unavailable", {"baseline_status": status, "unavailable_status": status}
    if not await poe.headless_browser_available():
        return "no_browser", {}
    outcome, proof = await _marker_check(
        _payload_url(request, request.payload or ""), xss_proof_marker(request.candidate_id),
        poe=poe, headers=auth_headers, cancelled=cancelled,
    )
    proof["baseline_status"] = status
    unavailable = _unavailable((status, proof.get("navigation_status")))
    if outcome == "not_reproduced" and unavailable is not None:
        proof["unavailable_status"] = unavailable
        return "unavailable", proof
    return outcome, proof


async def run_proof_retest(
    verification: Mapping[str, Any], inputs: Mapping[str, Any], *, poe: Any,
    replay_commands: list[str], ladder: list[str], cancelled: Callable[[], bool],
) -> dict[str, Any] | None:
    """The retest of a proven Scan finding, or None for any other finding.

    ``poe`` is the scanner's proof module (``fetch_with_capture``, ``baseline_refusal``,
    ``headless_browser_available``, ``proof_browser_context``, ``proof_browser_page``, the session
    calls). The retest's session headers are the ones the finding's Scan was given
    (``auth_context``).
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
            outcome, proof = await _browser_check(request, poe=poe, auth_headers=auth_headers, cancelled=cancelled)
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
    if outcome == "unavailable":
        return _result(status="completed", result_status="inconclusive", verdict="inconclusive",
                       reason=_unavailable_reason(int(proof["unavailable_status"])),
                       proof=proof, artifacts=artifacts, **common)
    if outcome == "left_origin":
        return _result(status="completed", result_status="inconclusive", verdict="inconclusive",
                       reason="The page sent the browser to another site, so the browser check that "
                              "proved the finding could not run on it; the finding stays open.",
                       proof=proof, artifacts=artifacts, **common)
    if outcome == "no_browser":
        return _result(status="completed", result_status="inconclusive", verdict="inconclusive",
                       reason="This worker has no headless browser, so the browser check that proved "
                              "the finding could not run; the finding stays open.",
                       proof=proof, artifacts=artifacts, **common)
    if outcome == "browser_unresponsive":
        return _result(status="completed", result_status="inconclusive", verdict="inconclusive",
                       reason="The headless browser did not answer in time, so the browser check that "
                              "proved the finding could not run; the finding stays open.",
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

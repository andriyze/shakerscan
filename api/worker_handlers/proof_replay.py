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
a missing browser or one that does not answer is inconclusive, and the finding stays open. In the
browser "every request" includes the page's own (``_PageActivity``): a same-origin script or frame
that answered with an error, a script, frame or data request that a service refused (408, 429,
5xx), failed on the network, or that the retest's request cap cut, and a request still open when
the proof's page timeout ran out leave the page not running as it did when the finding was proved,
and the retest inconclusive. The page's data requests are judged against the proof's own page,
which the finding keeps (``browser_proof.page_requests``): one the proof saw answered must be
answered again, and one that also failed or never answered then (a guest's ``/api/me`` answering
401, a long poll) does not count. An open event stream counts as answered. A failed image, style
or font, an image the cap cut, a data request the page cancels itself, and a request to another
origin (blocked as the proof blocks it) do not count. Nothing here escalates to the AI tier.
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
    from runtime.auth_refusal import (
        MISSING_STATUSES, TARGET_UNAVAILABLE, UNAVAILABLE_STATUSES, unavailable_status,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.auth_refusal import (
        MISSING_STATUSES, TARGET_UNAVAILABLE, UNAVAILABLE_STATUSES, unavailable_status,
    )
try:
    from proof_retest import PROOF_RETEST_GAPS, ProofRetestRequest, proof_retest_request
    from retest_contract import auth_context_to_headers, parse_json_field
    from worker_handlers.retest_outcome import _internal_retest_scope_authorized, classify_retest_outcome
except ModuleNotFoundError:  # package import in host-side tests
    from ..proof_retest import PROOF_RETEST_GAPS, ProofRetestRequest, proof_retest_request
    from ..retest_contract import auth_context_to_headers, parse_json_field
    from .retest_outcome import _internal_retest_scope_authorized, classify_retest_outcome
try:
    from scanner_tools.url_redaction import redact_url
except ModuleNotFoundError:  # package import in host-side tests
    from scanner.scanner_tools.url_redaction import redact_url


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
# The Scan's proofs apply the same rule (``auth_refusal.unavailable_status``).
_UNAVAILABLE = UNAVAILABLE_STATUSES
_MISSING = MISSING_STATUSES
_unavailable = unavailable_status


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
    unavailable = _unavailable(transport.statuses)
    if refusal == TARGET_UNAVAILABLE and unavailable is not None:
        # The check itself read the answers as the service's (``unavailable_status``).
        proof["unavailable_status"] = unavailable
        return "unavailable", proof
    if result.status != "success" or result.errors or not observations:
        return "failed", proof
    if unavailable is not None:
        proof["unavailable_status"] = unavailable
        return "unavailable", proof
    return "not_reproduced", proof


# What the browser proof lets a page send: same-origin reads, at most this many requests.
_BROWSER_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_BROWSER_MAX_REQUESTS = 50
_BROWSER_CLOSE_SECONDS = 10.0
# The page's own requests that carry its application: when one of these fails, the page did not
# run as it did when the finding was proved. A failed image, style or font does not stop a script.
_APPLICATION_RESOURCES = frozenset({"document", "script", "fetch", "xhr", "eventsource"})
# Its data requests: judged against what the proof's own page saw (``browser_proof.page_requests``,
# recorded by the Scan), since a working page may expect one to fail (a guest's ``/api/me``
# answering 401) or never to finish (a long poll).
_DATA_RESOURCES = frozenset({"fetch", "xhr", "eventsource"})
# An event stream's body never finishes by design: once its headers arrive it is answered.
_STREAM_RESOURCES = frozenset({"eventsource"})
# Answers that say the service, not the page, decided: on any of the page's own requests.
_SERVICE_REFUSALS = frozenset({408, 429})
_SESSION_REFUSALS = frozenset({401, 403})
# How long the requests the page still has open may keep a negative answer waiting, past the
# proof's settle: up to the proof's own page timeout.
_PENDING_POLL_SECONDS = 0.1
_PENDING_QUIET_SECONDS = 0.25


def _proof_page_requests(verification: Mapping[str, Any]) -> Any:
    """The browser proof page's own data requests the finding keeps, or None without them."""
    proof = parse_json_field(verification.get("evidence")).get("browser_proof")
    return proof.get("page_requests") if isinstance(proof, Mapping) else None


def _request_key(method: Any, url: Any) -> tuple[str, str]:
    """A request as the proof's record names it: the method and the path of the redacted URL."""
    try:
        path = urllib.parse.urlsplit(redact_url(str(url or ""))).path or "/"
    except ValueError:
        path = "/"
    return str(method or "GET").upper()[:10], path[:500]


def _proved_requests(recorded: Any) -> dict[tuple[str, str], bool] | None:
    """``{(method, path): answered}`` from a finding's ``page_requests``, or None without one."""
    if not isinstance(recorded, (list, tuple)):
        return None
    proved: dict[tuple[str, str], bool] = {}
    for item in recorded:
        if not isinstance(item, Mapping):
            continue
        key = (str(item.get("method") or "GET").upper()[:10], str(item.get("path") or "/")[:500])
        with contextlib.suppress(TypeError, ValueError):
            proved[key] = proved.get(key, False) or 100 <= int(item.get("status") or 0) < 400
    return proved


class _PageActivity:
    """What the page's same-origin requests did: answered with an error, failed, cut by the
    retest's request cap, or still open. The page's own navigation is judged elsewhere.

    A script or frame that answers with an error, and any of its application requests that a
    service refused (408, 429, 5xx) or that failed on the network, mean the page did not run as
    proved. Its data requests are judged against the proof's own page (``proved``, from the
    finding's ``browser_proof.page_requests``): one the proof saw answered must be answered again,
    while one that also failed or never answered then (a guest's 401, a long poll) does not count.
    For a finding recorded without them, a data request answering 401 or 403 counts only when the
    retest carries a session (``signed_in``: the session expired), and one still open at the
    timeout counts. A data request the page cancels itself (``net::ERR_ABORTED``) is not a failure
    by itself; the request cap counts only application requests."""

    def __init__(
        self, origin: tuple[str, str, int | None] | None, *,
        proved: Any = None, signed_in: bool = False,
    ) -> None:
        self.origin = origin
        self.pending: dict[int, Any] = {}
        self.failures: list[dict[str, Any]] = []
        self.capped = 0
        self.aborted: set[int] = set()
        self.proved = _proved_requests(proved)
        self.signed_in = signed_in
        self.answered_keys: set[tuple[str, str]] = set()

    @staticmethod
    def _key(request: Any) -> tuple[str, str]:
        with contextlib.suppress(Exception):
            return _request_key(getattr(request, "method", "GET"), request.url)
        return "GET", "/"

    def _proof_answered(self, request: Any) -> bool:
        return bool(self.proved and self.proved.get(self._key(request)))

    def application(self, request: Any) -> bool:
        """A request that carries the page's application (``_APPLICATION_RESOURCES``)."""
        return self._resource(request) in _APPLICATION_RESOURCES

    def _same_origin(self, request: Any) -> bool:
        with contextlib.suppress(Exception):
            return _url_origin(request.url) == self.origin
        return False

    @staticmethod
    def _main_navigation(request: Any) -> bool:
        with contextlib.suppress(Exception):
            frame = request.frame
            return bool(request.is_navigation_request()) and frame.parent_frame is None
        return False

    @staticmethod
    def _resource(request: Any) -> str:
        with contextlib.suppress(Exception):
            return str(request.resource_type or "")
        return ""

    def started(self, request: Any) -> None:
        if self._same_origin(request):
            self.pending[id(request)] = request

    def finished(self, request: Any) -> None:
        self.pending.pop(id(request), None)

    def failed(self, request: Any) -> None:
        self.pending.pop(id(request), None)
        if id(request) in self.aborted or not self._same_origin(request) or self._main_navigation(request):
            return
        resource = self._resource(request)
        if resource in _APPLICATION_RESOURCES:
            error = ""
            with contextlib.suppress(Exception):
                error = str(request.failure or "")
            if resource in _DATA_RESOURCES and "ERR_ABORTED" in error.upper():
                # The page cancelled its own call (superseded, or its own timeout): not a failure by
                # itself; a call the proof saw answered must still be answered (``_unanswered``).
                return
            self.failures.append({"resource_type": resource, "error": error[:80] or "failed"})

    def answered(self, response: Any) -> None:
        with contextlib.suppress(Exception):
            request = response.request
            status = int(response.status)
            if not self._same_origin(request) or self._main_navigation(request):
                return
            resource = self._resource(request)
            if status < 400:
                if resource in _STREAM_RESOURCES:
                    self.pending.pop(id(request), None)
                if resource in _DATA_RESOURCES:
                    self.answered_keys.add(self._key(request))
                return
            if resource in _APPLICATION_RESOURCES and self._error_counts(request, resource, status):
                self.failures.append({"resource_type": resource, "status": status})

    def _error_counts(self, request: Any, resource: str, status: int) -> bool:
        if status in _SERVICE_REFUSALS or status >= 500 or resource not in _DATA_RESOURCES:
            return True
        if self.proved is not None:
            return self._proof_answered(request)
        return self.signed_in or status not in _SESSION_REFUSALS

    def _pending_counts(self, request: Any) -> bool:
        """A request still open that keeps the page from having run as proved: any but a data
        request the proof's own page did not see answered either (a long poll)."""
        if self.proved is not None and self._resource(request) in _DATA_RESOURCES:
            return self._proof_answered(request)
        return True

    def waiting(self) -> bool:
        """Whether a request the page still has open may yet change the answer."""
        return any(self._pending_counts(item) for item in self.pending.values())

    def _unanswered(self) -> list[dict[str, str]]:
        """Data requests the proof's page saw answered that this page got no answer to: it did
        not make them, cancelled them, or they are still open."""
        if not self.proved:
            return []
        return [{"method": method, "path": path} for (method, path), answered in sorted(self.proved.items())
                if answered and (method, path) not in self.answered_keys][:10]

    def incomplete(self) -> dict[str, Any] | None:
        """Why the page did not run as proved, or None when every request it needed answered."""
        pending = [item for item in self.pending.values() if self._pending_counts(item)]
        unanswered = self._unanswered()
        if not (self.failures or self.capped or pending or unanswered):
            return None
        return {
            "failed": self.failures[:10],
            "pending": len(pending),
            "pending_resource_types": sorted({self._resource(item) for item in pending}),
            "capped": self.capped,
            **({"unanswered_since_proof": unanswered} if unanswered else {}),
        }


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
    proved: Any = None,
) -> tuple[str, dict[str, Any]]:
    """Load the payload page once and apply the browser proof's oracle to it. ``proved`` is the
    proof page's own data requests (``browser_proof.page_requests``), when the finding has them."""
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
    activity = _PageActivity(origin, proved=proved, signed_in=bool(headers))

    async def route(handled: Any) -> None:
        nonlocal blocked, sent
        request = handled.request
        same_origin = _url_origin(request.url) == origin
        safe = str(request.method).upper() in _BROWSER_SAFE_METHODS
        if cancelled() or not same_origin or not safe or sent >= _BROWSER_MAX_REQUESTS:
            blocked += 1
            activity.aborted.add(id(request))
            if same_origin and safe and not cancelled() and activity.application(request):
                # A script, frame or data request the retest's cap cut: the page did not run whole.
                # An image, style or font it cut does not stop the page's application.
                activity.capped += 1
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
        page.on("request", activity.started)
        page.on("requestfinished", activity.finished)
        page.on("requestfailed", activity.failed)
        page.on("response", activity.answered)
        loaded = time.monotonic()
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=XSS_PROOF_TIMEOUT_MS)
        except Exception as exc:  # no page to judge: nothing reproduced, nothing ruled out
            return "failed", {"errors": [type(exc).__name__]}
        await asyncio.sleep(XSS_PROOF_SETTLE_SECONDS)
        dom = xss_proof_signal(await page.get_attribute("html", XSS_PROOF_ATTRIBUTE), marker)
        # Requests the page still has open (a slow script, the call its sink waits for, the
        # payload's own image) may yet run the payload: wait for them, within the proof's own page
        # timeout. A marker that fires meanwhile is the same oracle's answer.
        # Once they have finished, a short quiet spell lets what they started run (and start more).
        # An open event stream, and a long poll the proof's own page never saw answered either, do
        # not hold it (``_PageActivity.waiting``).
        deadline = loaded + XSS_PROOF_TIMEOUT_MS / 1000
        quiet_since: float | None = None
        while activity.waiting() or quiet_since is not None:
            if signals or dom or cancelled() or time.monotonic() >= deadline:
                break
            if activity.waiting():
                quiet_since = None
            else:
                quiet_since = quiet_since or time.monotonic()
                if time.monotonic() - quiet_since >= _PENDING_QUIET_SECONDS:
                    break
            await asyncio.sleep(_PENDING_POLL_SECONDS)
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
    incomplete = activity.incomplete()
    if incomplete is not None:
        # The page did not run as it did when the finding was proved: no negative answer.
        proof["page_incomplete"] = incomplete
        return "page_incomplete", proof
    return "not_reproduced", proof


def _page_incomplete_reason(incomplete: Mapping[str, Any]) -> str:
    failed = list(incomplete.get("failed") or ())
    if failed:
        first = failed[0]
        kind = str(first.get("resource_type") or "request")
        what = {"script": "script", "document": "frame", "fetch": "data request",
                "xhr": "data request", "eventsource": "data request"}.get(kind, "request")
        answer = (f"answered HTTP {first['status']}" if first.get("status")
                  else "failed before it was answered")
        cause = f"One of the page's own {what}s {answer}"
    elif incomplete.get("capped"):
        cause = "The page made more requests than the retest allows, and the rest were not sent"
    elif incomplete.get("pending"):
        cause = "The page's own requests did not all finish loading in time"
    else:
        cause = ("A data request the page made when the finding was proved got no answer this "
                 "time (it was not made, was cancelled or is still open)")
    return (f"{cause}, so the page did not run as it did when the finding was proved: nothing was "
            "reproduced or ruled out, and the finding stays open.")


async def _browser_check(
    request: ProofRetestRequest, *, poe: Any, auth_headers: Mapping[str, str] | None,
    cancelled: Callable[[], bool], proved: Any = None,
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
        poe=poe, headers=auth_headers, cancelled=cancelled, proved=proved,
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
            outcome, proof = await _browser_check(
                request, poe=poe, auth_headers=auth_headers, cancelled=cancelled,
                proved=_proof_page_requests(verification),
            )
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
    if outcome == "page_incomplete":
        return _result(status="completed", result_status="inconclusive", verdict="inconclusive",
                       reason=_page_incomplete_reason(proof.get("page_incomplete") or {}),
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

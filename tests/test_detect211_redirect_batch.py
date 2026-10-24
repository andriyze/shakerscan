"""The ``redirect.verify_batch`` action end to end over a fake transport (no target contacted)."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import urllib.parse
import uuid

import pytest

import scan.action_adapter as action_adapter_module
from runtime.models import ScanPolicy
from runtime.observation_manifests import ObservationManifest
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlan
from scan.capability_result import (
    CapabilityReceiptReference, CapabilityResultReference, CapabilityResultStatus,
)
from scan.execution_backend import PostgresScanExecutionBackend
from scan.finalizer import finalize_scan_report
from scan.work_manifests import build_endpoint_manifest

from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop


def _manifest(scan_id: str, routes):
    return build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": path, "concrete_path": path, "query_keys": list(keys),
                "source": "web.crawl",
            } for path, keys in routes],
        },
        source_action_ids=("discover.web_crawl",),
    )


class _Transport:
    def __init__(self, unanswered=None):
        self.sent: list[str] = []
        # path -> the pinned transport's error_code for a request that got no HTTP answer.
        self.unanswered = dict(unanswered or {})

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        assert follow_redirects is False and request.method == "GET" and not request.body
        self.sent.append(request.url)
        parts = urllib.parse.urlsplit(request.url)
        query = dict(urllib.parse.parse_qsl(parts.query))
        if parts.path in self.unanswered:  # what PinnedAiohttpReplayTransport returns, never raises
            error_code = self.unanswered[parts.path]
            return ReplayTransportResult(status_code=None, connected_address=None, final_url=request.url,
                                         response_headers={}, response_body=b"",
                                         elapsed_ms=int(timeout_seconds * 1000) if error_code == "timeout" else 3,
                                         error_code=error_code, timed_out=error_code == "timeout")
        if parts.path == "/go":  # vulnerable: redirects anywhere
            return ReplayTransportResult(status_code=302, connected_address="192.0.2.10", final_url=request.url,
                                         response_headers={"Location": query.get("next", "/")}, response_body=b"", elapsed_ms=2)
        if parts.path == "/login":  # safe: only same-site paths
            return ReplayTransportResult(status_code=302, connected_address="192.0.2.10", final_url=request.url,
                                         response_headers={"Location": "/home"}, response_body=b"", elapsed_ms=2)
        return ReplayTransportResult(status_code=200, connected_address="192.0.2.10", final_url=request.url,
                                     response_headers={}, response_body=b"ok", elapsed_ms=2)


def _redirect_action(manifest, *, http=100):
    action = _action("verify.redirect", "redirect.verify_batch", 0, capability_args={
        "endpoint_manifest_ref": manifest.reference().canonical_dict(),
        "slice": {"start": 0, "count": 100}, "profile": "balanced",
        "proof_policy": "deterministic_proof_contract_required",
    })
    return replace(action, requested_budget={"http_requests": http, "tool_wall_seconds": 60}, action_digest=None)


def _run(monkeypatch, routes, *, http=100, backend=None, manifest=None, scan_id=None, unanswered=None):
    scan_id = scan_id or str(uuid.uuid4())
    manifest = manifest or _manifest(scan_id, routes)
    transport = _Transport(unanswered)
    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", lambda **_: transport)
    action = _redirect_action(manifest, http=http)
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    backend = backend or Backend(manifests={manifest.manifest_id: manifest})
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy(active_testing=True))
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt, transport, backend, manifest, scan_id


ROUTES = (("/go", ("next",)), ("/login", ("returnUrl",)), ("/search", ("q",)), ("/about", ()))


def test_only_the_redirect_that_follows_the_parameter_is_proven(monkeypatch):
    receipt, transport, *_ = _run(monkeypatch, ROUTES)
    proofs = [item for item in receipt.observations if item.get("kind") == "open_redirect_proof"]
    assert {(urllib.parse.urlsplit(p["url"]).path, p["proof_state"]) for p in proofs} == {
        ("/go", "verified"), ("/login", "not_proven"),
    }
    # One GET per redirect-named parameter; routes without one are never requested.
    assert sorted(urllib.parse.urlsplit(url).path for url in transport.sent) == ["/go", "/login"]
    assert all("shakerscan-redirect-probe.invalid" in urllib.parse.unquote(url) for url in transport.sent)
    inapplicable = {item["reason"] for item in receipt.observations if item.get("kind") == "candidate_inapplicable"}
    assert inapplicable == {"no_redirect_parameter"}
    assert receipt.status == "success"


def test_the_request_ceiling_stops_the_batch_and_resume_finishes_it(monkeypatch):
    receipt, transport, backend, manifest, scan_id = _run(monkeypatch, ROUTES, http=1)
    assert receipt.status == "partial" and len(transport.sent) == 1
    resumed, transport, *_ = _run(monkeypatch, ROUTES, backend=backend, manifest=manifest, scan_id=scan_id)
    assert len(transport.sent) == 1  # the checkpointed probe is not sent again
    assert len([item for item in resumed.observations if item.get("kind") == "open_redirect_proof"]) == 2


def _path(url):
    return urllib.parse.urlsplit(url).path


def _kind(receipt, kind):
    return [item for item in receipt.observations if item.get("kind") == kind]


def _settled(receipt, action):
    """The durable result the execution backend settles this receipt to (no database)."""
    status, reason = PostgresScanExecutionBackend._receipt_outcome(PostgresScanExecutionBackend, receipt)
    return CapabilityResultReference(
        action_id=action.action_id, action_digest=str(action.action_digest),
        capability_name=action.capability_name, adapter_name=receipt.adapter_name,
        adapter_version=receipt.adapter_version, output_schema=action.output_schema,
        status=status, partial=status in {CapabilityResultStatus.PARTIAL, CapabilityResultStatus.TIMED_OUT},
        timed_out=status is CapabilityResultStatus.TIMED_OUT, reason_code=reason,
        receipt_ref=CapabilityReceiptReference(receipt_id=receipt.receipt_id, receipt_hash=receipt.receipt_hash),
        observation_manifest_ref=ObservationManifest(
            manifest_id=str(uuid.uuid4()), owner_id=receipt.scan_id, action_id=action.action_id,
            capability_name=action.capability_name, output_schema=action.output_schema,
            observation_count=len(receipt.observations), content_sha256="0" * 64, size_bytes=512,
            object_key=f"scans/{receipt.scan_id}/{action.action_id}.jsonl",
        ).reference(),
        budget_reserved=receipt.budget_reserved, budget_consumed=receipt.budget_consumed,
    )


def _report(receipt, manifest):
    # The compiled plan's verify.redirect is best-effort, never required.
    action = replace(_redirect_action(manifest), required=False, action_digest=None)
    final = _action("finalize.report", "scan.finalize", 1, dependencies=(action.action_id,))
    plan = ScanActionPlan(scan_id=receipt.scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action, final))
    return finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results={action.action_id: _settled(receipt, action)},
        observations={action.action_id: tuple(dict(item) for item in receipt.observations)},
    )


UNANSWERED_ROUTES = (("/go", ("next",)), ("/login", ("returnUrl",)), ("/about", ()))


@pytest.mark.parametrize(("error_code", "reason", "stated"), [
    ("timeout", "timed_out", "timed_out"),
    ("transport_error", "transport_error", "adapter_failed"),  # a connection reset or refused
])
def test_a_probe_that_got_no_answer_is_a_gap_not_an_examined_negative(monkeypatch, error_code, reason, stated):
    receipt, transport, backend, manifest, _ = _run(
        monkeypatch, UNANSWERED_ROUTES, unanswered={"/go": error_code},
    )
    assert sorted(_path(url) for url in transport.sent) == ["/go", "/login"]
    proofs = {_path(item["url"]): item for item in _kind(receipt, "open_redirect_proof")}
    # The parameter was never tested: inconclusive for that reason, never "not proven".
    assert proofs["/go"]["proof_state"] == "unproven"
    assert proofs["/go"]["finding_verdict"] == "inconclusive"
    assert proofs["/go"]["inconclusive_reason"] == reason
    assert proofs["/go"]["status"] is None and proofs["/go"]["location"] == ""
    # The route that answered is examined as before.
    assert proofs["/login"]["proof_state"] == "not_proven" and "inconclusive_reason" not in proofs["/login"]
    attempts = {item["proof_state"]: item for item in _kind(receipt, "candidate_attempt")}
    assert set(attempts) == {"unproven", "not_proven"}
    assert attempts["unproven"]["status"] != "success"
    assert attempts["unproven"]["verdict"] == "inconclusive"
    assert attempts["unproven"]["inconclusive_reason"] == reason
    assert attempts["not_proven"]["status"] == "success"
    # Only the answered probe is checkpointed, so a resumed batch sends the other again.
    checkpoints = backend.attempts["verify.redirect"]
    assert set(checkpoints) == {attempts["not_proven"]["attempt_id"]}
    assert checkpoints[attempts["not_proven"]["attempt_id"]]["proof_state"] == "not_proven"
    # Every candidate was attempted, so the batch did not time out; it is partial and says why.
    assert receipt.status == "partial" and receipt.partial is True and receipt.timed_out is False
    assert receipt.errors[0] == stated
    assert receipt.redacted_execution["unanswered_count"] == 1
    assert receipt.redacted_execution["unattempted_count"] == 0
    settled = _settled(receipt, _redirect_action(manifest))
    assert settled.status is CapabilityResultStatus.PARTIAL and settled.reason_code.value == stated
    coverage = _report(receipt, manifest)["coverage"]
    assert {(gap["action_id"], gap["status"], gap["reason_code"]) for gap in coverage["optional_gaps"]} == {
        ("verify.redirect", "partial", stated),
    }
    assert coverage["capability_coverage"]["completed"] == 0


def test_a_resumed_batch_probes_the_unanswered_parameter_again(monkeypatch):
    first, _transport, backend, manifest, scan_id = _run(
        monkeypatch, UNANSWERED_ROUTES, unanswered={"/go": "timeout"},
    )
    assert first.status == "partial"
    assert [item for item in _report(first, manifest)["findings"] if item.get("title") == "Open redirect"] == []
    # The target now answers: only the probe that never got an answer is sent again.
    resumed, transport, *_ = _run(
        monkeypatch, UNANSWERED_ROUTES, backend=backend, manifest=manifest, scan_id=scan_id,
    )
    assert [_path(url) for url in transport.sent] == ["/go"]
    assert {(_path(item["url"]), item["proof_state"]) for item in _kind(resumed, "open_redirect_proof")} == {
        ("/go", "verified"), ("/login", "not_proven"),
    }
    assert resumed.status == "success" and resumed.redacted_execution["resumed_count"] == 1
    report = _report(resumed, manifest)
    findings = [item for item in report["findings"] if item.get("title") == "Open redirect"]
    assert len(findings) == 1 and findings[0]["evidence"]["parameter"] == "next"
    assert report["coverage"]["optional_gaps"] == []


def test_the_cors_probes_send_their_fixed_origin_anonymously(monkeypatch):
    from scan.posture_findings import CORS_PROBE_ACTIONS
    from tests.test_scan_action_adapter import _principal

    for action_id, origin in CORS_PROBE_ACTIONS.items():
        action = _action(action_id, "http.request", 0)
        plan = ScanActionPlan(scan_id=str(uuid.uuid4()), execution_plan_digest="a" * 64,
                              target_binding_digest=TARGET.digest, actions=(action,))
        captured = {}

        async def execute_bound(_origin, args, **kwargs):
            captured.update(args=dict(args), **kwargs)
            return {"ok": True, "response": {"status": 200, "security_headers": {
                "access-control-allow-origin": origin}}, "request": {"path": "/"}}

        monkeypatch.setattr(action_adapter_module, "execute_bound_http_request", execute_bound)
        monkeypatch.setattr(action_adapter_module, "resolve_scan_http_principal",
                            lambda _options, *, lane, capability_name: _principal(lane))
        receipt = asyncio.run(_dispatcher(plan, Backend())(action, _lease(plan, action), _noop))
        assert receipt.status == "success"
        assert captured["args"]["headers"] == {"Origin": origin}
        assert captured["args"]["method"] == "GET" and captured["args"]["follow_redirects"] is False
        assert captured["trusted_headers"] is None and captured["principal_slot"] == "anonymous"

"""The ``redirect.verify_batch`` action end to end over a fake transport (no target contacted)."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import urllib.parse
import uuid

import scan.action_adapter as action_adapter_module
from runtime.models import ScanPolicy
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlan
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
    def __init__(self):
        self.sent: list[str] = []

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        assert follow_redirects is False and request.method == "GET" and not request.body
        self.sent.append(request.url)
        parts = urllib.parse.urlsplit(request.url)
        query = dict(urllib.parse.parse_qsl(parts.query))
        if parts.path == "/go":  # vulnerable: redirects anywhere
            return ReplayTransportResult(status_code=302, connected_address="192.0.2.10", final_url=request.url,
                                         response_headers={"Location": query.get("next", "/")}, response_body=b"", elapsed_ms=2)
        if parts.path == "/login":  # safe: only same-site paths
            return ReplayTransportResult(status_code=302, connected_address="192.0.2.10", final_url=request.url,
                                         response_headers={"Location": "/home"}, response_body=b"", elapsed_ms=2)
        return ReplayTransportResult(status_code=200, connected_address="192.0.2.10", final_url=request.url,
                                     response_headers={}, response_body=b"ok", elapsed_ms=2)


def _run(monkeypatch, routes, *, http=100, backend=None, manifest=None, scan_id=None):
    scan_id = scan_id or str(uuid.uuid4())
    manifest = manifest or _manifest(scan_id, routes)
    transport = _Transport()
    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", lambda **_: transport)
    action = _action("verify.redirect", "redirect.verify_batch", 0, capability_args={
        "endpoint_manifest_ref": manifest.reference().canonical_dict(),
        "slice": {"start": 0, "count": 100}, "profile": "balanced",
        "proof_policy": "deterministic_proof_contract_required",
    })
    action = replace(action, requested_budget={"http_requests": http, "tool_wall_seconds": 60}, action_digest=None)
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

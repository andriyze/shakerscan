"""A scheme-less target's exposure and spec probes use the origin the scan selected (soak N38).

``honey.shakerscan.com`` entered without a scheme is frozen with ``allowed_origins`` http then
https. ``scan.origin_select`` chose https, but ``_exposure_origin`` took the first frozen
origin, so both seed sweeps of scan 1c7b0a60 hit ``http://`` (90 x 302) and verified 12
exposures where the https run verified 19.
"""

from __future__ import annotations

import asyncio
import uuid

import scan.action_adapter as action_adapter_module
from runtime.models import ScanPolicy, TargetBinding
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlan
from scan.capability_execution import SCAN_BASE_ORIGIN_CAPABILITIES
from scan.work_manifests import build_endpoint_manifest

from tests.test_exposure_probe_batch_controls import DOTENV
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop

ORIGINS = ("http://app.example.test", "https://app.example.test")
SCHEMELESS = TargetBinding(
    target_id=TARGET.target_id, target_kind="web", canonical_host=TARGET.canonical_host,
    # Admission froze http first, as for honey.
    allowed_origins=ORIGINS, inferred_origins=ORIGINS,
    allowed_addresses=TARGET.allowed_addresses,
    allowed_root_domains=TARGET.allowed_root_domains,
)


class _Transport:
    def __init__(self):
        self.sent: list[str] = []

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        self.sent.append(request.url)
        if request.url.startswith("http://"):
            # The http origin only redirects to https.
            return ReplayTransportResult(
                status_code=302, connected_address="192.0.2.10", final_url=request.url,
                response_headers={"Location": request.url.replace("http://", "https://")},
                elapsed_ms=3,
            )
        status, body = (200, DOTENV) if request.url.endswith("/.env") else (404, b"not found")
        return ReplayTransportResult(
            status_code=status, connected_address="192.0.2.10", final_url=request.url,
            response_headers={"Content-Type": "text/plain"}, response_body=body, elapsed_ms=3,
        )


def _plan_and_backend(*, selected: str | None):
    scan_id = str(uuid.uuid4())
    manifest = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=SCHEMELESS.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": "/app", "concrete_path": "/app",
                "query_keys": [], "source": "web.content_discover",
            }],
        },
        source_action_ids=("discover.content",),
    )
    origin = _action(
        "origin.select", "scan.origin_select", 0,
        capability_args={"origins": list(SCHEMELESS.inferred_origins)}, target=SCHEMELESS,
    )
    exposure = _action(
        "verify.exposure", "exposure.verify_batch", 1,
        capability_args={
            "endpoint_manifest_ref": manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 100},
            "profile": "balanced",
            "proof_policy": "deterministic_proof_contract_required",
        },
        target=SCHEMELESS,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=SCHEMELESS.digest, actions=(origin, exposure),
    )
    backend = Backend(
        manifests={manifest.manifest_id: manifest},
        observations={"origin.select": ({
            "kind": "origin_selection_observation", "selected_origin": selected,
            "attempts": [{"origin": item, "attempted": True} for item in ORIGINS],
        },)},
    )
    return plan, backend, exposure


def _run(monkeypatch, *, selected):
    transport = _Transport()
    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", lambda **_: transport)
    plan, backend, exposure = _plan_and_backend(selected=selected)
    dispatcher = _dispatcher(
        plan, backend, target=SCHEMELESS, policy=ScanPolicy(), target_url="app.example.test",
    )
    receipt = asyncio.run(dispatcher(exposure, _lease(plan, exposure), _noop))
    return receipt, transport


def test_the_seed_sweep_runs_on_the_selected_https_origin(monkeypatch):
    receipt, transport = _run(monkeypatch, selected="https://app.example.test")
    assert transport.sent, receipt
    assert all(url.startswith("https://app.example.test/") for url in transport.sent)
    assert any(
        item.get("kind") == "sensitive_exposure_proof" and item.get("proof_state") == "verified"
        for item in receipt.observations
    )


def test_an_unselected_origin_skips_instead_of_guessing_http(monkeypatch):
    receipt, transport = _run(monkeypatch, selected=None)
    assert transport.sent == []
    assert receipt.status == "skipped"
    assert receipt.errors == ("origin_unreachable",)


def test_the_exposure_and_spec_actions_wait_for_origin_selection():
    assert {"exposure.verify_batch", "web.spec_ingest"} <= SCAN_BASE_ORIGIN_CAPABILITIES

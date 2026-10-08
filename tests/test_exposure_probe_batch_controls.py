"""The exposure batch proves a match is path-specific, never fetches a heap dump, and leaks nothing.

A host that answers every path with the same 200 body would let one body that happens to match
a signature "verify" every seed. The batch therefore reads two paths that cannot exist the first
time a signature matches, and a match byte-identical to the host's answer for an absent path is
not a finding. Twin: the same body served only at /.env verifies.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

import scan.action_adapter as action_adapter_module
import workflow_experiment
from capabilities import secret_material
from runtime.models import ScanPolicy
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlan
from scan.work_manifests import build_endpoint_manifest

from tests.test_scan_action_adapter import (
    TARGET,
    Backend,
    _action,
    _dispatcher,
    _lease,
    _noop,
)

PASSWORD = "Vt9qLx2Rm7Zp4Kw8sJ3n"
STRIPE = "sk_" + "live_" + "Qz7Lm2Xc9Vb4Nr8Tk1Wp6Hd"
DOTENV = f"DB_PASSWORD={PASSWORD}\nSTRIPE_SECRET_KEY={STRIPE}\nAPP_ENV=prod\n".encode()


def _manifest(scan_id: str, paths: tuple[str, ...]):
    return build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": path, "concrete_path": path,
                "query_keys": [], "source": "web.content_discover",
            } for path in paths],
        },
        source_action_ids=("discover.content",),
    )


class _Transport:
    def __init__(self, answer):
        self.answer = answer
        self.sent: list[str] = []

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        assert follow_redirects is False and request.method == "GET"
        self.sent.append(request.url)
        status, body = self.answer(request.url)
        return ReplayTransportResult(
            status_code=status, connected_address="192.0.2.10", final_url=request.url,
            response_headers={"Content-Type": "text/plain"}, response_body=body, elapsed_ms=3,
        )


def _run(monkeypatch, answer, *, paths=("/app",)):
    scan_id = str(uuid.uuid4())
    manifest = _manifest(scan_id, paths)
    transport = _Transport(answer)
    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", lambda **_: transport)
    action = _action(
        "verify.exposure", "exposure.verify_batch", 0,
        capability_args={
            "endpoint_manifest_ref": manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 100},
            "profile": "balanced",
            "proof_policy": "deterministic_proof_contract_required",
        },
    )
    action = type(action)(**{**action.__dict__, "requested_budget": {
        "http_requests": 300, "tool_wall_seconds": 180,
    }})
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    backend = Backend(manifests={manifest.manifest_id: manifest})
    # Passive policy: the read-only exposure checks need no active-testing authority.
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy())
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    proofs = [item for item in receipt.observations if item.get("kind") == "sensitive_exposure_proof"]
    return receipt, proofs, transport


def test_a_body_served_for_every_path_is_not_a_finding(monkeypatch):
    receipt, proofs, transport = _run(monkeypatch, lambda _url: (200, DOTENV))
    assert not [item for item in proofs if item.get("proof_state") == "verified"]
    assert receipt.redacted_execution["soft_404_controls_requested"] is True
    assert receipt.redacted_execution["indistinguishable_from_absent"] >= 5
    controls = [url for url in transport.sent if "/.shakerscan-absent-" in url]
    assert len(controls) == 2  # read once per batch, only after the first match


def test_the_same_body_served_only_at_dotenv_verifies(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)

    def answer(url):
        return (200, DOTENV) if url.endswith("/.env") else (404, b"not found")

    receipt, proofs, _transport = _run(monkeypatch, answer)
    verified = [item for item in proofs if item.get("proof_state") == "verified"]
    assert [item["exposure_class"] for item in verified] == ["environment_secret_file"]
    assert verified[0]["proof_contract"] == "dotenv_secret_exposure/v1"
    assert {item["field"] for item in verified[0]["exposure_fingerprints"]} == {"DB_PASSWORD", "STRIPE_SECRET_KEY"}
    assert receipt.redacted_execution["indistinguishable_from_absent"] == 0
    text = json.dumps([receipt.observations, receipt.redacted_execution], default=str) + caplog.text
    for canary in (PASSWORD, STRIPE):
        assert canary not in text


def test_a_site_with_nothing_exposed_spends_no_control_requests(monkeypatch):
    receipt, proofs, transport = _run(monkeypatch, lambda _url: (404, b"not found"))
    assert not proofs
    assert receipt.redacted_execution["soft_404_controls_requested"] is False
    assert not [url for url in transport.sent if "/.shakerscan-absent-" in url]


def test_heapdump_is_never_requested_and_seeds_are_not_requested_twice(monkeypatch):
    _receipt, _proofs, transport = _run(
        monkeypatch, lambda _url: (404, b"not found"),
        paths=("/actuator/heapdump", "/.env", "/.git/config", "/app"),
    )
    assert not [url for url in transport.sent if url.rstrip("/").endswith("/heapdump")]
    assert transport.sent.count("https://app.example.test/.env") == 1
    assert transport.sent.count("https://app.example.test/.git/config") == 1
    assert "https://app.example.test/app" in transport.sent


def test_hunt_and_dast_share_one_secret_contract():
    # The Hunt data_exposure verifier and the DAST probe read the same narrow set.
    assert workflow_experiment._SELF_EVIDENT_SECRET_PATTERNS is secret_material.SELF_EVIDENT_SECRET_PATTERNS
    assert workflow_experiment._is_placeholder_secret is secret_material.is_placeholder_secret
    body = f'{{"key":"{STRIPE}"}}'
    assert workflow_experiment._classify_selfevident_secret_values(body) == ["stripe_key"]


# Soak N42: a credential store is a reviewed seed, verified and never stored in clear (the
# classification tests are in tests/test_exposure_credential_stores.py).
GIT_TOKEN = "ghp_" + "Zt8Qw3Er6Ty9Ui2Op5As7Df1Gh4Jk0Lz3Xc6V"
GIT_CREDENTIALS = f"https://deploy:{GIT_TOKEN}@github.com\n"


def test_the_batch_verifies_git_credentials_and_keeps_the_token_out(monkeypatch):
    def answer(url):
        if url.endswith("/.git-credentials"):
            return 200, GIT_CREDENTIALS.encode()
        return 404, b"not found"

    receipt, proofs, transport = _run(monkeypatch, answer)
    assert "https://app.example.test/.git-credentials" in transport.sent
    verified = [item for item in proofs if item.get("proof_state") == "verified"]
    assert [item["request_url"] for item in verified] == ["https://app.example.test/.git-credentials"]
    assert verified[0]["proof_contract"] == "config_secret_exposure/v1"
    text = json.dumps([receipt.observations, receipt.redacted_execution], default=str)
    for canary in (GIT_TOKEN,):
        assert canary not in text

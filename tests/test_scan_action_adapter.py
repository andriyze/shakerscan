from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import urllib.parse
import uuid

import pytest

from hunt.capability_executor import CapabilityAdapterResult
from capabilities.auth import TargetBoundSessionCredential, WorkerPrivateScanSession
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import PreparedExecution, ScanPolicy, TargetBinding
from runtime.request_replay_executor import ReplayTransportResult
import scan.action_adapter as action_adapter_module
from runtime.observation_manifests import ObservationManifestReference
from scan.action_adapter import DatabaseNeutralScanActionDispatcher
from scan.action_plan import ScanAction, ScanActionPlan
from scan.private_inputs import (
    BROKER_PRIVATE_SCAN_INPUT_SCHEMA,
    BrokerPrivateScanInputs,
    private_replay_plan_payload,
)
from scan.private_state import (
    SCAN_PRIVATE_STATE_KEY_OPTION,
    generate_scan_private_state_key,
    seal_scan_auth_session_state,
)
from runtime.scan_credentials import (
    resolve_scan_http_principal,
    resolve_scan_interactive_credential,
)
from scan.capability_result import (
    CapabilityReceiptReference,
    CapabilityResultReference,
    CapabilityResultStatus,
)
from scan.execution_backend import ActionLease
from scan.work_manifests import (
    build_candidate_manifest,
    build_canonical_nuclei_template_manifest,
    build_canonical_passive_nuclei_template_manifest,
    build_endpoint_manifest,
    build_request_candidate_manifest,
    build_request_manifest,
)
try:
    from scanner_tools.request_replay import ReplayAuthorization, build_replay_plan
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import (
        ReplayAuthorization,
        build_replay_plan,
    )


TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)


def _action(
    action_id: str,
    capability: str,
    ordinal: int,
    *,
    dependencies=(),
    capability_args=None,
) -> ScanAction:
    spec = CAPABILITY_REGISTRY.require(capability)
    return ScanAction(
        action_id=action_id,
        stage="finalize_evidence" if action_id == "finalize.report" else "resolve_inputs",
        ordinal=ordinal,
        capability_name=capability,
        capability_args=(
            dict(capability_args)
            if capability_args is not None
            else {"report_only": True} if action_id == "finalize.report" else {}
        ),
        target_binding_digest=TARGET.digest,
        input_binding_digest=str(ordinal + 1) * 64,
        requested_budget=dict(spec.budget_cost),
        placement={
            "schema_version": "scan-action-placement/v1",
            "eligible_backends": ["local", "broker"],
            "requirements": dict(spec.placement_requirements),
            "adapter_name": spec.adapter,
            "adapter_version": spec.adapter_version,
        },
        dependencies=tuple(dependencies),
        required=True,
        supporting=False,
        output_schema=spec.output_schema,
    )


class Backend:
    def __init__(self, results=None, observations=None, manifests=None):
        self.results = dict(results or {})
        self.observations = dict(observations or {})
        self.manifests = dict(manifests or {})
        self.attempts = {}

    async def load_result(self, action_id):
        return self.results.get(action_id)

    async def load_observations(self, action_id):
        return tuple(self.observations.get(action_id) or ())

    async def load_work_manifest(self, _action_id, reference):
        return self.manifests[reference.manifest_id]

    async def load_batch_attempts(self, action_id):
        return tuple(self.attempts.get(action_id, {}).values())

    async def checkpoint_batch_attempt(self, action_id, attempt):
        self.attempts.setdefault(action_id, {})[attempt["attempt_id"]] = dict(attempt)


def _dispatcher(
    plan, backend, *, target=TARGET, policy=None, private_inputs=None,
    private_replay_plan_loader=None,
):
    async def process_runner(*_args, **_kwargs):
        raise AssertionError("process runner must not be used")

    return DatabaseNeutralScanActionDispatcher(
        target_url="https://app.example.test/",
        options={},
        target=target,
        policy=policy or ScanPolicy(),
        scan_id=plan.scan_id,
        job_id="job-1",
        worker_id="broker:worker-1",
        plan=plan,
        backend=backend,
        process_runner=process_runner,
        cancelled=lambda: False,
        private_inputs=private_inputs,
        private_replay_plan_loader=private_replay_plan_loader,
    )


def _principal(lane):
    return type("Principal", (), {
        "authenticated": True,
        "binding_digest": ("1" if lane == "primary" else "2") * 64,
        "headers": lambda self: {
            "Authorization": "Bearer " + lane,
        },
    })()


def _lease(plan, action):
    return ActionLease(
        lease_id=str(uuid.uuid4()),
        lease_token="x" * 32,
        scan_id=plan.scan_id,
        plan_digest=plan.plan_digest,
        execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=plan.target_binding_digest,
        action=action,
        backend="broker",
        worker_id="broker:worker-1",
        lease_seconds=60,
        attempt=1,
    )


def test_receipt_records_only_server_exercised_principal_context(monkeypatch):
    action = _action("baseline.http", "http.request", 0)
    plan = ScanActionPlan(
        scan_id=str(uuid.uuid4()), execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    monkeypatch.setattr(
        action_adapter_module, "resolve_scan_http_principal",
        lambda _options, *, lane, capability_name: _principal(lane),
    )
    receipt = _dispatcher(plan, Backend())._receipt(
        action, status="success", parser_version="test/v1",
        started_at=datetime.now(timezone.utc).isoformat(),
        consumed={"http_requests": 1, "tool_wall_seconds": 1},
    )
    context = next(item for item in receipt.observations if item["kind"] == "principal_context")
    assert context == {
        "kind": "principal_context",
        "lane": "primary",
        "authenticated": True,
        "binding_digest": "1" * 64,
        "source": "server_runtime",
    }
    assert "Authorization" not in json.dumps(receipt.observations)


def test_database_neutral_dispatcher_never_treats_profile_reference_as_secret():
    action = _action("inputs.auth_primary", "auth.session.establish", 0)
    plan = ScanActionPlan(
        scan_id=str(uuid.uuid4()),
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    dispatcher = _dispatcher(plan, Backend())

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "skipped"
    assert receipt.budget_consumed == {
        name: 0 for name in action.requested_budget
    }
    assert receipt.errors == ("not_applicable",)


def test_database_neutral_auth_uses_worker_private_session_contract(monkeypatch):
    scan_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    action = _action("inputs.auth_primary", "auth.session.establish", 0)
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    now = datetime.now(timezone.utc)
    key = generate_scan_private_state_key()
    options = {
        SCAN_PRIVATE_STATE_KEY_OPTION: key,
        "login_username": "operator",
        "login_password": "worker-private-password",
        "login_url": "/login",
        "resolved_credential_profiles": [{
            "profile_id": profile_id,
            "profile_version": 2,
            "auth_kind": "form_login",
            "principal_slot": "primary",
            "principal_label": "owner",
            "scan_lane": "primary",
            "allowed_capabilities": ["auth.session.establish", "http.request"],
        }],
    }
    private_inputs = BrokerPrivateScanInputs.from_payload(
        {
            "schema_version": BROKER_PRIVATE_SCAN_INPUT_SCHEMA,
            "lease_id": "lease-1",
            "worker_id": "broker:worker-1",
            "plan_digest": plan.plan_digest,
            "target_binding_digest": TARGET.digest,
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "options": options,
            "replay_plans": {},
        },
        lease_id="lease-1",
        worker_id="broker:worker-1",
        plan_digest=plan.plan_digest,
        target_binding_digest=TARGET.digest,
    )
    captured = {}

    async def establish(credential, *, target):
        captured["credential"] = credential
        captured["target"] = target
        return WorkerPrivateScanSession(
            lane="primary",
            auth_kind="form_login",
            binding_digest=credential.binding_digest,
            established=True,
            observation={"kind": "credential_session", "status": "established"},
            error=None,
            request_count=1,
            _headers={"Cookie": "session=worker-private-cookie"},
            session_ref=str(uuid.uuid4()),
            profile_id=profile_id,
            profile_version=2,
            principal="owner",
            established_at=now,
            expires_at=now + timedelta(hours=1),
            refresh_after=now + timedelta(minutes=55),
            compatible_capabilities=("auth.session.establish", "http.request"),
            evidence_receipt_digest="e" * 64,
        )

    monkeypatch.setattr(
        action_adapter_module, "establish_target_bound_http_session", establish,
    )
    dispatcher = _dispatcher(
        plan, Backend(), private_inputs=private_inputs,
    )

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    assert isinstance(captured["credential"], TargetBoundSessionCredential)
    assert captured["credential"].profile_id == profile_id
    assert captured["credential"].principal == "owner"
    assert captured["target"] == TARGET
    checkpoints = [
        item for item in receipt.observations
        if item.get("kind") == "credential_session_state"
    ]
    assert len(checkpoints) == 1
    assert checkpoints[0]["session_ref"]
    assert "worker-private-cookie" not in json.dumps(receipt.public_dict())


def test_database_neutral_dispatcher_replays_sealed_requests_before_mutation(monkeypatch):
    scan_id = str(uuid.uuid4())
    request_id = "private-request-1"
    route_id = "a" * 64
    replay_plan = build_replay_plan(
        [{
            "id": request_id,
            "method": "POST",
            "url": "https://app.example.test/api/items?token=canary-query",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": "Bearer canary-header",
            },
            "body": '{"name":"canary-body"}',
            "body_mode": "raw",
            "auth_type": "bearer",
            "has_sensitive_material": True,
        }],
        allowed_origins=TARGET.allowed_origins,
        default_origin=TARGET.allowed_origins[0],
        authorization=ReplayAuthorization(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
    )
    request_manifest = build_request_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        source_action_ids=("inputs.collection_00",),
        requests=({
            "request_ref_id": request_id,
            "route_id": route_id,
            "method": "POST",
            "auth_lane": "primary",
            "selected_shard": None,
            "safe_method": False,
            "body_schema_digest": "b" * 64,
            "content_type": "application/json",
            "body_field_names": ["name"],
            "selection_digest": "c" * 64,
        },),
    )
    candidates = build_request_candidate_manifest(
        (request_manifest,),
        source_action_ids=("inputs.collection_00",),
        maximum=1,
    )
    collection = _action(
        "inputs.collection_00",
        "collections.replay_active",
        0,
        capability_args={
            "request_manifest_ref": request_manifest.reference().canonical_dict(),
        },
    )
    mutation = _action(
        "verify.xss.request.00000",
        "xss.request_verify",
        1,
        dependencies=(collection.action_id,),
        capability_args={
            "request_candidate_manifest_ref": candidates.reference().canonical_dict(),
            "request_candidate_index": 0,
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(collection, mutation),
    )
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    private_inputs = BrokerPrivateScanInputs.from_payload(
        {
            "schema_version": BROKER_PRIVATE_SCAN_INPUT_SCHEMA,
            "lease_id": "lease-1",
            "worker_id": "broker:worker-1",
            "plan_digest": plan.plan_digest,
            "target_binding_digest": TARGET.digest,
            "expires_at": expires_at.isoformat(),
            "options": {},
            "replay_plans": {
                collection.action_id: private_replay_plan_payload(replay_plan),
            },
        },
        lease_id="lease-1",
        worker_id="broker:worker-1",
        plan_digest=plan.plan_digest,
        target_binding_digest=TARGET.digest,
    )
    sent = []

    class Transport:
        async def send(self, request, **_kwargs):
            sent.append(request)
            return ReplayTransportResult(
                status_code=200,
                connected_address="192.0.2.10",
                final_url=request.url,
                response_headers={"Content-Type": "application/json"},
                response_body=b'{"ok":true}',
                elapsed_ms=1,
            )

    transport = Transport()
    monkeypatch.setattr(
        action_adapter_module,
        "PinnedAiohttpReplayTransport",
        lambda: transport,
    )
    backend = Backend(manifests={candidates.manifest_id: candidates})
    dispatcher = _dispatcher(
        plan,
        backend,
        private_inputs=private_inputs,
        policy=ScanPolicy(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
    )

    replay_receipt = asyncio.run(dispatcher(
        collection, _lease(plan, collection), _noop,
    ))
    mutation_receipt = asyncio.run(dispatcher(
        mutation, _lease(plan, mutation), _noop,
    ))

    assert replay_receipt.status == "success"
    assert mutation_receipt.status == "success"
    assert len(sent) == 3
    assert sent[0].body == b'{"name":"canary-body"}'
    assert sent[1].body == sent[0].body
    assert sent[2].body != sent[0].body
    durable = json.dumps({
        "replay": replay_receipt.public_dict(),
        "mutation": mutation_receipt.public_dict(),
    })
    assert "canary-body" not in durable
    assert "canary-header" not in durable
    assert "canary-query" not in durable

    fresh = _dispatcher(
        plan,
        backend,
        private_inputs=private_inputs,
        policy=ScanPolicy(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
    )
    sent.clear()
    assert asyncio.run(fresh.restore_terminal_state(collection, None)) is True
    resumed_mutation = asyncio.run(fresh(
        mutation, _lease(plan, mutation), _noop,
    ))
    assert resumed_mutation.status == "success"
    assert len(sent) == 2


def test_database_neutral_dispatcher_lazily_loads_local_private_replay(monkeypatch):
    scan_id = str(uuid.uuid4())
    replay_plan = build_replay_plan(
        [{
            "id": "local-private-request",
            "method": "GET",
            "url": "https://app.example.test/api/items",
            "headers": {},
            "body": None,
            "body_mode": "none",
            "auth_type": "none",
            "has_sensitive_material": False,
        }],
        allowed_origins=TARGET.allowed_origins,
        default_origin=TARGET.allowed_origins[0],
        authorization=ReplayAuthorization(),
    )
    collection = _action(
        "inputs.collection_00", "collections.replay_safe", 0,
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(collection,),
    )
    loaded = []

    async def loader(action, options):
        loaded.append((action.action_id, dict(options)))
        return replay_plan

    class Transport:
        async def send(self, request, **_kwargs):
            return ReplayTransportResult(
                status_code=200,
                connected_address="192.0.2.10",
                final_url=request.url,
                response_headers={"Content-Type": "application/json"},
                response_body=b'{"ok":true}',
                elapsed_ms=1,
            )

    monkeypatch.setattr(
        action_adapter_module,
        "PinnedAiohttpReplayTransport",
        Transport,
    )
    dispatcher = _dispatcher(
        plan,
        Backend(),
        private_replay_plan_loader=loader,
    )

    receipt = asyncio.run(dispatcher(
        collection, _lease(plan, collection), _noop,
    ))

    assert receipt.status == "success"
    assert receipt.budget_consumed["http_requests"] == 1
    assert loaded == [(collection.action_id, {})]


def test_database_neutral_resume_restores_sealed_auth_without_login_traffic():
    pytest.importorskip("cryptography")
    scan_id = str(uuid.uuid4())
    action = _action("inputs.auth_primary", "auth.session.establish", 0)
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    key = generate_scan_private_state_key()
    profile_id = str(uuid.uuid4())
    options = {
        SCAN_PRIVATE_STATE_KEY_OPTION: key,
        "login_username": "operator",
        "login_password": "worker-private-password",
        "login_url": "/login",
        "resolved_credential_profiles": [{
            "profile_id": profile_id,
            "profile_version": 1,
            "auth_kind": "form_login",
            "principal_slot": "primary",
            "scan_lane": "primary",
            "allowed_capabilities": [
                "auth.session.establish", "http.request",
            ],
        }],
    }
    credential = resolve_scan_interactive_credential(
        options, lane="primary", capability_name="auth.session.establish",
    )
    assert credential is not None
    checkpoint = seal_scan_auth_session_state(
        key,
        scan_id=scan_id,
        action_id=action.action_id,
        action_digest=action.action_digest,
        target_binding_digest=TARGET.digest,
        lane="primary",
        credential_binding_digest=credential.binding_digest,
        headers={"Cookie": "session=worker-private-session"},
        profile_id=profile_id,
        profile_version=1,
        principal="primary",
    )
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    private_inputs = BrokerPrivateScanInputs.from_payload(
        {
            "schema_version": BROKER_PRIVATE_SCAN_INPUT_SCHEMA,
            "lease_id": "lease-1",
            "worker_id": "broker:worker-1",
            "plan_digest": plan.plan_digest,
            "target_binding_digest": TARGET.digest,
            "expires_at": expires_at.isoformat(),
            "options": options,
            "replay_plans": {},
        },
        lease_id="lease-1",
        worker_id="broker:worker-1",
        plan_digest=plan.plan_digest,
        target_binding_digest=TARGET.digest,
    )
    dispatcher = _dispatcher(
        plan,
        Backend(observations={action.action_id: (checkpoint,)}),
        private_inputs=private_inputs,
    )

    assert asyncio.run(
        dispatcher.restore_terminal_state(action, None)
    ) is True
    principal = resolve_scan_http_principal(
        dispatcher.options, lane="primary", capability_name="http.request",
    )
    assert principal.authenticated is True
    assert principal.headers() == {"Cookie": "session=worker-private-session"}
    assert "worker-private-session" not in json.dumps(checkpoint)

    tampered = dict(checkpoint)
    tampered["action_digest"] = "f" * 64
    tampered_dispatcher = _dispatcher(
        plan,
        Backend(observations={action.action_id: (tampered,)}),
        private_inputs=private_inputs,
    )
    assert asyncio.run(
        tampered_dispatcher.restore_terminal_state(action, None)
    ) is False


async def _noop():
    return None


def test_database_neutral_batch_checkpoints_and_resumes_each_candidate(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoint_manifest = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https",
                    "host": "app.example.test", "port": 443,
                    "normalized_path": "/one", "concrete_path": "/one",
                    "query_keys": ["first"], "source": "web.crawl",
                },
                {
                    "method": "GET", "scheme": "https",
                    "host": "app.example.test", "port": 443,
                    "normalized_path": "/two", "concrete_path": "/two",
                    "query_keys": ["second"], "source": "web.crawl",
                },
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoint_manifest,
        source_action_ids=("discover.web_crawl",),
        maximum=10,
    )
    action = _action(
        "verify.xss.batch.00000", "xss.verify_batch", 0,
        capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoint_manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 2},
            "profile": "balanced",
            "proof_policy": "deterministic",
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    calls = []

    async def execute(_self, context, adapter, **_kwargs):
        calls.append(adapter._process_payload["execution_target"])
        return CapabilityAdapterResult(
            status="success",
            actual_budget={name: 1 for name in context.requested_budget},
            observations=({"kind": "xss_probe", "response_sha256": "e" * 64},),
            execution_started=True,
            parser_version="dalfox-jsonl/v1",
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    backend = Backend(manifests={
        endpoint_manifest.manifest_id: endpoint_manifest,
        candidates.manifest_id: candidates,
    })
    dispatcher = _dispatcher(
        plan, backend,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )

    first = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    second = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert first.status == "success"
    assert second.status == "success"
    assert len(calls) == 2
    assert len(backend.attempts[action.action_id]) == 2
    assert {item["candidate_id"] for item in backend.attempts[action.action_id].values()} == {
        item["candidate_id"] for item in candidates.entries
    }
    assert second.redacted_execution["resumed_count"] == 2
    assert all(len(attempt_id) == 64 for attempt_id in backend.attempts[action.action_id])


def test_browser_proof_attempts_fragment_candidate_without_server_signal(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoint_manifest = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https",
                "host": "app.example.test", "port": 443,
                "normalized_path": "/", "concrete_path": "/",
                "query_keys": [], "browser_fragment_path": "/search",
                "browser_fragment_query_keys": ["q"],
                "source": "web.browser_crawl",
            }],
        },
        source_action_ids=("discover.browser_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoint_manifest,
        source_action_ids=("discover.browser_crawl",),
        maximum=10,
    )
    action = _action(
        "prove.xss", "xss.browser_prove_batch", 0,
        capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoint_manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 1},
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    attempted = []

    async def execute(_self, context, adapter, **_kwargs):
        attempted.append(adapter.prepared)
        return CapabilityAdapterResult(
            status="success",
            actual_budget={
                "browser_actions": 2, "http_requests": 1, "tool_wall_seconds": 1,
            },
            observations=({
                "kind": "xss_browser_proof", "proof_state": "not_proven",
            },),
            execution_started=True,
            parser_version="xss-browser-proof/v1",
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    backend = Backend(manifests={
        endpoint_manifest.manifest_id: endpoint_manifest,
        candidates.manifest_id: candidates,
    })
    receipt = asyncio.run(_dispatcher(
        plan, backend,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    assert len(attempted) == 1
    assert attempted[0].injection_location == "fragment"
    assert "#/search?q=" in attempted[0].url


def test_exposure_probe_batch_probes_seeds_follows_listings_and_checkpoints(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoint_manifest = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https",
                "host": "app.example.test", "port": 443,
                "normalized_path": "/app", "concrete_path": "/app",
                "query_keys": [], "source": "web.crawl",
            }],
        },
        source_action_ids=("discover.web_crawl",),
    )
    canned = {
        "/id_rsa": (200, {"Content-Type": "text/plain"},
                    b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn..."),
        "/metrics": (200, {"Content-Type": "text/plain"},
                     b"# HELP up 1\n# TYPE up gauge\nup 1\n"),
        "/ftp": (200, {"Content-Type": "text/html"},
                 b"<title>Index of /ftp</title><a href=\"secret.md\">secret.md</a>"),
        "/ftp/secret.md": (200, {"Content-Type": "text/markdown"},
                           b"# Internal\nConfidential."),
    }

    class FakeTransport:
        def __init__(self):
            self.sent = []

        async def send(self, request, *, target, timeout_seconds, follow_redirects):
            assert follow_redirects is False
            self.sent.append(request.url)
            path = "/" + request.url.split("/", 3)[3] if request.url.count("/") >= 3 else "/"
            for suffix, (status, headers, body) in canned.items():
                if request.url.endswith(suffix):
                    return ReplayTransportResult(
                        status_code=status, connected_address="192.0.2.10",
                        final_url=request.url, response_headers=headers,
                        response_body=body, elapsed_ms=5,
                    )
            return ReplayTransportResult(
                status_code=404, connected_address="192.0.2.10",
                final_url=request.url,
                response_headers={"Content-Type": "text/plain"},
                response_body=b"not found", elapsed_ms=5,
            )

    transport = FakeTransport()
    monkeypatch.setattr(
        action_adapter_module, "PinnedAiohttpReplayTransport", lambda: transport,
    )
    action = _action(
        "verify.exposure", "exposure.verify_batch", 0,
        capability_args={
            "endpoint_manifest_ref": endpoint_manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 100},
            "profile": "balanced",
            "proof_policy": "deterministic_proof_contract_required",
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    backend = Backend(manifests={endpoint_manifest.manifest_id: endpoint_manifest})
    dispatcher = _dispatcher(
        plan, backend,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )

    first = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    proofs = [
        item for item in first.observations
        if item.get("kind") == "sensitive_exposure_proof"
    ]
    classes = {item["exposure_class"] for item in proofs}
    assert "private_key_material" in classes
    assert "metrics_endpoint" in classes
    assert "directory_listing" in classes
    # The listing was followed to its confidential file.
    assert "confidential_file" in classes
    assert any(
        item["request_url"].endswith("/ftp/secret.md") for item in proofs
    )
    # No secret bytes escape into the observation: evidence is content-addressed
    # and the excerpt is redacted (the visibility flag is itself masked by the
    # receipt redaction layer, so accept either the bool or its redacted marker).
    assert all(item["secret_values_visible"] in (False, "***") for item in proofs)
    assert all("PRIVATE KEY" not in (item.get("redacted_excerpt") or "") for item in proofs)
    assert all(len(item["response_body_sha256"]) == 64 for item in proofs)

    # Every probe is checkpointed; a resumed run repeats no request.
    assert backend.attempts[action.action_id]
    sent_first = len(transport.sent)
    second = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    assert len(transport.sent) == sent_first  # fully resumed from durable attempts
    assert second.redacted_execution["resumed_count"] >= 1


def test_authz_surface_batch_proves_bfla_only_with_an_established_boundary(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoint_manifest = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https", "host": "app.example.test",
                    "port": 443, "normalized_path": "/admin", "concrete_path": "/admin",
                    "query_keys": [], "source": "web.crawl",
                },
                {
                    "method": "GET", "scheme": "https", "host": "app.example.test",
                    "port": 443, "normalized_path": "/api/Users",
                    "concrete_path": "/api/Users", "query_keys": [], "source": "web.crawl",
                },
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    users_body = b'[{"id":1,"email":"a@b.test"},{"id":2,"email":"c@d.test"}]'

    class PrincipalTransport:
        async def send(self, request, **_kwargs):
            authed = any(name.lower() == "authorization" for name, _ in request.headers)
            path = urllib.parse.urlsplit(request.url).path
            if path == "/admin" and not authed:
                return ReplayTransportResult(
                    status_code=401, connected_address="192.0.2.10",
                    final_url=request.url, response_headers={"Content-Type": "application/json"},
                    response_body=b'{"error":"unauthorized"}', elapsed_ms=5,
                )
            if path == "/admin":
                return ReplayTransportResult(
                    status_code=200, connected_address="192.0.2.10",
                    final_url=request.url, response_headers={"Content-Type": "application/json"},
                    response_body=b'{"panel":true}', elapsed_ms=5,
                )
            # /api/Users serves the identical authenticated user list to anyone.
            return ReplayTransportResult(
                status_code=200, connected_address="192.0.2.10",
                final_url=request.url, response_headers={"Content-Type": "application/json"},
                response_body=users_body, elapsed_ms=5,
            )

    monkeypatch.setattr(
        action_adapter_module, "PinnedAiohttpReplayTransport", PrincipalTransport,
    )
    monkeypatch.setattr(
        action_adapter_module, "resolve_scan_http_principal",
        lambda _options, *, lane, capability_name=None: _principal(lane),
    )
    action = _action(
        "verify.authz_surface", "authz_surface.verify_batch", 0,
        capability_args={
            "endpoint_manifest_ref": endpoint_manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 100},
            "profile": "balanced",
            "proof_policy": "deterministic_proof_contract_required",
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    backend = Backend(manifests={endpoint_manifest.manifest_id: endpoint_manifest})
    dispatcher = _dispatcher(
        plan, backend,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )

    first = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    proofs = [
        item for item in first.observations
        if item.get("kind") == "authz_surface_proof"
    ]
    assert len(proofs) == 1
    assert proofs[0]["route_id"].endswith("/api/users") or "users" in proofs[0]["request_url"].lower()
    assert first.redacted_execution["boundary_established"] is True

    # Resume replays no request and reproduces the same single finding.
    second = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    assert second.redacted_execution["resumed_count"] == 2
    assert len([
        item for item in second.observations
        if item.get("kind") == "authz_surface_proof"
    ]) == 1


def test_authz_surface_batch_makes_no_claim_on_a_fully_public_app(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoint_manifest = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test",
                "port": 443, "normalized_path": "/api/Users",
                "concrete_path": "/api/Users", "query_keys": [], "source": "web.crawl",
            }],
        },
        source_action_ids=("discover.web_crawl",),
    )

    class PublicTransport:
        async def send(self, request, **_kwargs):
            # Everything is 200 identical to everyone: no auth boundary exists.
            return ReplayTransportResult(
                status_code=200, connected_address="192.0.2.10",
                final_url=request.url, response_headers={"Content-Type": "application/json"},
                response_body=b'[{"id":1},{"id":2}]', elapsed_ms=5,
            )

    monkeypatch.setattr(
        action_adapter_module, "PinnedAiohttpReplayTransport", PublicTransport,
    )
    monkeypatch.setattr(
        action_adapter_module, "resolve_scan_http_principal",
        lambda _options, *, lane, capability_name=None: _principal(lane),
    )
    action = _action(
        "verify.authz_surface", "authz_surface.verify_batch", 0,
        capability_args={
            "endpoint_manifest_ref": endpoint_manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 100},
            "profile": "balanced",
            "proof_policy": "deterministic_proof_contract_required",
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    backend = Backend(manifests={endpoint_manifest.manifest_id: endpoint_manifest})
    dispatcher = _dispatcher(
        plan, backend,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )

    result = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    assert result.redacted_execution["boundary_established"] is False
    assert not [
        item for item in result.observations
        if item.get("kind") == "authz_surface_proof"
    ]


def test_safe_authentication_body_batch_still_charges_state_budget(monkeypatch):
    scan_id = str(uuid.uuid4())
    route_id = "d" * 64
    request = build_replay_plan(
        ({
            "id": "credential-login:primary",
            "method": "POST",
            "url": "https://app.example.test/rest/user/login",
            "headers": {"Content-Type": "application/json"},
            "body": '{"email":"disposable@example.test","password":"private"}',
            "body_mode": "application/json",
            "auth_type": "none",
            "has_sensitive_material": True,
        },),
        allowed_origins=TARGET.allowed_origins,
        authorization=ReplayAuthorization(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="credential-workflow",
        ),
    ).requests[0]
    request_manifest = build_request_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        source_action_ids=("inputs.auth_primary",),
        requests=({
            "request_ref_id": request.request_id,
            "route_id": route_id,
            "method": "POST",
            "auth_lane": "primary",
            "selected_shard": None,
            "request_class": "safe_authentication",
            "content_type": "application/json",
            "body_field_names": ["email", "password"],
            "selection_digest": "e" * 64,
            "body_schema_digest": "f" * 64,
        },),
    )
    candidates = build_request_candidate_manifest(
        (request_manifest,),
        source_action_ids=("inputs.auth_primary",),
        maximum=10,
    )
    action = _action(
        "verify.request_sqli", "sqli.request_verify_batch", 0,
        capability_args={
            "request_candidate_manifest_ref": candidates.reference().canonical_dict(),
            "slice": {"start": 0, "count": 2},
            "profile": "balanced_batch_v1",
            "proof_policy": "deterministic_differential_required",
        },
    )
    action = ScanAction(
        **{
            **action.digest_material(),
            "requested_budget": {
                "http_requests": 4,
                "state_changing_requests": 4,
                "tool_wall_seconds": 20,
            },
        }
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )

    class Transport:
        async def send(self, exact_request, **_kwargs):
            return ReplayTransportResult(
                status_code=200,
                connected_address="192.0.2.10",
                final_url=exact_request.url,
                response_body=b"normal",
            )

    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", Transport)
    backend = Backend(manifests={candidates.manifest_id: candidates})
    dispatcher = _dispatcher(
        plan, backend,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )
    dispatcher._private_requests[request.request_id] = request

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    assert receipt.budget_consumed == {
        "http_requests": 4,
        "state_changing_requests": 4,
        "tool_wall_seconds": 2,
    }
    assert all(
        item.get("request_class") == "safe_authentication"
        for item in receipt.observations if item.get("kind") == "candidate_attempt"
    )
    public = json.dumps(receipt.public_dict())
    assert "disposable@example.test" not in public
    assert '"password":"private"' not in public


def test_database_neutral_finalizer_reads_only_durable_results_and_observations():
    baseline = _action("baseline.http", "http.request", 0)
    final = _action("finalize.report", "scan.finalize", 1, dependencies=(baseline.action_id,))
    plan = ScanActionPlan(
        scan_id=str(uuid.uuid4()),
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(baseline, final),
    )
    manifest = ObservationManifestReference(
        manifest_id=str(uuid.uuid4()),
        sha256="b" * 64,
        count=1,
        size_bytes=10,
        object_key="scan/test/baseline.json",
        manifest_digest="c" * 64,
    )
    result = CapabilityResultReference(
        action_id=baseline.action_id,
        action_digest=baseline.action_digest,
        capability_name=baseline.capability_name,
        adapter_name=str(baseline.placement["adapter_name"]),
        adapter_version=str(baseline.placement["adapter_version"]),
        output_schema=baseline.output_schema,
        status=CapabilityResultStatus.SUCCESS,
        partial=False,
        timed_out=False,
        reason_code=None,
        receipt_ref=CapabilityReceiptReference(
            receipt_id=str(uuid.uuid4()), receipt_hash="d" * 64,
        ),
        observation_manifest_ref=manifest,
        budget_reserved=baseline.requested_budget,
        budget_consumed={name: 0 for name in baseline.requested_budget},
    )
    backend = Backend(
        results={baseline.action_id: result},
        observations={baseline.action_id: ({"kind": "http_observation"},)},
    )
    dispatcher = _dispatcher(plan, backend)

    receipt = asyncio.run(dispatcher(final, _lease(plan, final), _noop))

    assert receipt.status == "success"
    assert receipt.observations[0]["kind"] == "scan_report"
    assert receipt.redacted_execution["target_traffic"] is False


def test_database_neutral_http_receipt_drops_body_and_redacts_urls(monkeypatch):
    action = _action("baseline.http", "http.request", 0)
    plan = ScanActionPlan(
        scan_id=str(uuid.uuid4()),
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )

    async def execute_bound(*_args, **_kwargs):
        return {
            "ok": True,
            "request": {"method": "GET", "path": "/reset/token/abc123?key=secret"},
            "response": {
                "status": 200,
                "body_sample": "Bearer should-never-enter-durable-evidence",
                "selected_json": {"access_token": "also-secret"},
                "selected_headers": {
                    "authorization": "Bearer should-never-enter-durable-evidence",
                },
                "final_url": "https://app.example.test/reset?token=also-secret",
            },
            "redirect_chain": [],
            "hops_followed": 0,
        }

    monkeypatch.setattr(
        action_adapter_module, "execute_bound_http_request", execute_bound,
    )
    dispatcher = _dispatcher(plan, Backend())
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    serialized = json.dumps(receipt.public_dict(), sort_keys=True)

    assert receipt.status == "success"
    assert "should-never-enter-durable-evidence" not in serialized
    assert "also-secret" not in serialized
    assert receipt.observations[0]["response"]["body_sample"] == ""
    assert receipt.observations[0]["response"]["selected_json"] == {}
    assert "<redacted>" in serialized


def test_database_neutral_network_action_limits_commands_to_reserved_hosts(monkeypatch):
    target = TargetBinding(
        target_id=TARGET.target_id,
        target_kind=TARGET.target_kind,
        canonical_host=TARGET.canonical_host,
        allowed_origins=TARGET.allowed_origins,
        allowed_addresses=("192.0.2.10", "192.0.2.11", "192.0.2.12"),
        allowed_root_domains=TARGET.allowed_root_domains,
    )
    spec = CAPABILITY_REGISTRY.require("ports.discover")
    action = ScanAction(
        action_id="discover.ports",
        stage="discover_network",
        ordinal=0,
        capability_name=spec.name,
        capability_args={},
        target_binding_digest=target.digest,
        input_binding_digest="e" * 64,
        requested_budget={
            "hosts_attempted": 1,
            "tcp_ports_attempted": 4,
            "tool_wall_seconds": 5,
        },
        placement={
            "schema_version": "scan-action-placement/v1",
            "eligible_backends": ["local", "broker"],
            "requirements": dict(spec.placement_requirements),
            "adapter_name": spec.adapter,
            "adapter_version": spec.adapter_version,
        },
        dependencies=(),
        required=True,
        supporting=True,
        output_schema=spec.output_schema,
    )
    plan = ScanActionPlan(
        scan_id=str(uuid.uuid4()),
        execution_plan_digest="a" * 64,
        target_binding_digest=target.digest,
        actions=(action,),
    )
    captured = {}

    class Factory:
        capability_name = spec.name
        adapter_name = spec.adapter
        adapter_version = spec.adapter_version
        parser_version = spec.output_schema

        def prepare(self, *, target, args, policy):
            del policy
            captured["addresses"] = target.allowed_addresses
            captured["ports"] = tuple(args["ports"])
            return PreparedExecution(
                capability_name=spec.name,
                adapter_name=spec.adapter,
                adapter_version=spec.adapter_version,
                commands=(),
                estimated_budget={
                    "hosts_attempted": len(target.allowed_addresses),
                    "tcp_ports_attempted": len(args["ports"]),
                    "tool_wall_seconds": 5,
                },
                input_digest="f" * 64,
                redacted_execution={},
                parser_version=spec.output_schema,
            )

    class ExecutionAdapter:
        manages_cancellation = False

        def __init__(self, *, prepared, parser, **_kwargs):
            del parser
            self.capability_name = prepared.capability_name
            self.adapter_name = prepared.adapter_name
            self.adapter_version = prepared.adapter_version

        async def execute(self, **_kwargs):
            return CapabilityAdapterResult(
                status="success",
                actual_budget={
                    "hosts_attempted": 1,
                    "tcp_ports_attempted": 4,
                    "tool_wall_seconds": 1,
                },
                execution_started=True,
                parser_version=spec.output_schema,
            )

    monkeypatch.setattr(action_adapter_module, "network_capability_adapter", lambda _name: Factory())
    monkeypatch.setattr(action_adapter_module, "NetworkExecutionAdapter", ExecutionAdapter)
    dispatcher = _dispatcher(plan, Backend(), target=target)
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    assert captured["addresses"] == ("192.0.2.10",)
    assert len(captured["ports"]) == 4


def test_database_neutral_tls_action_inspects_the_complete_frozen_matrix(monkeypatch):
    target = TargetBinding(
        target_id=TARGET.target_id,
        target_kind=TARGET.target_kind,
        canonical_host=TARGET.canonical_host,
        allowed_origins=(
            "https://app.example.test",
            "https://app.example.test:8443",
        ),
        allowed_addresses=("192.0.2.10", "192.0.2.11"),
        allowed_root_domains=TARGET.allowed_root_domains,
    )
    spec = CAPABILITY_REGISTRY.require("tls.inspect")
    args = {
        "origins_ref": "frozen_https_origins",
        "origin_count": 2,
        "addresses_ref": "frozen_addresses",
        "address_count": 2,
    }
    action = ScanAction(
        action_id="baseline.tls",
        stage="deterministic_baseline",
        ordinal=0,
        capability_name=spec.name,
        capability_args=args,
        target_binding_digest=target.digest,
        input_binding_digest="e" * 64,
        requested_budget={
            "tcp_ports_attempted": 16,
            "tool_wall_seconds": 60,
        },
        placement={
            "schema_version": "scan-action-placement/v1",
            "eligible_backends": ["local", "broker"],
            "requirements": dict(spec.placement_requirements),
            "adapter_name": spec.adapter,
            "adapter_version": spec.adapter_version,
        },
        dependencies=(),
        required=True,
        supporting=False,
        output_schema=spec.output_schema,
    )
    plan = ScanActionPlan(
        scan_id=str(uuid.uuid4()),
        execution_plan_digest="a" * 64,
        target_binding_digest=target.digest,
        actions=(action,),
    )
    captured = {}

    async def inspect(*, target, timeout_seconds_per_target):
        captured["target"] = target
        captured["timeout"] = timeout_seconds_per_target
        return {
            "ok": True,
            "status": "success",
            "observations": [{
                "kind": "tls_protocol",
                "origin": origin,
                "pinned_address": address,
            } for origin in target.allowed_origins
              for address in target.allowed_addresses],
            "budget_consumed": {
                "tcp_ports_attempted": 12,
                "tool_wall_seconds": 4,
            },
        }

    monkeypatch.setattr(action_adapter_module, "inspect_tls_binding", inspect)
    dispatcher = _dispatcher(plan, Backend(), target=target)

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    assert captured == {"target": target, "timeout": 15}
    assert len(receipt.observations) == 4
    assert receipt.budget_consumed == {
        "tcp_ports_attempted": 12,
        "tool_wall_seconds": 4,
    }


def test_database_neutral_active_action_executes_exact_manifest_candidate(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoint_manifest = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https",
                    "host": "app.example.test", "port": 443,
                    "normalized_path": "/one", "concrete_path": "/one",
                    "query_keys": ["first"], "source": "web.crawl",
                },
                {
                    "method": "GET", "scheme": "https",
                    "host": "app.example.test", "port": 443,
                    "normalized_path": "/two", "concrete_path": "/two",
                    "query_keys": ["second"], "source": "web.crawl",
                },
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidate_manifest = build_candidate_manifest(
        endpoint_manifest,
        source_action_ids=("discover.web_crawl",),
        maximum=10,
    )
    action = _action(
        "verify.xss.00001",
        "xss.verify",
        0,
        capability_args={
            "candidate_manifest_ref": candidate_manifest.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoint_manifest.reference().canonical_dict(),
            "candidate_index": 1,
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    captured = {}

    class ExternalAdapter:
        manages_cancellation = True

        def __init__(
            self, *, specification, process_payload, requested_budget, **_kwargs,
        ):
            self.capability_name = specification.name
            self.adapter_name = specification.adapter
            self.adapter_version = specification.adapter_version
            self.requested_budget = dict(requested_budget)
            captured.update(process_payload)

        async def execute(self, **_kwargs):
            return CapabilityAdapterResult(
                status="success",
                actual_budget={
                    name: min(amount, 1)
                    for name, amount in self.requested_budget.items()
                },
                execution_started=True,
                parser_version="dalfox-jsonl/v1",
            )

    monkeypatch.setattr(
        action_adapter_module, "ScannerExecutionAdapter", ExternalAdapter,
    )
    backend = Backend(manifests={
        endpoint_manifest.manifest_id: endpoint_manifest,
        candidate_manifest.manifest_id: candidate_manifest,
    })
    dispatcher = _dispatcher(
        plan,
        backend,
        policy=ScanPolicy(
            active_testing=True,
            approval_receipt_id="approval-1",
        ),
    )

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    assert captured["execution_target"] == "https://app.example.test/two?second=1"
    assert captured["registered_target"] == "https://app.example.test"


def test_database_neutral_required_verifier_skips_an_empty_bound_manifest():
    scan_id = str(uuid.uuid4())
    endpoint_manifest = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https",
                "host": "app.example.test", "port": 443,
                "normalized_path": "/", "concrete_path": "/",
                "query_keys": [], "source": "seed",
            }],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoint_manifest,
        source_action_ids=("discover.web_crawl",),
        maximum=10,
    )
    action = _action(
        "verify.xss", "xss.verify", 0,
        capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoint_manifest.reference().canonical_dict(),
            "candidate_index": 0,
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    dispatcher = _dispatcher(
        plan,
        Backend(manifests={
            endpoint_manifest.manifest_id: endpoint_manifest,
            candidates.manifest_id: candidates,
        }),
        policy=ScanPolicy(active_testing=True),
    )

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "skipped"
    assert receipt.errors == ("not_applicable",)


def test_database_neutral_authz_uses_only_bound_endpoint_manifest(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https",
                    "host": "app.example.test", "port": 443,
                    "normalized_path": "/api/items/{int}",
                    "concrete_path": "/api/items/{int}",
                    "query_keys": ["expand"], "source": "web.crawl",
                },
                {
                    "method": "POST", "scheme": "https",
                    "host": "app.example.test", "port": 443,
                    "normalized_path": "/api/items",
                    "concrete_path": "/api/items",
                    "query_keys": [], "source": "collections.replay",
                },
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    action = _action(
        "verify.authz", "authz.verify", 0,
        capability_args={
            "principal_lanes": ["primary", "secondary"],
            "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    captured = {}

    monkeypatch.setattr(
        action_adapter_module,
        "resolve_scan_http_principal",
        lambda _options, *, lane, capability_name=None: _principal(lane),
    )

    async def verify(_target_url, routes, **_kwargs):
        captured["routes"] = list(routes)
        return {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "authz_differential",
                "proof_state": "inconclusive",
                "principal_contexts_distinct": True,
            },
            "budget_consumed": {"http_requests": 0, "tool_wall_seconds": 0},
        }

    monkeypatch.setattr(
        action_adapter_module,
        "verify_target_bound_object_authorization",
        verify,
    )
    dispatcher = _dispatcher(
        plan,
        Backend(manifests={endpoints.manifest_id: endpoints}),
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    assert captured["routes"] == [
        "https://app.example.test/api/items/1?expand=1"
    ]


def test_database_neutral_nuclei_uses_only_digest_checked_template_pack(monkeypatch):
    scan_id = str(uuid.uuid4())
    template_manifest = build_canonical_nuclei_template_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
    )
    action = _action(
        "active.templates",
        "templates.scan",
        0,
        capability_args={
            "template_manifest_ref": (
                template_manifest.reference().canonical_dict()
            ),
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    captured = {}

    class ExternalAdapter:
        manages_cancellation = True

        def __init__(
            self, *, specification, process_payload, requested_budget, **kwargs,
        ):
            del kwargs
            self.capability_name = specification.name
            self.adapter_name = specification.adapter
            self.adapter_version = specification.adapter_version
            self.requested_budget = dict(requested_budget)
            captured.update(process_payload)

        async def execute(self, **_kwargs):
            return CapabilityAdapterResult(
                status="success",
                actual_budget={
                    name: min(amount, 1)
                    for name, amount in self.requested_budget.items()
                },
                execution_started=True,
                parser_version="nuclei-jsonl/v1",
            )

    monkeypatch.setattr(
        action_adapter_module, "ScannerExecutionAdapter", ExternalAdapter,
    )
    dispatcher = _dispatcher(
        plan,
        Backend(manifests={
            template_manifest.manifest_id: template_manifest,
        }),
        policy=ScanPolicy(
            active_testing=True,
            approval_receipt_id="approval-1",
        ),
    )

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    assert captured["scanner_options"]["severity"] == "high,critical"
    assert captured["scanner_options"]["tags"] == (
        "exposure,misconfig,auth-bypass,default-login"
    )
    assert captured["scanner_options"]["template_pack_digest"] == (
        template_manifest.entries[0]["template_digest"]
    )


def test_database_neutral_passive_nuclei_uses_exact_reviewed_allowlist(monkeypatch):
    scan_id = str(uuid.uuid4())
    template_manifest = build_canonical_passive_nuclei_template_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
    )
    action = _action(
        "passive.templates",
        "templates.passive_scan",
        0,
        capability_args={
            "template_manifest_ref": (
                template_manifest.reference().canonical_dict()
            ),
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    captured = {}

    class ExternalAdapter:
        manages_cancellation = True

        def __init__(
            self, *, specification, process_payload, requested_budget, **kwargs,
        ):
            del kwargs
            self.capability_name = specification.name
            self.adapter_name = specification.adapter
            self.adapter_version = specification.adapter_version
            self.requested_budget = dict(requested_budget)
            captured.update(process_payload)

        async def execute(self, **_kwargs):
            return CapabilityAdapterResult(
                status="success",
                actual_budget={"http_requests": 7, "tool_wall_seconds": 1},
                execution_started=True,
                parser_version="nuclei-jsonl/v1",
            )

    monkeypatch.setattr(
        action_adapter_module, "ScannerExecutionAdapter", ExternalAdapter,
    )
    dispatcher = _dispatcher(
        plan,
        Backend(manifests={
            template_manifest.manifest_id: template_manifest,
        }),
        policy=ScanPolicy(active_testing=False),
    )

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    options = captured["scanner_options"]
    assert options["template_request_cost_upper_bound"] == 7
    assert set(options["template_ids"].split(",")) == {
        entry["template_id"] for entry in template_manifest.entries
    }
    assert "tags" not in options


def test_directory_listing_entries_resolve_for_both_href_conventions():
    """Listing generators disagree about what their hrefs are relative to.

    Apache and nginx emit a bare filename, which resolves against the
    directory. The Node/Express serve-index middleware emits the path from the
    site root -- ``ftp/acquisitions.md`` for a listing of ``/ftp`` -- which
    resolved to ``/ftp/ftp/acquisitions.md`` and was refused, so the
    confidential files a browsable directory exposes were never reached.
    """
    resolve = action_adapter_module._directory_listing_child_url
    cases = {
        # site-root-relative (serve-index)
        ("http://app.test/ftp", "ftp/acquisitions.md"): "http://app.test/ftp/acquisitions.md",
        ("http://app.test/ftp", "./ftp/quarantine"): "http://app.test/ftp/quarantine",
        # directory-relative (apache, nginx)
        ("http://app.test/ftp", "acquisitions.md"): "http://app.test/ftp/acquisitions.md",
        ("http://app.test/backup/", "dump.sql"): "http://app.test/backup/dump.sql",
        # absolute path, and a genuine subdirectory that must stay nested
        ("http://app.test/ftp", "/ftp/legal.md"): "http://app.test/ftp/legal.md",
        ("http://app.test/ftp", "other/file.txt"): "http://app.test/ftp/other/file.txt",
    }
    for (directory, link), expected in cases.items():
        assert resolve(directory, link) == expected, (directory, link)


def test_spec_ingest_declares_body_endpoints_from_the_fetched_spec(monkeypatch):
    import json as _json
    scan_id = str(uuid.uuid4())
    spec_body = _json.dumps({
        "openapi": "3.0.0",
        "paths": {
            "/rest/products/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
            "/rest/user/login": {"post": {"requestBody": {"content": {"application/json": {
                "schema": {"type": "object", "properties": {"email": {}, "password": {}}}}}}}},
        },
    }).encode()

    class FakeTransport:
        def __init__(self):
            self.sent = []

        async def send(self, request, *, target, timeout_seconds, follow_redirects):
            assert follow_redirects is False
            self.sent.append(request.url)
            # The application publishes its spec at exactly one conventional path.
            if request.url.endswith("/openapi.json"):
                return ReplayTransportResult(
                    status_code=200, connected_address="192.0.2.10",
                    final_url=request.url,
                    response_headers={"Content-Type": "application/json"},
                    response_body=spec_body, elapsed_ms=5,
                )
            return ReplayTransportResult(
                status_code=404, connected_address="192.0.2.10",
                final_url=request.url,
                response_headers={"Content-Type": "text/html"},
                response_body=b"not found", elapsed_ms=5,
            )

    transport = FakeTransport()
    monkeypatch.setattr(
        action_adapter_module, "PinnedAiohttpReplayTransport", lambda: transport,
    )
    action = _action("discover.spec", "web.spec_ingest", 0)
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    dispatcher = _dispatcher(plan, Backend())
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    routes = {
        (item["method"], item["url"]): item
        for item in receipt.observations
        if item.get("kind") == "discovered_route"
    }
    login = next(
        item for (method, url), item in routes.items()
        if method == "POST" and url.endswith("/rest/user/login")
    )
    assert login["body_field_names"] == ["email", "password"]
    assert login["content_type"] == "application/json"
    # Query values never persist in an observation; the parameter key survives for candidates.
    assert any(
        method == "GET" and "/rest/products/search?q=" in url
        for method, url in routes
    )
    # Fetched once per conventional path, bounded, and never off the pinned target.
    assert all(url.startswith("https://app.example.test/") for url in transport.sent)
    assert receipt.status == "success"


def test_spec_ingest_skips_cleanly_when_no_spec_is_published(monkeypatch):
    scan_id = str(uuid.uuid4())

    class NotFoundTransport:
        async def send(self, request, *, target, timeout_seconds, follow_redirects):
            return ReplayTransportResult(
                status_code=404, connected_address="192.0.2.10",
                final_url=request.url, response_headers={}, response_body=b"", elapsed_ms=1,
            )

    monkeypatch.setattr(
        action_adapter_module, "PinnedAiohttpReplayTransport", lambda: NotFoundTransport(),
    )
    action = _action("discover.spec", "web.spec_ingest", 0)
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    receipt = asyncio.run(_dispatcher(plan, Backend())(action, _lease(plan, action), _noop))
    assert receipt.status == "success"
    assert not [o for o in receipt.observations if o.get("kind") == "discovered_route"]


def test_path_candidate_goes_to_sqlmap_with_a_marker_and_is_skipped_by_dalfox(monkeypatch):
    """A path-segment candidate is a SQLi-only site carrying the sqlmap ``*`` marker.

    The SQLi verifier tests the marked URL; the XSS verifier would feed the literal ``*`` to
    dalfox as a value, so it skips path candidates.
    """
    scan_id = str(uuid.uuid4())
    endpoint_manifest = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": "/api/orders/{int}", "concrete_path": "/api/orders/1",
                "query_keys": [], "source": "web.spec_ingest",
            }],
        },
        source_action_ids=("discover.spec",),
    )
    candidates = build_candidate_manifest(
        endpoint_manifest, source_action_ids=("discover.spec",), maximum=10,
    )
    assert any(c.get("parameter_location") == "path" for c in candidates.entries)

    def _batch_action(capability):
        return _action(
            f"verify.{capability.split('.')[0]}.batch.00000", capability, 0,
            capability_args={
                "candidate_manifest_ref": candidates.reference().canonical_dict(),
                "endpoint_manifest_ref": endpoint_manifest.reference().canonical_dict(),
                "slice": {"start": 0, "count": 5},
                "profile": "balanced", "proof_policy": "deterministic",
            },
        )

    def run(capability, parser_version):
        action = _batch_action(capability)
        plan = ScanActionPlan(
            scan_id=scan_id, execution_plan_digest="a" * 64,
            target_binding_digest=TARGET.digest, actions=(action,),
        )
        calls = []

        async def execute(_self, context, adapter, **_kwargs):
            calls.append(adapter._process_payload["execution_target"])
            return CapabilityAdapterResult(
                status="success",
                actual_budget={name: 1 for name in context.requested_budget},
                observations=(), execution_started=True, parser_version=parser_version,
            )

        monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
        backend = Backend(manifests={
            endpoint_manifest.manifest_id: endpoint_manifest,
            candidates.manifest_id: candidates,
        })
        dispatcher = _dispatcher(
            plan, backend,
            policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
        )
        asyncio.run(dispatcher(action, _lease(plan, action), _noop))
        return calls

    sqli_calls = run("sqli.verify_batch", "sqlmap-jsonl/v1")
    assert sqli_calls == ["https://app.example.test/api/orders/1*"], sqli_calls

    xss_calls = run("xss.verify_batch", "dalfox-jsonl/v1")
    assert xss_calls == [], "dalfox never receives a path candidate"

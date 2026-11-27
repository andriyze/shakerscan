"""recon_active actions through the Scan dispatcher: authority, binding, metering, cancellation.

Fixture tests with fake DNS answers and a fake bound HTTP executor (no network).
"""

from __future__ import annotations

import asyncio
import uuid

from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy, TargetBinding
import scan.recon_active_actions as recon_actions
import target_resolution
from scan.action_adapter import DatabaseNeutralScanActionDispatcher
from scan.action_plan import ScanAction, ScanActionPlan
from scan.execution_backend import ActionLease

# The dispatcher harness of test_scan_action_adapter.py, kept local to this module.
TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)
# The operator declared the apex itself: name guessing under it is authorized.
APEX = TargetBinding(
    target_id="target-2",
    target_kind="web",
    canonical_host="example.test",
    allowed_origins=("https://example.test",),
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
    target=TARGET,
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
        target_binding_digest=target.digest,
        input_binding_digest=f"{ordinal + 1:064x}",
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
    private_replay_plan_loader=None, options=None, target_url="https://app.example.test/",
):
    async def process_runner(*_args, **_kwargs):
        raise AssertionError("process runner must not be used")

    return DatabaseNeutralScanActionDispatcher(
        target_url=target_url,
        options=dict(options or {}),
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


async def _noop():
    return None


ACTIVE = ScanPolicy(active_testing=True, subdomain_discovery=True,
                    include_families=("recon_active",), approval_receipt_id="receipt-1")


def _plan(*actions, target=TARGET):
    return ScanActionPlan(scan_id=str(uuid.uuid4()), execution_plan_digest="a" * 64,
                          target_binding_digest=target.digest, actions=tuple(actions))


def _run(action, *, policy=ACTIVE, backend=None, cancelled=None, target=TARGET, extra=()):
    plan = _plan(*extra, action, target=target)
    host = target.canonical_host
    dispatcher = _dispatcher(plan, backend or Backend(), policy=policy, target=target,
                             target_url=f"https://{host}/")
    if cancelled is not None:
        dispatcher.cancelled = cancelled
    return asyncio.run(dispatcher(action, _lease(plan, action), _noop))


def test_without_active_approval_nothing_is_asked(monkeypatch):
    async def answer(_name):
        raise AssertionError("no DNS question without approval")

    monkeypatch.setattr(target_resolution, "system_answer", answer)
    action = _action("discover.dns_names", "dns.enumerate", 0,
                     capability_args={"root_domains": ["example.test"]})
    receipt = _run(action, policy=ScanPolicy(subdomain_discovery=True))
    assert receipt.status == "skipped"


def test_dns_enumeration_needs_subdomain_discovery(monkeypatch):
    action = _action("discover.dns_names", "dns.enumerate", 0, target=APEX)
    policy = ScanPolicy(active_testing=True, include_families=("recon_active",),
                        approval_receipt_id="receipt-1")
    assert _run(action, policy=policy, target=APEX).status == "skipped"


def test_name_guessing_is_refused_without_apex_authority(monkeypatch):
    # app.example.test binds example.test only as its registrable domain (it may be one tenant
    # of a provider's domain): no DNS question and no other Host is ever sent, even when the
    # action is in the plan with arguments naming the root.
    async def answer(_name):
        raise AssertionError("no DNS question without apex authority")

    async def bound(*_args, **_kwargs):
        raise AssertionError("no request without apex authority")

    monkeypatch.setattr(target_resolution, "system_answer", answer)
    monkeypatch.setattr(recon_actions, "execute_bound_http_request", bound)
    for action_id, capability in (("discover.dns_names", "dns.enumerate"),
                                  ("discover.virtual_hosts", "vhost.discover")):
        action = _action(action_id, capability, 0,
                         capability_args={"root_domains": ["example.test"]})
        receipt = _run(action)
        assert receipt.status == "skipped" and receipt.errors == ("not_applicable",)


def test_dns_enumeration_meters_questions_and_reports_names(monkeypatch):
    asked = []

    async def answer(name):
        asked.append(name)
        return (["192.0.2.5"], None) if name in {"vpn.example.test", "mail.example.test"} else ([], None)

    monkeypatch.setattr(target_resolution, "system_answer", answer)
    action = _action("discover.dns_names", "dns.enumerate", 0, target=APEX)
    receipt = _run(action, target=APEX)
    assert receipt.status in {"success", "partial"}
    hosts = {row["host"] for row in receipt.observations if row.get("kind") == "subdomain"}
    assert hosts == {"vpn.example.test", "mail.example.test"}
    assert all(name.endswith(".example.test") for name in asked)
    reserved = action.requested_budget["hosts_attempted"]
    assert len(asked) == reserved == receipt.budget_consumed["hosts_attempted"]
    summary = [row for row in receipt.observations if row.get("kind") == "dns_enumeration"][0]
    assert summary["wordlist"]["provenance"] == "authored_by_shakerscan"


def test_cancelled_dns_enumeration_settles_cancelled_with_what_it_spent(monkeypatch):
    asked = []

    async def answer(name):
        asked.append(name)
        return [], None

    monkeypatch.setattr(target_resolution, "system_answer", answer)
    action = _action("discover.dns_names", "dns.enumerate", 0, target=APEX)

    def cancelled():  # the operator cancels once the first batch has been asked
        return bool(asked)

    receipt = _run(action, cancelled=cancelled, target=APEX)
    assert receipt.status == "cancelled"
    assert 0 < receipt.budget_consumed["hosts_attempted"] < action.requested_budget["hosts_attempted"]


class _Private:
    def __init__(self, status, body, location=None):
        self.status_code, self._body = status, body
        self._headers = {"location": location} if location else {}

    def body(self):
        return self._body

    def headers(self):
        return dict(self._headers)


def test_vhost_discovery_uses_the_bound_origin_and_reports_only_confirmed_leads(monkeypatch):
    calls = []

    async def bound(origin, args, *, target, allow_write, private_response_sink,
                    virtual_host=None, **_kwargs):
        calls.append((origin, args["path"], virtual_host, allow_write, target.digest))
        body = b"<h1>Intranet portal</h1>" * 30 if virtual_host == "intranet.example.test" else b"default"
        private_response_sink(_Private(200, body))
        return {"ok": True}

    monkeypatch.setattr(recon_actions, "execute_bound_http_request", bound)
    action = _action("discover.virtual_hosts", "vhost.discover", 0, target=APEX)
    receipt = _run(action, target=APEX)
    leads = [row["host"] for row in receipt.observations if row.get("kind") == "virtual_host"]
    assert leads == ["intranet.example.test"]
    assert {call[0] for call in calls} == {"https://example.test"}
    assert all(call[3] is False and call[4] == APEX.digest for call in calls)
    assert receipt.budget_consumed["http_requests"] == len(calls) <= action.requested_budget["http_requests"]


def test_vhost_discovery_skips_a_bound_address_infrastructure_places_on_a_cdn(monkeypatch):
    async def bound(*_args, **_kwargs):
        raise AssertionError("no request on a shared edge")

    monkeypatch.setattr(recon_actions, "execute_bound_http_request", bound)
    infra = _action("baseline.infrastructure", "infrastructure.inspect", 0, target=APEX)
    action = _action("discover.virtual_hosts", "vhost.discover", 1, target=APEX)
    backend = Backend(observations={"baseline.infrastructure": ({
        "kind": "infrastructure_intelligence",
        "addresses": [{"address": "192.0.2.10", "asn": {"asn": "54113", "name": "FASTLY"}}],
    },)})
    receipt = _run(action, target=APEX, backend=backend, extra=(infra,))
    summary = [row for row in receipt.observations if row.get("kind") == "virtual_host_discovery"][0]
    assert summary["skipped"] == "not_applicable" and summary["reason"] == "shared_edge_or_cdn"
    assert summary["edge"] == "Fastly" and receipt.budget_consumed["http_requests"] == 0


def test_vhost_discovery_reads_edge_headers_of_the_bound_name(monkeypatch):
    calls = []

    async def bound(origin, args, *, private_response_sink, private_response_headers=(),
                    virtual_host=None, **_kwargs):
        calls.append((virtual_host, tuple(private_response_headers)))
        response = _Private(200, b"default")
        response._headers = {"server": "cloudflare", "cf-ray": "8a1b-AMS"}
        private_response_sink(response)
        return {"ok": True}

    monkeypatch.setattr(recon_actions, "execute_bound_http_request", bound)
    action = _action("discover.virtual_hosts", "vhost.discover", 0, target=APEX)
    receipt = _run(action, target=APEX)
    assert [call[0] for call in calls] == [None]
    assert "cf-ray" in calls[0][1]
    summary = [row for row in receipt.observations if row.get("kind") == "virtual_host_discovery"][0]
    assert summary["reason"] == "shared_edge_or_cdn" and summary["edge"] == "Cloudflare"


def test_parameter_discovery_reads_observed_routes_and_meters_requests(monkeypatch):
    calls = []

    async def bound(origin, args, *, target, private_response_sink, **_kwargs):
        calls.append((args["path"], dict(args.get("query") or {})))
        query = args.get("query") or {}
        body = b"results"
        if args["path"] == "/search" and "q" in query:
            body += str(query["q"]).encode()
        private_response_sink(_Private(200, body))
        return {"ok": True}

    monkeypatch.setattr(recon_actions, "execute_bound_http_request", bound)
    crawl = _action("discover.web_crawl", "web.crawl", 0)
    action = _action("discover.parameters", "web.param_discover", 1,
                     dependencies=("discover.web_crawl",))
    backend = Backend(observations={"discover.web_crawl": (
        {"kind": "discovered_route", "method": "GET", "url": "https://app.example.test/search"},
        {"kind": "discovered_route", "method": "GET", "url": "https://other.example.test/x"},
    )})
    plan = _plan(crawl, action)
    receipt = asyncio.run(_dispatcher(plan, backend, policy=ACTIVE)(action, _lease(plan, action), _noop))
    found = [(row["path"], row["parameter"]) for row in receipt.observations
             if row.get("kind") == "discovered_parameter"]
    assert found == [("/search", "q")]
    assert {path for path, _query in calls} == {"/", "/search"}
    assert receipt.budget_consumed["http_requests"] == len(calls)

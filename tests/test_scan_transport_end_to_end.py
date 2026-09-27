"""A target entered without a scheme, driven from submission to the finished report.

Observed on engine 2.5.4:

* ``tidyhelpers.com`` added without a scheme failed every Scan 0.1 s after start: the worker
  received the bare host and the external-tool binding refused it.
* ``POST /targets/{id}/scan`` for such a target froze only ``https://`` (the stored URL) even
  though the stored options said the scheme was inferred, while ``POST /scans`` with the same
  name froze both -- the two routes admitted different things.
* ``http://honey.shakerscan.com`` only redirects to ``https://`` on the same host. Its scan
  completed with coverage ``complete``, no grade and no findings: indistinguishable from a
  clean result, although nothing past the redirect was examined.

Each step had unit tests; nothing drove one target through admission, binding, the persisted
job, worker materialization, the compiled action graph, the orchestrator, the dispatcher and
the finalizer. These tests do, for both submission routes, with a fake network and a fake
action store -- every other component is the real one. External tools are not launched: the
test executor records the origin the dispatcher would hand them and settles them successful.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import sys
import urllib.parse
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(1, str(ROOT / "scanner"))

import api as api_module  # noqa: E402
import fleet_routes.router as fleet_router  # noqa: E402
import target_resolution  # noqa: E402
from targets import router as targets_router  # noqa: E402
from runtime.models import ScanPolicy, TargetBinding  # noqa: E402
from runtime.observation_manifests import ObservationManifest  # noqa: E402
import scan.action_adapter as action_adapter_module  # noqa: E402
from scan.action_adapter import DatabaseNeutralScanActionDispatcher  # noqa: E402
from scan.action_plan import ScanActionPlanCompiler  # noqa: E402
from scan.capability_result import (  # noqa: E402
    CapabilityReceiptReference,
    CapabilityResultReason,
    CapabilityResultReference,
    CapabilityResultStatus,
)
from scan.contracts import bind_scan_scope_receipt, resolve_scan_contract  # noqa: E402
from scan.execution_backend import ActionLease  # noqa: E402
from scan.jobs import CanonicalScanJob  # noqa: E402
from scan.job_runtime import materialize_canonical_scan_job  # noqa: E402
from scan.orchestrator import ScanOrchestrator  # noqa: E402
from scan.redirect_evidence import http_origin  # noqa: E402
from scan.transport import TRANSPORT_ACTION_ID  # noqa: E402
from scan.work_manifests import build_canonical_passive_nuclei_template_manifest  # noqa: E402

TARGET_ID = "00000000-0000-4000-8000-0000000000aa"
SCAN_ID = "00000000-0000-4000-8000-0000000000bb"
ADDRESS = "93.184.215.14"


# ----------------------------------------------------------------------------- the network


class Site:
    """Fake network: each origin serves the application, redirects, or refuses."""

    def __init__(self, **behaviour):
        # keys: canonical origins; values: "app" | ("redirect", location) | "down"
        self.behaviour = {http_origin(origin): value for origin, value in behaviour.items()}
        self.requests: list[str] = []

    async def request(self, base_url, args, *, target, **_kwargs):
        origin = http_origin(args.get("origin") or base_url)
        path = str(args.get("path") or "/")
        assert urllib.parse.urlsplit(origin).hostname == target.canonical_host, (
            "a request left the frozen host"
        )
        assert any(http_origin(item) == origin for item in target.allowed_origins), (
            "a request left the frozen origins"
        )
        self.requests.append(f"{origin}{path}")
        view = {"method": "GET", "origin": origin, "path": path}
        behaviour = self.behaviour.get(origin, "down")
        if behaviour == "down":
            return {"ok": False, "error": "request_error:ConnectError", "request": view}
        if behaviour == "app":
            return {"ok": True, "request": view, "response": {
                "status": 200, "final_url": f"{origin}{path}", "location": None,
                "security_headers": {"content-security-policy": "default-src 'self'"},
            }}
        _kind, location = behaviour
        return {"ok": True, "request": view, "response": {
            "status": 301, "final_url": f"{origin}{path}", "location": location,
            "security_headers": {},
        }}


# --------------------------------------------------------------------------- admission


def _admit(monkeypatch, *, route, typed, dns):
    """Run submission for ``typed`` through ``route`` up to the frozen binding and job."""

    async def lookup(hostname):
        import socket

        if hostname in dns:
            return [ADDRESS]
        raise socket.gaierror(socket.EAI_NONAME, "not known")

    async def resolve(url, *, subject, environment="production"):
        host = urllib.parse.urlsplit(url).hostname
        assert host in dns, f"admission resolved a name DNS does not know: {host}"
        return [ADDRESS]

    monkeypatch.setattr(target_resolution, "system_lookup", lookup)
    monkeypatch.setattr(api_module, "_resolve_runtime_target_addresses", resolve)
    monkeypatch.setattr(fleet_router, "_resolve_runtime_target_addresses", resolve)

    if route == "target":
        # The target was added as typed; creation stores the normalized URL and whether the
        # scheme was inferred. The target-ID route then submits from that stored state.
        normalized, _note = api_module.normalize_target_url(typed)
        stored = {"target_scheme_inferred": True} if "://" not in typed else {}
        submitted: list[str] = []

        class Conn:
            async def fetchrow(self, query, *args):
                return {"url": normalized, "scan_options": dict(stored)}

        class Pool:
            def acquire(self):
                class _A:
                    async def __aenter__(self_inner):
                        return Conn()

                    async def __aexit__(self_inner, *exc):
                        return False

                return _A()

        async def capture(request):
            submitted.append(request.target)
            return {}

        monkeypatch.setattr(targets_router, "_pool", lambda: Pool())
        monkeypatch.setattr(targets_router, "_submit_scan", capture)
        asyncio.run(targets_router.scan_target(TARGET_ID))
        request_target = submitted[0]
    else:
        request_target = typed

    # What _submit_scan does with the target, in order.
    scheme_inferred = "://" not in request_target
    normalized, _note = api_module.normalize_target_url(request_target)
    normalized, fallback = asyncio.run(
        target_resolution.scan_target_dns_fallback(normalized, None)
    )
    guard = asyncio.run(api_module._freeze_scan_target_binding(
        target_id=TARGET_ID, target_kind="web", target_url=normalized,
        scope_receipt_id="scope-1", scheme_inferred=scheme_inferred,
    ))
    binding = TargetBinding(
        target_id=TARGET_ID, target_kind="web",
        canonical_host=guard["canonical_host"],
        allowed_origins=tuple(guard["allowed_origins"]),
        allowed_addresses=tuple(guard["allowed_addresses"]),
        allowed_root_domains=tuple(guard["allowed_root_domains"]),
        environment=str(guard.get("environment") or "unknown"),
        scope_receipt_id="scope-1",
    )
    contract = bind_scan_scope_receipt(
        resolve_scan_contract(budget_profile="balanced", policy={"active_testing": False}),
        "scope-1",
    )
    job = CanonicalScanJob.create(
        job_id="job-1", scan_id=SCAN_ID, target=binding,
        execution_plan=contract.execution_plan, created_at="2026-09-26T12:00:00Z",
    )
    options = contract.execution_plan.option_metadata()
    options.update({"target_scheme_inferred": scheme_inferred, "runtime_scope_guard": guard})
    materialized = materialize_canonical_scan_job(job.payload(), {
        "target_id": TARGET_ID, "target_url": normalized, "job_id": job.job_id,
        "options": options, "scan_generation": "v2",
        "policy_json": job.execution_plan.canonical_dict()["policy"],
        "budget_json": job.execution_plan.canonical_dict()["budget"],
        "scan_job_payload": job.payload(), "scan_job_digest": job.payload_digest,
    }, resolved_addresses=(ADDRESS,))
    return binding, contract, materialized, fallback


# ------------------------------------------------------------------ orchestrated execution


class Backend:
    """In-memory action store converting receipts exactly as the Postgres backend does."""

    def __init__(self, plan):
        self.plan = plan
        self.results: dict[str, CapabilityResultReference] = {}
        self.observations: dict[str, tuple] = {}
        self.receipts: dict[str, dict] = {}

    async def acquire_action(self, action):
        return ActionLease(
            lease_id=str(uuid.uuid5(uuid.NAMESPACE_URL, action.action_id)),
            lease_token="0123456789abcdef0123456789abcdef",
            scan_id=self.plan.scan_id, plan_digest=self.plan.plan_digest,
            execution_plan_digest=self.plan.execution_plan_digest,
            target_binding_digest=self.plan.target_binding_digest,
            action=action, backend="local", worker_id="worker-1",
            lease_seconds=30, attempt=1,
        )

    async def heartbeat(self, lease):
        return None

    def _reference(self, action, *, status, reason, receipt=None):
        manifest = None
        count = len(receipt.observations) if receipt is not None else 0
        payload = json.dumps(
            [dict(item) for item in receipt.observations] if receipt is not None else [],
            sort_keys=True, default=str,
        ).encode()
        if status in {CapabilityResultStatus.SUCCESS, CapabilityResultStatus.PARTIAL}:
            manifest = ObservationManifest(
                owner_id=self.plan.scan_id, action_id=action.action_id,
                capability_name=action.capability_name, output_schema=action.output_schema,
                observation_count=count, content_sha256=hashlib.sha256(payload).hexdigest(),
                size_bytes=len(payload) if count else 0,
                object_key=f"scans/{self.plan.scan_id}/{action.action_id}.jsonl",
            ).reference()
        consumed = dict(receipt.budget_consumed) if receipt is not None else {}
        return CapabilityResultReference(
            action_id=action.action_id, action_digest=str(action.action_digest),
            capability_name=action.capability_name,
            adapter_name=str(action.placement["adapter_name"]),
            adapter_version=str(action.placement["adapter_version"]),
            output_schema=action.output_schema, status=status,
            partial=status is CapabilityResultStatus.PARTIAL, timed_out=False,
            reason_code=reason,
            receipt_ref=CapabilityReceiptReference(
                receipt_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"r:{action.action_id}")),
                receipt_hash=hashlib.sha256(action.action_id.encode()).hexdigest(),
            ),
            observation_manifest_ref=manifest,
            budget_reserved=dict(action.requested_budget), budget_consumed=consumed,
        )

    async def settle(self, lease, receipt):
        action = lease.action
        if isinstance(receipt, CapabilityResultReference):
            self.results[action.action_id] = receipt
            return receipt
        raw = receipt.status.strip().lower()
        status, reason = {
            "success": (CapabilityResultStatus.SUCCESS, None),
            "skipped": (CapabilityResultStatus.SKIPPED, CapabilityResultReason.NOT_APPLICABLE),
            "blocked": (CapabilityResultStatus.BLOCKED, CapabilityResultReason.ADAPTER_FAILED),
        }.get(raw, (CapabilityResultStatus.FAILED, CapabilityResultReason.ADAPTER_FAILED))
        self.receipts[action.action_id] = {
            "observations": [dict(item) for item in receipt.observations],
        }
        result = self._reference(action, status=status, reason=reason, receipt=receipt)
        # As in PostgreSQL: only a manifest-bound (successful or partial) result exposes its
        # observations; a failed action's evidence stays on its receipt.
        self.observations[action.action_id] = (
            tuple(receipt.observations) if result.observation_manifest_ref is not None else ()
        )
        self.results[action.action_id] = result
        return result

    async def cancel_action(self, action):
        raise AssertionError("nothing is cancelled here")

    async def load_result(self, action_id):
        return self.results.get(action_id)

    async def load_observations(self, action_id):
        return self.observations.get(action_id, ())

    async def load_action_receipt(self, action_id):
        return self.receipts.get(action_id, {})

    async def cancellation_requested(self):
        return False


class Executor:
    """Real dispatcher for HTTP probes and finalization; external tools only recorded."""

    def __init__(self, dispatcher, backend):
        self.dispatcher = dispatcher
        self.backend = backend
        self.tool_origins: dict[str, str] = {}

    async def execute(self, action, lease, heartbeat):
        if action.capability_name in {"http.request", "scan.finalize"}:
            return await self.dispatcher(action, lease, heartbeat)
        if self.dispatcher.target_url is None:
            await self.dispatcher._load_transport_resolution(required=True)
        self.tool_origins[action.action_id] = self.dispatcher.target_url
        return self.dispatcher._receipt(
            action, status="success", parser_version="test/1",
            started_at=datetime.now(timezone.utc).isoformat(),
        )

    async def terminal_without_execution(
        self, action, lease, *, status, reason_code, charge_full_reservation,
    ):
        return self.backend._reference(
            action, status=CapabilityResultStatus(status),
            reason=CapabilityResultReason(reason_code),
        )


def _scan(monkeypatch, *, route, typed, dns, site):
    binding, contract, materialized, fallback = _admit(
        monkeypatch, route=route, typed=typed, dns=dns,
    )
    monkeypatch.setattr(action_adapter_module, "execute_bound_http_request", site.request)
    templates = build_canonical_passive_nuclei_template_manifest(
        scan_id=SCAN_ID, target_binding_digest=binding.digest,
    )
    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID, execution_plan=contract.execution_plan, target_binding=binding,
        template_manifest_ref=templates.reference().canonical_dict(),
    )
    backend = Backend(plan)
    dispatcher = DatabaseNeutralScanActionDispatcher(
        target_url=materialized["target"], options=materialized["options"], target=binding,
        policy=ScanPolicy(**{
            **contract.execution_plan.canonical_dict()["policy"],
            "include_families": tuple(contract.execution_plan.policy.include_families),
            "exclude_families": tuple(contract.execution_plan.policy.exclude_families),
        }),
        scan_id=SCAN_ID, job_id="job-1", worker_id="worker-1", plan=plan, backend=backend,
        process_runner=None, cancelled=lambda: False,
    )
    executor = Executor(dispatcher, backend)
    outcome = asyncio.run(ScanOrchestrator(backend=backend, executor=executor).run(plan))
    report = next(
        row["report"] for row in backend.observations["finalize.report"]
        if row.get("kind") == "scan_report"
    )
    return {
        "binding": binding, "plan": plan, "materialized": materialized, "fallback": fallback,
        "results": outcome.action_results, "report": report, "tools": executor.tool_origins,
        "requests": site.requests, "backend": backend,
    }


ROUTES = ("scans", "target")


# ------------------------------------------------------------------------------- scenarios


@pytest.mark.parametrize("route", ROUTES)
def test_an_http_only_site_typed_without_a_scheme_is_examined_over_http(monkeypatch, route):
    site = Site(**{"http://plain.example.com": "app"})
    run = _scan(monkeypatch, route=route, typed="plain.example.com",
                dns={"plain.example.com"}, site=site)

    assert set(run["binding"].allowed_origins) == {
        "http://plain.example.com", "https://plain.example.com",
    }, "both routes freeze both origins for a target typed without a scheme"
    assert run["materialized"]["target"] == "plain.example.com"
    assert run["requests"][:2] == ["https://plain.example.com/", "http://plain.example.com/"]
    assert set(run["tools"].values()) == {"http://plain.example.com/"}
    assert run["results"][TRANSPORT_ACTION_ID].status is CapabilityResultStatus.SUCCESS
    report = run["report"]
    assert report["reachability"]["status"] == "reachable"
    # The stored report passes receipt URL redaction, which renders origins with a root path.
    assert http_origin(report["reachability"]["transport"]["effective_origin"]) == (
        "http://plain.example.com"
    )
    assert report["result"]["risk_assessment_state"] == "observed"
    assert report["coverage"]["status"] == "complete"


@pytest.mark.parametrize("route", ROUTES)
def test_an_https_only_site_is_examined_over_https_with_one_probe(monkeypatch, route):
    site = Site(**{"https://secure.example.com": "app"})
    run = _scan(monkeypatch, route=route, typed="secure.example.com",
                dns={"secure.example.com"}, site=site)

    assert run["requests"][0] == "https://secure.example.com/"
    probes = [row for row in run["backend"].observations[TRANSPORT_ACTION_ID]]
    assert len(probes) == 1, "HTTPS answered, so HTTP was never probed"
    transport = run["results"][TRANSPORT_ACTION_ID]
    assert transport.budget_reserved["http_requests"] == 2
    assert transport.budget_consumed["http_requests"] == 1, "the probe is metered"
    assert set(run["tools"].values()) == {"https://secure.example.com/"}
    assert run["report"]["result"]["risk_assessment_state"] == "observed"


@pytest.mark.parametrize("route", ROUTES)
def test_an_apex_without_an_address_is_examined_on_www(monkeypatch, route):
    site = Site(**{"https://www.example.com": "app"})
    run = _scan(monkeypatch, route=route, typed="example.com",
                dns={"www.example.com"}, site=site)

    assert run["fallback"]["resolved_host"] == "www.example.com"
    assert run["binding"].canonical_host == "www.example.com"
    assert run["binding"].target_id == TARGET_ID, "the original target keeps its identity"
    assert set(run["tools"].values()) == {"https://www.example.com/"}


@pytest.mark.parametrize("route", ROUTES)
def test_port_80_typed_without_a_scheme_resolves_to_http(monkeypatch, route):
    site = Site(**{"http://legacy.example.com": "app"})
    run = _scan(monkeypatch, route=route, typed="legacy.example.com:80",
                dns={"legacy.example.com"}, site=site)

    assert "http://legacy.example.com" in run["binding"].allowed_origins
    assert set(run["tools"].values()) == {"http://legacy.example.com/"}


@pytest.mark.parametrize("route", ROUTES)
def test_a_nonstandard_port_keeps_its_port_on_the_selected_origin(monkeypatch, route):
    site = Site(**{"http://app.example.com:8080": "app"})
    run = _scan(monkeypatch, route=route, typed="app.example.com:8080",
                dns={"app.example.com"}, site=site)

    assert set(run["binding"].allowed_origins) == {
        "http://app.example.com:8080", "https://app.example.com:8080",
    }
    assert set(run["tools"].values()) == {"http://app.example.com:8080/"}


@pytest.mark.parametrize("route", ROUTES)
def test_an_unreachable_application_is_not_examined_and_keeps_its_errors(monkeypatch, route):
    site = Site()  # nothing answers
    run = _scan(monkeypatch, route=route, typed="dark.example.com",
                dns={"dark.example.com"}, site=site)

    assert run["results"][TRANSPORT_ACTION_ID].status is CapabilityResultStatus.FAILED
    assert run["tools"] == {}, "no tool ran against an origin nobody answered"
    assert run["requests"] == ["https://dark.example.com/", "http://dark.example.com/"]
    report = run["report"]
    assert report["result"]["risk_assessment_state"] == "not_examined"
    assert report["result"]["grade"] is None
    assert report["coverage"]["status"] == "failed"
    assert "target_unreachable" in report["coverage"]["reasons"]
    attempts = report["reachability"]["transport"]["attempts"]
    assert [http_origin(item["origin"]) for item in attempts] == [
        "https://dark.example.com", "http://dark.example.com",
    ]
    assert all(item["outcome"] == "unreachable" and item["error"] for item in attempts)
    assert report["reachability"]["transport"]["effective_origin"] is None


@pytest.mark.parametrize("route", ROUTES)
def test_an_explicit_http_origin_that_only_redirects_to_https_is_not_examined(monkeypatch, route):
    """The honey.shakerscan.com case: explicit http://, application only on https://."""
    site = Site(**{
        "http://honey.example.com": ("redirect", "https://honey.example.com/"),
        "https://honey.example.com": "app",
    })
    run = _scan(monkeypatch, route=route, typed="http://honey.example.com",
                dns={"honey.example.com"}, site=site)

    assert run["binding"].allowed_origins == ("http://honey.example.com",), (
        "an explicit scheme stays exact"
    )
    assert not any(item.startswith("https://") for item in run["requests"]), (
        "the redirect is never followed to another origin"
    )
    transport = run["results"].get(TRANSPORT_ACTION_ID)
    assert transport is None, "a single frozen origin needs no transport probe"
    report = run["report"]
    assert report["result"]["risk_assessment_state"] == "not_examined"
    assert report["result"]["grade"] is None
    assert report["coverage"]["status"] != "complete"
    assert report["coverage"]["not_examined_reason"] == (
        "the target redirects to https://honey.example.com, outside this scan's origin"
    )
    assert "application_not_observed" in report["coverage"]["reasons"]


@pytest.mark.parametrize("route", ROUTES)
def test_scheme_less_target_whose_http_redirects_is_examined_on_https(monkeypatch, route):
    site = Site(**{
        "http://honey.example.com": ("redirect", "https://honey.example.com/"),
        "https://honey.example.com": "app",
    })
    run = _scan(monkeypatch, route=route, typed="honey.example.com",
                dns={"honey.example.com"}, site=site)

    assert set(run["tools"].values()) == {"https://honey.example.com/"}
    assert run["report"]["result"]["risk_assessment_state"] == "observed"
    assert run["report"]["coverage"]["status"] == "complete"

"""Database-neutral execution of immutable Scan actions.

The same adapter boundary can run behind a local PostgreSQL backend or an
outbound-only broker backend.  Durable leasing and settlement stay outside this
module; it performs only the target-bound operation authorized by one action.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Awaitable, Callable, Mapping, Protocol
import urllib.parse

try:
    import agent_tools
    from capabilities.auth import establish_target_bound_http_session
    from capabilities.authz import (
        authz_route_inventory_digest,
        verify_target_bound_object_authorization,
    )
    from capabilities.dns import inspect_dns_posture
    from capabilities.http import execute_bound_http_request
    from capabilities.inline import (
        AuthSessionExecutionAdapter,
        AuthzVerificationExecutionAdapter,
        DnsInspectionExecutionAdapter,
        HttpRequestExecutionAdapter,
        TlsInspectionExecutionAdapter,
    )
    from capabilities.network import NetworkExecutionAdapter, network_capability_adapter
    from capabilities.browser import XSSBrowserProofAdapter
    from capabilities.request_mutation import RequestMutationVerificationAdapter
    from capabilities.sqli_proof import SQLiProofAdapter
    from capabilities.nosqli_verify import NoSQLiVerifyAdapter
    from capabilities.exposure_probe import (
        SENSITIVE_SEED_PATHS,
        EXPOSURE_PROBE_PARSER_VERSION,
        classify_confidential_file,
        classify_exposure,
        directory_listing_links,
        redacted_exposure_excerpt,
    )
    from capabilities.scanner import ScannerExecutionAdapter
    from capabilities.tls import inspect_tls_binding
    from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.models import TargetBinding
    from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
    from runtime.receipts import CapabilityReceipt
    from runtime.request_replay_executor import execute_replay_plan
    from runtime.scan_credentials import (
        bind_scan_session_headers,
        resolve_scan_http_principal,
        resolve_scan_interactive_credential,
    )
    from runtime.target_bound_socket import FrozenTargetSocketFactory
    from scan.private_state import (
        SCAN_AUTH_SESSION_STATE_KIND,
        SCAN_PRIVATE_STATE_KEY_OPTION,
        ScanPrivateStateError,
        open_scan_auth_session_state,
        seal_scan_auth_session_state,
    )
except (ImportError, ModuleNotFoundError):
    from .. import agent_tools
    from ..capabilities.auth import establish_target_bound_http_session
    from ..capabilities.authz import (
        authz_route_inventory_digest,
        verify_target_bound_object_authorization,
    )
    from ..capabilities.dns import inspect_dns_posture
    from ..capabilities.http import execute_bound_http_request
    from ..capabilities.inline import (
        AuthSessionExecutionAdapter,
        AuthzVerificationExecutionAdapter,
        DnsInspectionExecutionAdapter,
        HttpRequestExecutionAdapter,
        TlsInspectionExecutionAdapter,
    )
    from ..capabilities.network import NetworkExecutionAdapter, network_capability_adapter
    from ..capabilities.browser import XSSBrowserProofAdapter
    from ..capabilities.request_mutation import RequestMutationVerificationAdapter
    from ..capabilities.sqli_proof import SQLiProofAdapter
    from ..capabilities.nosqli_verify import NoSQLiVerifyAdapter
    from ..capabilities.exposure_probe import (
        SENSITIVE_SEED_PATHS,
        EXPOSURE_PROBE_PARSER_VERSION,
        classify_confidential_file,
        classify_exposure,
        directory_listing_links,
        redacted_exposure_excerpt,
    )
    from ..capabilities.scanner import ScannerExecutionAdapter
    from ..capabilities.tls import inspect_tls_binding
    from ..hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
    from ..runtime.capability_registry import CAPABILITY_REGISTRY
    from ..runtime.models import TargetBinding
    from ..runtime.pinned_http_replay import PinnedAiohttpReplayTransport
    from ..runtime.receipts import CapabilityReceipt
    from ..runtime.request_replay_executor import execute_replay_plan
    from ..runtime.scan_credentials import (
        bind_scan_session_headers,
        resolve_scan_http_principal,
        resolve_scan_interactive_credential,
    )
    from ..runtime.target_bound_socket import FrozenTargetSocketFactory
    from .private_state import (
        SCAN_AUTH_SESSION_STATE_KIND,
        SCAN_PRIVATE_STATE_KEY_OPTION,
        ScanPrivateStateError,
        open_scan_auth_session_state,
        seal_scan_auth_session_state,
    )

try:
    from scanner_tools.url_redaction import redact_url
except (ImportError, ModuleNotFoundError):
    from scanner.scanner_tools.url_redaction import redact_url

try:
    from redaction import redact_text
except (ImportError, ModuleNotFoundError):
    from scanner.redaction import redact_text

try:
    from scanner_tools.common import run_streaming
    from scanner_tools.request_replay import (
        ReplayPlan,
        ReplayRequest,
        bind_replay_credential_headers,
    )
except (ImportError, ModuleNotFoundError):
    from scanner.scanner_tools.common import run_streaming
    from scanner.scanner_tools.request_replay import (
        ReplayPlan,
        ReplayRequest,
        bind_replay_credential_headers,
    )

from .action_plan import ScanAction, ScanActionPlan
from .continuation import (
    ScanContinuationError,
    ScanPlanRevision,
    root_scan_plan_revision,
)
from .capability_execution import (
    CANONICAL_SCAN_NETWORK_PORTS,
    fit_prepared_scan_capability,
    prepare_scan_external_capability,
    prepare_scan_inline_capability,
    scan_external_execution_target,
    scan_parameterized_execution_candidates,
)
from .execution_backend import ActionHeartbeat, ActionLease
from .finalizer import finalize_scan_report
from .private_inputs import BrokerPrivateScanInputs
from .work_manifests import (
    ScanWorkManifest,
    ScanWorkManifestError,
    ScanWorkManifestKind,
    ScanWorkManifestReference,
    canonical_nuclei_options_for_manifest,
    execution_url_for_endpoint,
    execution_url_for_manifest_candidate,
    execution_url_for_manifest_endpoint,
    execution_routes_for_endpoint_manifest,
    unique_work_manifest_reference_dicts,
)


ScannerProcessRunner = Callable[..., Awaitable[Mapping[str, Any]]]
Cancelled = Callable[[], bool]
PrivateReplayPlanLoader = Callable[
    [ScanAction, Mapping[str, Any]], Awaitable[ReplayPlan | None]
]


class ObservationBackend(Protocol):
    async def load_result(self, action_id: str) -> Any: ...
    async def load_observations(
        self, action_id: str,
    ) -> tuple[Mapping[str, Any], ...]: ...
    async def load_work_manifest(
        self, action_id: str, reference: ScanWorkManifestReference,
    ) -> ScanWorkManifest: ...
    async def load_batch_attempts(
        self, action_id: str,
    ) -> tuple[Mapping[str, Any], ...]: ...
    async def checkpoint_batch_attempt(
        self, action_id: str, attempt: Mapping[str, Any],
    ) -> None: ...


class ScanActionAdapterError(RuntimeError):
    """One immutable action has no safe database-neutral adapter mapping."""


def _exposure_observation(
    url: str, discovered_via: str, signature: Any, result: Any,
) -> Mapping[str, Any]:
    """Build one verified sensitive-exposure observation with content-free proof."""
    content_type = next((
        str(value) for name, value in result.response_headers.items()
        if str(name).lower() == "content-type"
    ), "")
    return {
        "kind": "sensitive_exposure_proof",
        "proof_state": "verified",
        "finding_verdict": "verified",
        "exposure_class": signature.exposure_class,
        "severity": signature.severity,
        "request_url": url,
        "discovered_via": discovered_via,
        "response_status": result.status_code,
        "content_type": content_type,
        "response_body_sha256": hashlib.sha256(result.response_body).hexdigest(),
        "matched_signature": signature.matched_pattern,
        "redacted_excerpt": redacted_exposure_excerpt(result.response_body, signature),
        "proof_producer": "shakerscan",
        "secret_values_visible": False,
    }


class DatabaseNeutralScanActionDispatcher:
    """Execute canonical actions without Redis or PostgreSQL credentials."""

    def __init__(
        self,
        *,
        target_url: str,
        options: Mapping[str, Any],
        target: TargetBinding,
        policy: Any,
        scan_id: str,
        job_id: str,
        worker_id: str,
        plan: ScanActionPlan,
        plan_revision: ScanPlanRevision | Mapping[str, Any] | None = None,
        backend: ObservationBackend,
        process_runner: ScannerProcessRunner,
        cancelled: Cancelled,
        private_inputs: BrokerPrivateScanInputs | None = None,
        private_replay_plan_loader: PrivateReplayPlanLoader | None = None,
    ) -> None:
        if not isinstance(plan, ScanActionPlan) or target.digest != plan.target_binding_digest:
            raise ScanActionAdapterError("action dispatcher authority is inconsistent")
        try:
            revision = (
                plan_revision
                if isinstance(plan_revision, ScanPlanRevision)
                else ScanPlanRevision.from_dict(plan_revision)
                if isinstance(plan_revision, Mapping)
                else root_scan_plan_revision(plan)
            )
        except (ScanContinuationError, TypeError, ValueError) as exc:
            raise ScanActionAdapterError(
                "action dispatcher plan revision is invalid"
            ) from exc
        if revision.scan_id != plan.scan_id or revision.plan_digest != plan.plan_digest:
            raise ScanActionAdapterError(
                "action dispatcher plan revision differs from its plan"
            )
        if private_inputs is not None and (
            private_inputs.plan_digest != plan.plan_digest
            or private_inputs.target_binding_digest != plan.target_binding_digest
            or private_inputs.worker_id != str(worker_id)
        ):
            raise ScanActionAdapterError(
                "private Scan inputs differ from dispatcher authority"
            )
        self.target_url = scan_external_execution_target(target_url, target=target)
        self.options = dict(options)
        if private_inputs is not None:
            self.options.update(dict(private_inputs.options))
        self.target = target
        self.policy = policy
        self.scan_id = str(scan_id)
        self.job_id = str(job_id)
        self.worker_id = str(worker_id)
        self.plan = plan
        self.plan_revision = revision
        self.backend = backend
        self.process_runner = process_runner
        self.cancelled = cancelled
        self._private_replay_plan_loader = private_replay_plan_loader
        self._private_replay_plans = dict(
            private_inputs.replay_plans if private_inputs is not None else {}
        )
        # Exact request bodies become verifier inputs only after their replay
        # action actually succeeds.  Preloading them would let a dependent
        # verifier run after a failed or skipped collection action.
        self._private_requests: dict[str, Any] = {}

    async def _private_replay_plan(
        self, action: ScanAction,
    ) -> ReplayPlan | None:
        plan = self._private_replay_plans.get(action.action_id)
        if plan is not None or self._private_replay_plan_loader is None:
            return plan
        plan = await self._private_replay_plan_loader(action, self.options)
        if plan is not None:
            self._private_replay_plans[action.action_id] = plan
        return plan

    def _receipt(
        self,
        action: ScanAction,
        *,
        status: str,
        parser_version: str,
        started_at: str,
        observations: tuple[Mapping[str, Any], ...] = (),
        errors: tuple[str, ...] = (),
        consumed: Mapping[str, int] | None = None,
        partial: bool = False,
        timed_out: bool = False,
        redacted_execution: Mapping[str, Any] | None = None,
    ) -> CapabilityReceipt:
        return CapabilityReceipt(
            capability_name=action.capability_name,
            adapter_name=str(action.placement.get("adapter_name") or ""),
            adapter_version=str(action.placement.get("adapter_version") or ""),
            target_id=self.target.target_id,
            scan_id=self.scan_id,
            worker_id=self.worker_id,
            scope_receipt_id=self.target.scope_receipt_id,
            approval_receipt_id=self.policy.approval_receipt_id,
            status=status,
            partial=partial,
            timed_out=timed_out,
            input_digest=str(action.action_digest),
            parser_version=parser_version,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            redacted_execution=dict(redacted_execution or {
                "action_id": action.action_id,
            }),
            budget_reserved=action.requested_budget,
            budget_consumed=dict(consumed or {
                name: 0 for name in action.requested_budget
            }),
            observations=observations,
            errors=errors,
        )

    def _skip(self, action: ScanAction, reason: str) -> CapabilityReceipt:
        now = datetime.now(timezone.utc).isoformat()
        return self._receipt(
            action,
            status="skipped",
            parser_version="scan-action-dispatch/v1",
            started_at=now,
            errors=(reason,),
            redacted_execution={
                "action_id": action.action_id,
                "execution_started": False,
            },
        )

    async def _observations(self, action_id: str) -> tuple[Mapping[str, Any], ...]:
        return await self.backend.load_observations(action_id)

    async def restore_terminal_state(
        self, action: ScanAction, _result: Any,
    ) -> bool:
        """Rehydrate sealed prerequisites without repeating completed traffic."""
        if action.action_id in {"inputs.auth_primary", "inputs.auth_secondary"}:
            lane = (
                "primary" if action.action_id.endswith("primary") else "secondary"
            )
            credential = resolve_scan_interactive_credential(
                self.options, lane=lane, capability_name=action.capability_name,
            )
            if credential is None:
                return True
            if resolve_scan_http_principal(
                self.options, lane=lane, capability_name=action.capability_name,
            ).authenticated:
                return True
            checkpoints = [
                item for item in await self._observations(action.action_id)
                if item.get("kind") == SCAN_AUTH_SESSION_STATE_KIND
            ]
            if len(checkpoints) != 1:
                return False
            try:
                headers = open_scan_auth_session_state(
                    self.options.get(SCAN_PRIVATE_STATE_KEY_OPTION),
                    checkpoints[0],
                    scan_id=self.scan_id,
                    action_id=action.action_id,
                    action_digest=action.action_digest,
                    target_binding_digest=self.target.digest,
                    lane=lane,
                    credential_binding_digest=credential.binding_digest,
                    profile_id=credential.profile_id,
                    profile_version=credential.profile_version,
                    principal=credential.principal,
                )
                self.options = bind_scan_session_headers(
                    self.options, headers, lane=lane,
                )
            except (ScanPrivateStateError, ValueError, TypeError):
                return False
            return resolve_scan_http_principal(
                self.options, lane=lane, capability_name=action.capability_name,
            ).authenticated
        if action.action_id.startswith("inputs.collection_"):
            plan = await self._private_replay_plan(action)
            if plan is None:
                return False
            principal = resolve_scan_http_principal(
                self.options, lane="primary",
                capability_name=action.capability_name,
            )
            primary_profile_bound = any(
                isinstance(item, Mapping)
                and str(item.get("scan_lane") or item.get("auth_state") or "")
                in {"primary", "user1"}
                for item in self.options.get("resolved_credential_profiles") or ()
            )
            if primary_profile_bound:
                if not principal.authenticated:
                    return False
                plan = bind_replay_credential_headers(
                    plan, principal.headers(), auth_kind="broker_session",
                )
            for request in plan.requests:
                previous = self._private_requests.get(request.request_id)
                if (
                    previous is not None
                    and previous.digest_dict() != request.digest_dict()
                ):
                    return False
                self._private_requests[request.request_id] = request
        return True

    async def _work_manifest(
        self,
        action: ScanAction,
        argument_name: str,
        expected_kind: ScanWorkManifestKind,
    ) -> ScanWorkManifest | None:
        raw = action.capability_args.get(argument_name)
        if not isinstance(raw, Mapping):
            return None
        try:
            reference = ScanWorkManifestReference.from_dict(raw)
        except ScanWorkManifestError as exc:
            raise ScanActionAdapterError(
                f"action {action.action_id} has an invalid {argument_name}"
            ) from exc
        if reference.kind is not expected_kind:
            raise ScanActionAdapterError(
                f"action {action.action_id} has the wrong manifest kind"
            )
        return await self.backend.load_work_manifest(action.action_id, reference)

    async def _manifest_endpoint(self, action: ScanAction) -> str | None:
        manifest = await self._work_manifest(
            action, "target_manifest_ref", ScanWorkManifestKind.ENDPOINT,
        )
        if manifest is None:
            return None
        if not manifest.entries:
            return None
        try:
            return execution_url_for_manifest_endpoint(
                manifest, action.capability_args.get("endpoint_index"),
            )
        except ScanWorkManifestError as exc:
            raise ScanActionAdapterError(str(exc)) from exc

    async def _manifest_candidate(self, action: ScanAction) -> str | None:
        candidates = await self._work_manifest(
            action, "candidate_manifest_ref", ScanWorkManifestKind.CANDIDATE,
        )
        if candidates is None:
            return None
        if not candidates.entries:
            return None
        endpoints = await self._work_manifest(
            action, "endpoint_manifest_ref", ScanWorkManifestKind.ENDPOINT,
        )
        if endpoints is None:
            raise ScanActionAdapterError(
                "candidate action has no endpoint manifest authority"
            )
        try:
            return execution_url_for_manifest_candidate(
                endpoints,
                candidates,
                action.capability_args.get("candidate_index"),
            )
        except ScanWorkManifestError as exc:
            raise ScanActionAdapterError(str(exc)) from exc

    async def _execute_adapter(
        self,
        action: ScanAction,
        adapter: Any,
        heartbeat: ActionHeartbeat,
        *,
        managed_cancellation: bool = False,
        target: TargetBinding | None = None,
    ) -> CapabilityReceipt:
        started = datetime.now(timezone.utc)
        result = await CapabilityExecutor().execute(
            CapabilityExecutionContext(
                specification=CAPABILITY_REGISTRY.require(action.capability_name),
                target=target or self.target,
                requested_budget=action.requested_budget,
                adapter_managed_cancellation=managed_cancellation,
            ),
            adapter,
            heartbeat=heartbeat,
            cancelled=self.cancelled,
        )
        return self._receipt(
            action,
            status=result.status,
            parser_version=result.parser_version,
            started_at=started.isoformat(),
            observations=result.observations,
            errors=result.errors,
            consumed=result.actual_budget,
            partial=result.partial,
            timed_out=result.timed_out,
            redacted_execution=result.redacted_execution,
        )

    def _prepared_inline(
        self, action: ScanAction, args: Mapping[str, Any], operation: Any, kind: Any,
    ) -> Any:
        spec = CAPABILITY_REGISTRY.require(action.capability_name)
        prepared = fit_prepared_scan_capability(
            prepare_scan_inline_capability(
                specification=spec,
                target=self.target,
                args=args,
                policy=self.policy,
            ),
            ledger_limits=action.requested_budget,
        )
        return kind(
            specification=spec,
            operation=operation,
            requested_budget=action.requested_budget,
            redacted_execution=prepared.redacted_execution,
        )

    async def _http(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        parsed = urllib.parse.urlsplit(self.target_url)
        scheme = "http" if action.action_id == "baseline.http_redirect" else parsed.scheme
        origin = urllib.parse.urlunsplit((scheme, parsed.netloc, "", "", ""))
        if origin not in self.target.allowed_origins:
            return self._skip(action, "not_applicable")
        path = (
            "/.well-known/security.txt"
            if action.action_id == "baseline.security_txt"
            else parsed.path or "/"
        )
        follow = action.action_id == "baseline.http_redirect"
        args = {"method": "GET", "path": path, "follow_redirects": follow}
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=action.capability_name,
        )

        async def operation() -> Mapping[str, Any]:
            result = dict(await execute_bound_http_request(
                origin,
                args,
                target=self.target,
                allow_write=False,
                timeout_seconds=max(1, int(action.requested_budget.get("tool_wall_seconds") or 1)),
                allow_bound_origin_redirects=follow,
                trusted_headers=(
                    primary.headers()
                    if action.action_id == "baseline.http" else None
                ),
                principal_slot=(
                    "primary" if primary.authenticated else "anonymous"
                ),
            ))
            request = (
                dict(result.get("request") or {})
                if isinstance(result.get("request"), Mapping) else {}
            )
            if request.get("path"):
                request["path"] = redact_url(str(request["path"]))
            result["request"] = request
            response = (
                dict(result.get("response") or {})
                if isinstance(result.get("response"), Mapping) else {}
            )
            if action.action_id == "baseline.security_txt":
                body = str(response.get("body_sample") or "").strip()
                markers = (
                    "contact:", "expires:", "acknowledgments:", "encryption:",
                    "preferred-languages:", "policy:", "hiring:", "canonical:",
                )
                response["security_txt"] = {
                    "present": bool(
                        response.get("status") == 200
                        and body
                        and any(marker in body.lower() for marker in markers)
                    ),
                    "url": redact_url(
                        urllib.parse.urljoin(origin.rstrip("/") + "/", path.lstrip("/"))
                    ),
                    "sample": redact_text(body)[:500] if body else None,
                }
            response["body_sample"] = ""
            response["selected_json"] = {}
            selected = (
                dict(response.get("selected_headers") or {})
                if isinstance(response.get("selected_headers"), Mapping) else {}
            )
            response["selected_headers"] = {
                str(name).lower()[:120]: redact_text(str(value))[:2_000]
                for name, value in selected.items()
            }
            for name in ("final_url", "location"):
                if response.get(name):
                    response[name] = redact_url(str(response[name]))
            result["response"] = response
            chain = []
            for item in result.get("redirect_chain") or ():
                if not isinstance(item, Mapping):
                    continue
                row = dict(item)
                if row.get("location"):
                    row["location"] = redact_url(str(row["location"]))
                chain.append(row)
            result["redirect_chain"] = chain
            return result

        adapter = self._prepared_inline(
            action, args, operation, HttpRequestExecutionAdapter,
        )
        return await self._execute_adapter(action, adapter, heartbeat)

    async def _dns(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        async def operation() -> Mapping[str, Any]:
            return await inspect_dns_posture(
                self.target,
                timeout_seconds=max(1, int(action.requested_budget.get("tool_wall_seconds") or 1)),
            )

        adapter = self._prepared_inline(
            action, {}, operation, DnsInspectionExecutionAdapter,
        )
        return await self._execute_adapter(action, adapter, heartbeat)

    async def _tls(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        https_origins = [
            str(item) for item in self.target.allowed_origins
            if str(item).lower().startswith("https://")
        ]
        if not https_origins:
            return self._skip(action, "not_applicable")
        expected_args = {
            "origins_ref": "frozen_https_origins",
            "origin_count": len(https_origins),
            "addresses_ref": "frozen_addresses",
            "address_count": len(self.target.allowed_addresses),
        }
        if dict(action.capability_args) != expected_args:
            raise ScanActionAdapterError(
                "TLS action differs from the frozen target matrix"
            )

        async def operation() -> Mapping[str, Any]:
            return await inspect_tls_binding(
                target=self.target,
                timeout_seconds_per_target=15,
            )

        adapter = self._prepared_inline(
            action, expected_args, operation, TlsInspectionExecutionAdapter,
        )
        return await self._execute_adapter(action, adapter, heartbeat)

    async def _network(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        factory = network_capability_adapter(action.capability_name)
        host_limit = int(action.requested_budget.get("hosts_attempted") or 0)
        addresses = tuple(self.target.allowed_addresses[:host_limit])
        if not addresses:
            return self._skip(action, "not_applicable")
        bounded_target = TargetBinding(
            target_id=self.target.target_id,
            target_kind=self.target.target_kind,
            canonical_host=self.target.canonical_host,
            allowed_origins=self.target.allowed_origins,
            allowed_addresses=addresses,
            allowed_root_domains=self.target.allowed_root_domains,
            environment=self.target.environment,
            scope_receipt_id=self.target.scope_receipt_id,
        )
        if action.capability_name == "subdomains.discover":
            args = {"root_domain": self.target.allowed_root_domains[0]}
        else:
            attempt_budget = int(action.requested_budget.get("tcp_ports_attempted") or 0)
            per_address = max(0, attempt_budget // len(addresses))
            if action.capability_name == "ports.discover":
                ports = list(CANONICAL_SCAN_NETWORK_PORTS[:per_address])
            else:
                rows = await self._observations("discover.ports")
                ports = sorted({
                    int(item.get("port") or 0)
                    for item in rows
                    if item.get("kind") == "open_port" and item.get("port")
                })[:per_address]
            if not ports:
                return self._skip(action, "not_applicable")
            args = {"ports": ports}
            if action.capability_name == "service.fingerprint":
                args["profile"] = "version_light"
        prepared = fit_prepared_scan_capability(
            factory.prepare(target=bounded_target, args=args, policy=self.policy),
            ledger_limits=action.requested_budget,
        )
        adapter = NetworkExecutionAdapter(
            prepared=prepared,
            parser=factory,
            command_runner=run_streaming,
            max_stdout_bytes=2_000_000,
            max_stderr_bytes=20_000,
        )
        return await self._execute_adapter(
            action, adapter, heartbeat, target=bounded_target,
        )

    async def _auth_session(
        self, action: ScanAction, heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        lane = "primary" if action.action_id.endswith("primary") else "secondary"
        credential = resolve_scan_interactive_credential(
            self.options, lane=lane, capability_name=action.capability_name,
        )
        if credential is None:
            return self._skip(action, "not_applicable")

        async def operation() -> Mapping[str, Any]:
            session = await establish_target_bound_http_session(
                credential.session_credential(), target=self.target,
            )
            if session.established and session.headers():
                self.options = bind_scan_session_headers(
                    self.options, session.headers(), lane=lane,
                )
            result = dict(session.execution_result())
            if session.established and session.headers():
                state_key = self.options.get(SCAN_PRIVATE_STATE_KEY_OPTION)
                if not state_key:
                    raise ScanPrivateStateError(
                        "canonical auth session has no private checkpoint key"
                    )
                result["observations"] = [seal_scan_auth_session_state(
                    state_key,
                    scan_id=self.scan_id,
                    action_id=action.action_id,
                    action_digest=action.action_digest,
                    target_binding_digest=self.target.digest,
                    lane=lane,
                    credential_binding_digest=credential.binding_digest,
                    headers=session.headers(),
                    session_ref=session.session_ref,
                    profile_id=session.profile_id,
                    profile_version=session.profile_version,
                    principal=session.principal,
                    established_at=session.established_at,
                    expires_at=session.expires_at,
                    refresh_after=session.refresh_after,
                    compatible_capabilities=session.compatible_capabilities,
                    evidence_receipt_digest=session.evidence_receipt_digest,
                )]
            return result

        specification = CAPABILITY_REGISTRY.require(action.capability_name)
        adapter = AuthSessionExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=action.requested_budget,
            redacted_execution={
                "action_id": action.action_id,
                "lane": lane,
                "credential_binding_digest": credential.binding_digest,
                "secret_values_visible": False,
            },
        )
        return await self._execute_adapter(action, adapter, heartbeat)

    async def _collection_replay(
        self, action: ScanAction, heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        plan = await self._private_replay_plan(action)
        if plan is None:
            return self._skip(action, "private_request_unavailable")
        if any(
            int(action.requested_budget.get(name) or 0) < int(amount)
            for name, amount in plan.estimated_budget.items()
        ):
            raise ScanActionAdapterError(
                "private replay plan exceeds its immutable action reservation"
            )
        principal = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=action.capability_name,
        )
        primary_profile_bound = any(
            isinstance(item, Mapping)
            and str(item.get("scan_lane") or item.get("auth_state") or "")
            in {"primary", "user1"}
            for item in self.options.get("resolved_credential_profiles") or ()
        )
        if primary_profile_bound:
            if not principal.authenticated:
                return self._skip(action, "credential_session_unavailable")
            plan = bind_replay_credential_headers(
                plan,
                principal.headers(),
                auth_kind="broker_session",
            )
        bound_ref = action.capability_args.get("request_collection_ref")
        option_ref = next((
            dict(item)
            for item in self.options.get("request_collections") or ()
            if isinstance(item, Mapping)
            and isinstance(bound_ref, Mapping)
            and str(item.get("selection_id") or "")
            == str(bound_ref.get("selection_id") or "")
            and str(item.get("selection_digest") or "").lower()
            == str(bound_ref.get("selection_digest") or "").lower()
        ), {})
        receipt_context: dict[str, Any] = {
            "collection_id": str(option_ref.get("collection_id") or ""),
            "selection_id": str(option_ref.get("selection_id") or ""),
            "selection_digest": str(option_ref.get("selection_digest") or ""),
            "collection_payload_digest": str(
                option_ref.get("payload_sha256") or ""
            ),
            "environment_digest": str(
                option_ref.get("environment_sha256") or ""
            ),
            "target_binding_digest": self.target.digest,
        }
        manifest_ref = action.capability_args.get("request_manifest_ref")
        if isinstance(manifest_ref, Mapping):
            receipt_context["request_manifest_digest"] = str(
                manifest_ref.get("manifest_digest") or ""
            )
        if principal.authenticated and principal.binding_digest:
            receipt_context["principal_binding_digest"] = (
                principal.binding_digest
            )
        wall = max(1, int(action.requested_budget.get("tool_wall_seconds") or 1))
        await heartbeat()
        outcome = await execute_replay_plan(
            plan,
            target=self.target,
            owner_kind="scan",
            owner_id=self.scan_id,
            worker_id=self.worker_id,
            limits=action.requested_budget,
            consumed={name: 0 for name in action.requested_budget},
            transport=PinnedAiohttpReplayTransport(),
            timeout_seconds=max(0.1, min(30.0, wall / len(plan.requests))),
            lease_seconds=max(30, wall + 5),
            authorized_budget=action.requested_budget,
            receipt_context=receipt_context,
            receipt_capability_name=action.capability_name,
            receipt_input_digest=action.action_digest,
            cancelled=self.cancelled,
        )
        for request in plan.requests:
            previous = self._private_requests.get(request.request_id)
            if previous is not None and previous.digest_dict() != request.digest_dict():
                raise ScanActionAdapterError(
                    "private replay request changed during broker execution"
                )
            self._private_requests[request.request_id] = request
        receipt = outcome.receipt
        return self._receipt(
            action,
            status=(
                "success" if outcome.status == "succeeded" else outcome.status
            ),
            parser_version=receipt.parser_version,
            started_at=receipt.started_at,
            observations=receipt.observations,
            errors=receipt.errors,
            consumed=receipt.budget_consumed,
            partial=receipt.partial,
            timed_out=receipt.timed_out,
            redacted_execution={
                **dict(receipt.redacted_execution),
                "action_id": action.action_id,
                "private_transport": "lease_sealed",
            },
        )

    async def _request_mutation(
        self, action: ScanAction, heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        if (
            not self.policy.active_testing
            or not self.policy.allow_state_changing_http
            or not self.policy.approval_receipt_id
        ):
            return self._skip(action, "state_changing_authority_missing")
        manifest = await self._work_manifest(
            action,
            "request_candidate_manifest_ref",
            ScanWorkManifestKind.REQUEST_CANDIDATE,
        )
        if manifest is None or not manifest.entries:
            return self._skip(action, "manifest_unavailable")
        index = action.capability_args.get("request_candidate_index")
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or not 0 <= index < len(manifest.entries)
        ):
            raise ScanActionAdapterError(
                "request verifier candidate index is invalid"
            )
        candidate = manifest.entries[index]
        request = self._private_requests.get(
            str(candidate.get("request_ref_id") or "")
        )
        if request is None:
            return self._skip(action, "private_request_unavailable")
        specification = CAPABILITY_REGISTRY.require(action.capability_name)
        adapter = RequestMutationVerificationAdapter(
            specification=specification,
            target=self.target,
            request=request,
            candidate=candidate,
            transport=PinnedAiohttpReplayTransport(),
            requested_budget=action.requested_budget,
        )
        return await self._execute_adapter(
            action, adapter, heartbeat, managed_cancellation=True,
        )

    async def _request_mutation_batch(
        self, action: ScanAction, heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        """Mutate exact private body fields with per-candidate durable checkpoints."""
        manifest = await self._work_manifest(
            action,
            "request_candidate_manifest_ref",
            ScanWorkManifestKind.REQUEST_CANDIDATE,
        )
        if manifest is None:
            return self._skip(action, "manifest_unavailable")
        raw_slice = action.capability_args.get("slice")
        if not isinstance(raw_slice, Mapping):
            raise ScanActionAdapterError("request batch slice is invalid")
        start = raw_slice.get("start")
        count = raw_slice.get("count")
        if (
            isinstance(start, bool) or not isinstance(start, int) or start < 0
            or isinstance(count, bool) or not isinstance(count, int)
            or not 1 <= count <= 50
        ):
            raise ScanActionAdapterError("request batch slice is invalid")
        rows = tuple(manifest.entries[start:min(len(manifest.entries), start + count)])
        if not rows:
            return self._skip(action, "not_applicable")
        load_attempts = getattr(self.backend, "load_batch_attempts", None)
        checkpoint_attempt = getattr(self.backend, "checkpoint_batch_attempt", None)
        if not callable(load_attempts) or not callable(checkpoint_attempt):
            raise ScanActionAdapterError(
                "request batch backend has no durable attempt checkpoint contract"
            )
        completed = {
            str(item.get("attempt_id") or ""): dict(item)
            for item in await load_attempts(action.action_id)
            if isinstance(item, Mapping)
        }
        family = "xss" if action.capability_name.startswith("xss.") else "sqli"
        manifest_digest = manifest.reference().manifest_digest
        started_at = datetime.now(timezone.utc).isoformat()
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        consumed = {name: 0 for name in action.requested_budget}
        attempted = 0
        resumed = 0
        for offset, candidate in enumerate(rows):
            candidate_id = str(candidate["candidate_id"])
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:{family}:{candidate_id}".encode()
            ).hexdigest()
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                observations.extend(prior.get("observations") or ())
                for name, amount in dict(prior.get("budget_consumed") or {}).items():
                    consumed[name] = consumed.get(name, 0) + int(amount)
                continue
            if self.cancelled():
                break
            request_class = str(candidate.get("request_class") or "")
            request = self._private_requests.get(str(candidate["request_ref_id"]))
            authorized = (
                request_class == "safe_authentication"
                or (
                    request_class == "confirmed_mutation"
                    and self.policy.allow_state_changing_http
                    and bool(self.policy.approval_receipt_id)
                )
            )
            remaining_attempts = max(1, len(rows) - offset)
            remaining = {
                name: max(0, int(limit) - int(consumed.get(name, 0)))
                for name, limit in action.requested_budget.items()
            }
            sub_budget = {
                name: amount // remaining_attempts
                for name, amount in remaining.items() if amount // remaining_attempts > 0
            }
            if (
                request is None or not authorized
                or sub_budget.get("http_requests", 0) < 2
                or sub_budget.get("tool_wall_seconds", 0) < 1
                or (
                    request_class == "confirmed_mutation"
                    and sub_budget.get("state_changing_requests", 0) < 2
                )
            ):
                break
            specification = CAPABILITY_REGISTRY.require(action.capability_name)
            adapter = RequestMutationVerificationAdapter(
                specification=specification,
                target=self.target,
                request=request,
                candidate=candidate,
                transport=PinnedAiohttpReplayTransport(),
                requested_budget=sub_budget,
            )
            result = await CapabilityExecutor().execute(
                CapabilityExecutionContext(
                    specification=specification,
                    target=self.target,
                    requested_budget=sub_budget,
                    adapter_managed_cancellation=True,
                ),
                adapter,
                heartbeat=heartbeat,
                cancelled=self.cancelled,
            )
            attempt_observations = tuple({
                **dict(item),
                "attempt_id": attempt_id,
                "candidate_id": candidate_id,
            } for item in result.observations)
            proof_state = next((
                str(item.get("proof_status"))
                for item in attempt_observations if item.get("proof_status")
            ), "not_proven")
            attempt_observations = ({
                "kind": "candidate_attempt",
                "attempt_id": attempt_id,
                "candidate_id": candidate_id,
                "family": family,
                "request_class": request_class,
                "field_path": candidate.get("field_path"),
                "status": result.status,
                "proof_state": proof_state,
                "response_hashes": sorted({
                    str(value)
                    for item in attempt_observations
                    for key, value in item.items()
                    if "sha256" in str(key).lower() and str(value)
                })[:20],
                "budget_consumed": dict(result.actual_budget),
            }, *attempt_observations)
            attempt = {
                "attempt_id": attempt_id,
                "candidate_id": candidate_id,
                "status": result.status,
                "budget_consumed": dict(result.actual_budget),
                "observations": attempt_observations,
                "errors": tuple(result.errors),
                "proof_state": proof_state,
            }
            if result.status != "cancelled":
                await checkpoint_attempt(action.action_id, attempt)
            attempted += 1
            observations.extend(attempt_observations)
            errors.extend(str(item) for item in result.errors)
            for name, amount in result.actual_budget.items():
                consumed[name] = min(
                    int(action.requested_budget.get(name, 0)),
                    consumed.get(name, 0) + int(amount),
                )
            if result.status == "cancelled":
                break
        unattempted = max(0, len(rows) - attempted)
        return self._receipt(
            action,
            status="partial" if unattempted else "success",
            parser_version=CAPABILITY_REGISTRY.require(action.capability_name).output_schema,
            started_at=started_at,
            observations=tuple(observations),
            errors=tuple(errors[:20]),
            consumed=consumed,
            partial=bool(unattempted),
            timed_out=False,
            redacted_execution={
                "action_id": action.action_id,
                "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "candidate_count": len(rows),
                "attempted_count": attempted,
                "resumed_count": resumed,
                "unattempted_count": unattempted,
                "checkpoint_mode": "after_each_candidate",
                "private_transport": "exact_request",
            },
        )

    async def _xss_browser_proof_batch(
        self, action: ScanAction, heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        manifest = await self._work_manifest(
            action, "candidate_manifest_ref", ScanWorkManifestKind.CANDIDATE,
        )
        endpoints = await self._work_manifest(
            action, "endpoint_manifest_ref", ScanWorkManifestKind.ENDPOINT,
        )
        if manifest is None or endpoints is None:
            return self._skip(action, "manifest_unavailable")
        raw_slice = action.capability_args.get("slice")
        if not isinstance(raw_slice, Mapping):
            raise ScanActionAdapterError("XSS proof batch slice is invalid")
        start, count = raw_slice.get("start"), raw_slice.get("count")
        if (
            isinstance(start, bool) or not isinstance(start, int) or start < 0
            or isinstance(count, bool) or not isinstance(count, int)
            or not 1 <= count <= 50
        ):
            raise ScanActionAdapterError("XSS proof batch slice is invalid")
        rows = tuple(enumerate(
            manifest.entries[start:min(len(manifest.entries), start + count)], start=start,
        ))
        if not rows:
            return self._skip(action, "not_applicable")
        candidate_signals: set[str] = set()
        for dependency in action.dependencies:
            for item in await self._observations(dependency):
                if (
                    str(item.get("kind") or "") in {"xss_alert", "request_body_verification"}
                    and str(item.get("candidate_id") or "")
                    and str(item.get("proof_state") or item.get("proof_status") or "")
                    not in {"not_proven", "unproven", ""}
                ):
                    candidate_signals.add(str(item["candidate_id"]))
        if not candidate_signals:
            return self._skip(action, "no_xss_candidate_observation")
        load_attempts = getattr(self.backend, "load_batch_attempts", None)
        checkpoint_attempt = getattr(self.backend, "checkpoint_batch_attempt", None)
        if not callable(load_attempts) or not callable(checkpoint_attempt):
            raise ScanActionAdapterError("XSS proof backend lacks durable checkpoints")
        completed = {
            str(item.get("attempt_id") or ""): dict(item)
            for item in await load_attempts(action.action_id)
            if isinstance(item, Mapping)
        }
        manifest_digest = manifest.reference().manifest_digest
        started_at = datetime.now(timezone.utc).isoformat()
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        consumed = {name: 0 for name in action.requested_budget}
        attempted = resumed = 0
        for offset, (manifest_index, candidate) in enumerate(rows):
            candidate_id = str(candidate.get("candidate_id") or "")
            if candidate_id not in candidate_signals:
                continue
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:xss_browser_proof:{candidate_id}".encode()
            ).hexdigest()
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                observations.extend(prior.get("observations") or ())
                for name, amount in dict(prior.get("budget_consumed") or {}).items():
                    consumed[name] = consumed.get(name, 0) + int(amount)
                continue
            if self.cancelled():
                break
            execution_url = execution_url_for_manifest_candidate(
                endpoints, manifest, manifest_index,
            )
            remaining_attempts = max(1, len(rows) - offset)
            remaining = {
                name: max(0, int(limit) - int(consumed.get(name, 0)))
                for name, limit in action.requested_budget.items()
            }
            sub_budget = {
                name: amount // remaining_attempts
                for name, amount in remaining.items() if amount // remaining_attempts > 0
            }
            if sub_budget.get("browser_actions", 0) < 2:
                break
            adapter = XSSBrowserProofAdapter(XSSBrowserProofAdapter.prepare(
                target=self.target, execution_url=execution_url,
                candidate_id=candidate_id,
                parameter_name=str(candidate.get("parameter_name") or ""),
            ))
            specification = CAPABILITY_REGISTRY.require(action.capability_name)
            result = await CapabilityExecutor().execute(
                CapabilityExecutionContext(
                    specification=specification, target=self.target,
                    requested_budget=sub_budget, adapter_managed_cancellation=True,
                ),
                adapter, heartbeat=heartbeat, cancelled=self.cancelled,
            )
            attempt_observations = tuple({
                **dict(item), "attempt_id": attempt_id, "candidate_id": candidate_id,
            } for item in result.observations)
            proof_state = next((
                str(item.get("proof_state")) for item in attempt_observations
                if item.get("proof_state")
            ), "not_proven")
            bundled = ({
                "kind": "candidate_attempt", "attempt_id": attempt_id,
                "candidate_id": candidate_id, "family": "xss_browser_proof",
                "status": result.status, "proof_state": proof_state,
                "budget_consumed": dict(result.actual_budget),
            }, *attempt_observations)
            attempt = {
                "attempt_id": attempt_id, "candidate_id": candidate_id,
                "status": result.status, "budget_consumed": dict(result.actual_budget),
                "observations": bundled, "errors": tuple(result.errors),
                "proof_state": proof_state,
            }
            if result.status != "cancelled":
                await checkpoint_attempt(action.action_id, attempt)
            attempted += 1
            observations.extend(bundled)
            errors.extend(str(item) for item in result.errors)
            for name, amount in result.actual_budget.items():
                consumed[name] = min(
                    int(action.requested_budget.get(name, 0)),
                    consumed.get(name, 0) + int(amount),
                )
        eligible = sum(
            str(candidate.get("candidate_id") or "") in candidate_signals
            for _index, candidate in rows
        )
        unattempted = max(0, eligible - attempted)
        return self._receipt(
            action, status="partial" if unattempted else "success",
            parser_version=CAPABILITY_REGISTRY.require(action.capability_name).output_schema,
            started_at=started_at, observations=tuple(observations),
            errors=tuple(errors[:20]), consumed=consumed,
            partial=bool(unattempted), timed_out=False,
            redacted_execution={
                "action_id": action.action_id, "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "eligible_count": eligible, "attempted_count": attempted,
                "resumed_count": resumed, "unattempted_count": unattempted,
                "checkpoint_mode": "after_each_candidate",
                "secret_values_visible": False,
            },
        )

    async def _sqli_proof_batch(
        self, action: ScanAction, heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        """Reproduce verifier candidates under one strict deterministic proof contract."""
        request_mode = isinstance(
            action.capability_args.get("request_candidate_manifest_ref"), Mapping,
        )
        manifest = await self._work_manifest(
            action,
            "request_candidate_manifest_ref" if request_mode else "candidate_manifest_ref",
            ScanWorkManifestKind.REQUEST_CANDIDATE if request_mode else ScanWorkManifestKind.CANDIDATE,
        )
        endpoints = None if request_mode else await self._work_manifest(
            action, "endpoint_manifest_ref", ScanWorkManifestKind.ENDPOINT,
        )
        if manifest is None or (not request_mode and endpoints is None):
            return self._skip(action, "manifest_unavailable")
        raw_slice = action.capability_args.get("slice")
        if not isinstance(raw_slice, Mapping):
            raise ScanActionAdapterError("SQLi proof batch slice is invalid")
        start, count = raw_slice.get("start"), raw_slice.get("count")
        if (
            isinstance(start, bool) or not isinstance(start, int) or start < 0
            or isinstance(count, bool) or not isinstance(count, int)
            or not 1 <= count <= 50
        ):
            raise ScanActionAdapterError("SQLi proof batch slice is invalid")
        rows = tuple(enumerate(
            manifest.entries[start:min(len(manifest.entries), start + count)], start=start,
        ))
        if not rows:
            return self._skip(action, "not_applicable")
        candidate_signals: set[str] = set()
        for dependency in action.dependencies:
            for item in await self._observations(dependency):
                if (
                    str(item.get("kind") or "") in {
                        "sqli_finding", "request_body_verification", "candidate_attempt",
                    }
                    and str(item.get("candidate_id") or "")
                    and str(item.get("proof_state") or item.get("proof_status") or "")
                    not in {"not_proven", "unproven", ""}
                ):
                    candidate_signals.add(str(item["candidate_id"]))
        if not candidate_signals:
            return self._skip(action, "no_sqli_candidate_observation")
        load_attempts = getattr(self.backend, "load_batch_attempts", None)
        checkpoint_attempt = getattr(self.backend, "checkpoint_batch_attempt", None)
        if not callable(load_attempts) or not callable(checkpoint_attempt):
            raise ScanActionAdapterError("SQLi proof backend lacks durable checkpoints")
        completed = {
            str(item.get("attempt_id") or ""): dict(item)
            for item in await load_attempts(action.action_id)
            if isinstance(item, Mapping)
        }
        manifest_digest = manifest.reference().manifest_digest
        started_at = datetime.now(timezone.utc).isoformat()
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        consumed = {name: 0 for name in action.requested_budget}
        attempted = resumed = 0
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=action.capability_name,
        )
        for offset, (manifest_index, candidate) in enumerate(rows):
            candidate_id = str(candidate.get("candidate_id") or "")
            if candidate_id not in candidate_signals:
                continue
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:sqli_proof:{candidate_id}".encode()
            ).hexdigest()
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                observations.extend(prior.get("observations") or ())
                for name, amount in dict(prior.get("budget_consumed") or {}).items():
                    consumed[name] = consumed.get(name, 0) + int(amount)
                continue
            if self.cancelled():
                break
            request_class = str(candidate.get("request_class") or "safe_read")
            if request_mode:
                request = self._private_requests.get(str(candidate.get("request_ref_id") or ""))
                if request is None:
                    continue
                if (
                    request_class == "confirmed_mutation"
                    and not (
                        self.policy.allow_state_changing_http
                        and self.policy.approval_receipt_id
                    )
                ):
                    continue
            else:
                execution_url = execution_url_for_manifest_candidate(
                    endpoints, manifest, manifest_index,
                )
                request = ReplayRequest(
                    request_id=f"candidate:{candidate_id}",
                    ordinal=manifest_index,
                    name="canonical SQLi candidate",
                    folder="",
                    method=str(candidate.get("method") or "GET"),
                    url=execution_url,
                    headers=tuple(primary.headers().items()),
                    body=b"",
                    body_mode="none",
                    auth_type="broker_session" if primary.authenticated else "none",
                    has_sensitive_material=primary.authenticated,
                )
            remaining_attempts = max(1, len(rows) - offset)
            remaining = {
                name: max(0, int(limit) - int(consumed.get(name, 0)))
                for name, limit in action.requested_budget.items()
            }
            sub_budget = {
                name: amount // remaining_attempts
                for name, amount in remaining.items() if amount // remaining_attempts > 0
            }
            if sub_budget.get("http_requests", 0) < 4:
                break
            specification = CAPABILITY_REGISTRY.require(action.capability_name)
            adapter = SQLiProofAdapter(
                specification=specification,
                target=self.target,
                request=request,
                candidate=candidate,
                transport=PinnedAiohttpReplayTransport(),
                requested_budget=sub_budget,
            )
            result = await CapabilityExecutor().execute(
                CapabilityExecutionContext(
                    specification=specification,
                    target=self.target,
                    requested_budget=sub_budget,
                    adapter_managed_cancellation=True,
                ),
                adapter, heartbeat=heartbeat, cancelled=self.cancelled,
            )
            attempt_observations = tuple({
                **dict(item), "attempt_id": attempt_id, "candidate_id": candidate_id,
            } for item in result.observations)
            proof_state = next((
                str(item.get("proof_state")) for item in attempt_observations
                if item.get("proof_state")
            ), "not_proven")
            bundled = ({
                "kind": "candidate_attempt",
                "attempt_id": attempt_id,
                "candidate_id": candidate_id,
                "family": "sqli_proof",
                "status": result.status,
                "proof_state": proof_state,
                "budget_consumed": dict(result.actual_budget),
            }, *attempt_observations)
            attempt = {
                "attempt_id": attempt_id, "candidate_id": candidate_id,
                "status": result.status, "budget_consumed": dict(result.actual_budget),
                "observations": bundled, "errors": tuple(result.errors),
                "proof_state": proof_state,
            }
            if result.status != "cancelled":
                await checkpoint_attempt(action.action_id, attempt)
            attempted += 1
            observations.extend(bundled)
            errors.extend(str(item) for item in result.errors)
            for name, amount in result.actual_budget.items():
                consumed[name] = min(
                    int(action.requested_budget.get(name, 0)),
                    consumed.get(name, 0) + int(amount),
                )
        eligible = sum(
            str(candidate.get("candidate_id") or "") in candidate_signals
            for _index, candidate in rows
        )
        unattempted = max(0, eligible - attempted)
        return self._receipt(
            action, status="partial" if unattempted else "success",
            parser_version=CAPABILITY_REGISTRY.require(action.capability_name).output_schema,
            started_at=started_at, observations=tuple(observations),
            errors=tuple(errors[:20]), consumed=consumed,
            partial=bool(unattempted), timed_out=False,
            redacted_execution={
                "action_id": action.action_id, "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "eligible_count": eligible, "attempted_count": attempted,
                "resumed_count": resumed, "unattempted_count": unattempted,
                "checkpoint_mode": "after_each_candidate",
                "secret_values_visible": False,
            },
        )

    def _exposure_origin(self) -> tuple[str, str] | None:
        """Return the (origin, scheme) for canonical-host seed probing."""
        for origin in self.target.allowed_origins:
            parsed = urllib.parse.urlsplit(str(origin))
            host = (parsed.hostname or "").lower().rstrip(".")
            if host and host == str(self.target.canonical_host or "").lower():
                return str(origin).rstrip("/"), parsed.scheme.lower()
        return None

    async def _exposure_probe_batch(
        self, action: ScanAction, heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        """Probe well-known sensitive locations and discovered endpoints for
        deterministic content disclosure, following bounded directory listings."""
        endpoints = await self._work_manifest(
            action, "endpoint_manifest_ref", ScanWorkManifestKind.ENDPOINT,
        )
        if endpoints is None:
            return self._skip(action, "manifest_unavailable")
        raw_slice = action.capability_args.get("slice")
        if not isinstance(raw_slice, Mapping):
            raise ScanActionAdapterError("exposure probe batch slice is invalid")
        start, count = raw_slice.get("start"), raw_slice.get("count")
        if (
            isinstance(start, bool) or not isinstance(start, int) or start < 0
            or isinstance(count, bool) or not isinstance(count, int)
            or not 1 <= count <= 100
        ):
            raise ScanActionAdapterError("exposure probe batch slice is invalid")
        origin = self._exposure_origin()
        if origin is None:
            return self._skip(action, "no_canonical_origin")
        base_origin, _scheme = origin
        load_attempts = getattr(self.backend, "load_batch_attempts", None)
        checkpoint_attempt = getattr(self.backend, "checkpoint_batch_attempt", None)
        if not callable(load_attempts) or not callable(checkpoint_attempt):
            raise ScanActionAdapterError("exposure probe backend lacks durable checkpoints")
        completed = {
            str(item.get("attempt_id") or ""): dict(item)
            for item in await load_attempts(action.action_id)
            if isinstance(item, Mapping)
        }
        manifest_digest = endpoints.reference().manifest_digest

        # The seed wordlist is probed once, in the first slice; later slices scan
        # their own endpoint window for accidental disclosure signatures.
        probes: list[tuple[str, str]] = []
        if start == 0:
            probes.extend(
                (f"{base_origin}{path}", "seed_path") for path in SENSITIVE_SEED_PATHS
            )
        window = endpoints.entries[start:min(len(endpoints.entries), start + count)]
        for entry in window:
            try:
                probes.append((execution_url_for_endpoint(entry), "discovered_endpoint"))
            except (ScanWorkManifestError, KeyError):
                continue

        transport = PinnedAiohttpReplayTransport()
        started_at = datetime.now(timezone.utc).isoformat()
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        consumed = {name: 0 for name in action.requested_budget}
        http_ceiling = int(action.requested_budget.get("http_requests") or 0)
        wall_ceiling = max(1, int(action.requested_budget.get("tool_wall_seconds") or 1))
        attempted = resumed = 0

        async def probe(url: str, ordinal: int) -> Any:
            nonlocal consumed
            request = ReplayRequest(
                request_id=f"exposure:{ordinal}", ordinal=ordinal,
                name="exposure probe", folder="", method="GET", url=url,
                headers=(), body=b"", body_mode="none",
                auth_type="none", has_sensitive_material=False,
            )
            remaining = max(1, http_ceiling - consumed["http_requests"])
            result = await transport.send(
                request, target=self.target,
                timeout_seconds=max(0.5, min(15.0, wall_ceiling / remaining)),
                follow_redirects=False,
            )
            consumed["http_requests"] = min(
                http_ceiling, consumed["http_requests"] + 1,
            )
            await heartbeat()
            return result

        ordinal = start * 1000
        for probe_url, discovered_via in probes:
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:exposure:{probe_url}".encode()
            ).hexdigest()
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                observations.extend(prior.get("observations") or ())
                continue
            if self.cancelled() or consumed["http_requests"] >= http_ceiling:
                break
            ordinal += 1
            result = await probe(probe_url, ordinal)
            if result.error_code:
                errors.append(str(result.error_code))
            signature = classify_exposure(
                path=probe_url, status=result.status_code or 0,
                headers=result.response_headers, body=result.response_body,
            )
            attempt_observations: list[Mapping[str, Any]] = []
            if signature is not None:
                attempt_observations.append(_exposure_observation(
                    probe_url, discovered_via, signature, result,
                ))
                # A browsable directory is proof its listed files are reachable;
                # follow a bounded set to surface the confidential content itself.
                if (
                    signature.exposure_class == "directory_listing"
                    and consumed["http_requests"] < http_ceiling
                ):
                    for link in directory_listing_links(result.response_body, limit=10):
                        if self.cancelled() or consumed["http_requests"] >= http_ceiling:
                            break
                        child_url = urllib.parse.urljoin(probe_url.rstrip("/") + "/", link)
                        if urllib.parse.urlsplit(child_url).netloc != \
                                urllib.parse.urlsplit(probe_url).netloc:
                            continue
                        ordinal += 1
                        child = await probe(child_url, ordinal)
                        child_signature = classify_confidential_file(
                            status=child.status_code or 0,
                            headers=child.response_headers, body=child.response_body,
                        )
                        if child_signature is not None:
                            attempt_observations.append(_exposure_observation(
                                child_url, "directory_listing_follow",
                                child_signature, child,
                            ))
            bundled = ({
                "kind": "candidate_attempt", "attempt_id": attempt_id,
                "candidate_id": attempt_id[:32], "family": "sensitive_exposure",
                "status": "success", "proof_state": (
                    "verified" if attempt_observations else "not_proven"
                ),
                "budget_consumed": {"http_requests": 1},
            }, *attempt_observations)
            attempt = {
                "attempt_id": attempt_id, "candidate_id": attempt_id[:32],
                "status": "success", "budget_consumed": {"http_requests": 1},
                "observations": bundled,
                "proof_state": "verified" if attempt_observations else "not_proven",
            }
            if not self.cancelled():
                await checkpoint_attempt(action.action_id, attempt)
            attempted += 1
            observations.extend(bundled)
        unattempted = max(0, len(probes) - attempted)
        consumed["tool_wall_seconds"] = min(
            wall_ceiling, max(1, len(probes)),
        ) if "tool_wall_seconds" in consumed else consumed.get("tool_wall_seconds", 0)
        return self._receipt(
            action, status="partial" if unattempted else "success",
            parser_version=EXPOSURE_PROBE_PARSER_VERSION,
            started_at=started_at, observations=tuple(observations),
            errors=tuple(errors[:20]), consumed=consumed,
            partial=bool(unattempted), timed_out=False,
            redacted_execution={
                "action_id": action.action_id, "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "probe_count": len(probes), "attempted_count": attempted,
                "resumed_count": resumed, "unattempted_count": unattempted,
                "checkpoint_mode": "after_each_candidate",
                "secret_values_visible": False,
            },
        )

    async def _nosqli_verify_batch(
        self, action: ScanAction, heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        """First-order NoSQL operator-injection differential over one slice."""
        request_mode = isinstance(
            action.capability_args.get("request_candidate_manifest_ref"), Mapping,
        )
        manifest = await self._work_manifest(
            action,
            "request_candidate_manifest_ref" if request_mode else "candidate_manifest_ref",
            ScanWorkManifestKind.REQUEST_CANDIDATE if request_mode else ScanWorkManifestKind.CANDIDATE,
        )
        endpoints = None if request_mode else await self._work_manifest(
            action, "endpoint_manifest_ref", ScanWorkManifestKind.ENDPOINT,
        )
        if manifest is None or (not request_mode and endpoints is None):
            return self._skip(action, "manifest_unavailable")
        raw_slice = action.capability_args.get("slice")
        if not isinstance(raw_slice, Mapping):
            raise ScanActionAdapterError("NoSQLi verify batch slice is invalid")
        start, count = raw_slice.get("start"), raw_slice.get("count")
        if (
            isinstance(start, bool) or not isinstance(start, int) or start < 0
            or isinstance(count, bool) or not isinstance(count, int)
            or not 1 <= count <= 50
        ):
            raise ScanActionAdapterError("NoSQLi verify batch slice is invalid")
        rows = tuple(enumerate(
            manifest.entries[start:min(len(manifest.entries), start + count)], start=start,
        ))
        if not rows:
            return self._skip(action, "not_applicable")
        load_attempts = getattr(self.backend, "load_batch_attempts", None)
        checkpoint_attempt = getattr(self.backend, "checkpoint_batch_attempt", None)
        if not callable(load_attempts) or not callable(checkpoint_attempt):
            raise ScanActionAdapterError("NoSQLi verify backend lacks durable checkpoints")
        completed = {
            str(item.get("attempt_id") or ""): dict(item)
            for item in await load_attempts(action.action_id)
            if isinstance(item, Mapping)
        }
        manifest_digest = manifest.reference().manifest_digest
        started_at = datetime.now(timezone.utc).isoformat()
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        consumed = {name: 0 for name in action.requested_budget}
        attempted = resumed = 0
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=action.capability_name,
        )
        for offset, (manifest_index, candidate) in enumerate(rows):
            candidate_id = str(candidate.get("candidate_id") or "")
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:nosqli:{candidate_id}".encode()
            ).hexdigest()
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                observations.extend(prior.get("observations") or ())
                for name, amount in dict(prior.get("budget_consumed") or {}).items():
                    consumed[name] = consumed.get(name, 0) + int(amount)
                continue
            if self.cancelled():
                break
            request_class = str(candidate.get("request_class") or "safe_read")
            if request_mode:
                request = self._private_requests.get(str(candidate.get("request_ref_id") or ""))
                if request is None:
                    continue
                if (
                    request_class == "confirmed_mutation"
                    and not (
                        self.policy.allow_state_changing_http
                        and self.policy.approval_receipt_id
                    )
                ):
                    continue
            else:
                execution_url = execution_url_for_manifest_candidate(
                    endpoints, manifest, manifest_index,
                )
                request = ReplayRequest(
                    request_id=f"candidate:{candidate_id}",
                    ordinal=manifest_index,
                    name="canonical NoSQLi candidate",
                    folder="",
                    method=str(candidate.get("method") or "GET"),
                    url=execution_url,
                    headers=tuple(primary.headers().items()),
                    body=b"",
                    body_mode="none",
                    auth_type="broker_session" if primary.authenticated else "none",
                    has_sensitive_material=primary.authenticated,
                )
            remaining_attempts = max(1, len(rows) - offset)
            remaining = {
                name: max(0, int(limit) - int(consumed.get(name, 0)))
                for name, limit in action.requested_budget.items()
            }
            sub_budget = {
                name: amount // remaining_attempts
                for name, amount in remaining.items() if amount // remaining_attempts > 0
            }
            if sub_budget.get("http_requests", 0) < 4:
                break
            specification = CAPABILITY_REGISTRY.require(action.capability_name)
            adapter = NoSQLiVerifyAdapter(
                specification=specification,
                target=self.target,
                request=request,
                candidate=candidate,
                transport=PinnedAiohttpReplayTransport(),
                requested_budget=sub_budget,
            )
            result = await CapabilityExecutor().execute(
                CapabilityExecutionContext(
                    specification=specification,
                    target=self.target,
                    requested_budget=sub_budget,
                    adapter_managed_cancellation=True,
                ),
                adapter, heartbeat=heartbeat, cancelled=self.cancelled,
            )
            attempt_observations = tuple({
                **dict(item), "attempt_id": attempt_id, "candidate_id": candidate_id,
            } for item in result.observations)
            proof_state = next((
                str(item.get("proof_state")) for item in attempt_observations
                if item.get("proof_state")
            ), "not_proven")
            bundled = ({
                "kind": "candidate_attempt",
                "attempt_id": attempt_id,
                "candidate_id": candidate_id,
                "family": "nosqli",
                "status": result.status,
                "proof_state": proof_state,
                "budget_consumed": dict(result.actual_budget),
            }, *attempt_observations)
            attempt = {
                "attempt_id": attempt_id, "candidate_id": candidate_id,
                "status": result.status, "budget_consumed": dict(result.actual_budget),
                "observations": bundled, "errors": tuple(result.errors),
                "proof_state": proof_state,
            }
            if result.status != "cancelled":
                await checkpoint_attempt(action.action_id, attempt)
            attempted += 1
            observations.extend(bundled)
            errors.extend(str(item) for item in result.errors)
            for name, amount in result.actual_budget.items():
                consumed[name] = min(
                    int(action.requested_budget.get(name, 0)),
                    consumed.get(name, 0) + int(amount),
                )
        unattempted = max(0, len(rows) - attempted)
        return self._receipt(
            action, status="partial" if unattempted else "success",
            parser_version=CAPABILITY_REGISTRY.require(action.capability_name).output_schema,
            started_at=started_at, observations=tuple(observations),
            errors=tuple(errors[:20]), consumed=consumed,
            partial=bool(unattempted), timed_out=False,
            redacted_execution={
                "action_id": action.action_id, "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "candidate_count": len(rows), "attempted_count": attempted,
                "resumed_count": resumed, "unattempted_count": unattempted,
                "checkpoint_mode": "after_each_candidate",
                "secret_values_visible": False,
            },
        )

    async def _external(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        tool_by_capability = {
            "web.probe": "httpx",
            "web.crawl": "katana",
            "web.content_discover": "ffuf",
            "templates.scan": "nuclei",
            "templates.passive_scan": "nuclei",
            "xss.verify": "dalfox",
            "sqli.verify": "sqlmap",
        }
        tool = tool_by_capability[action.capability_name]
        execution_target = self.target_url
        if action.capability_name in {
            "templates.scan", "templates.passive_scan",
        }:
            manifest_endpoint = await self._manifest_endpoint(action)
            if (
                isinstance(action.capability_args.get("target_manifest_ref"), Mapping)
                and manifest_endpoint is None
            ):
                return self._skip(action, "not_applicable")
            execution_target = manifest_endpoint or execution_target
        if action.capability_name in {"xss.verify", "sqli.verify"}:
            manifest_candidate = await self._manifest_candidate(action)
            if isinstance(
                action.capability_args.get("candidate_manifest_ref"), Mapping,
            ):
                if manifest_candidate is None:
                    return self._skip(action, "not_applicable")
                execution_target = manifest_candidate
            else:
                crawl = await self._observations("discover.web_crawl")
                candidates = scan_parameterized_execution_candidates(
                    self.target_url,
                    target=self.target,
                    options=self.options,
                    crawl_observations=crawl,
                )
                if not candidates:
                    return self._skip(action, "not_applicable")
                execution_target = candidates[0]
        parsed = urllib.parse.urlsplit(execution_target)
        registered_target = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, "", "", "")
        )
        socket_factory = FrozenTargetSocketFactory(
            hostname=str(parsed.hostname or self.target.canonical_host),
            port=parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
            frozen_addresses=self.target.allowed_addresses,
        )
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=action.capability_name,
        )
        args: dict[str, Any] = dict(primary.capability_args())
        scanner_options: dict[str, Any] = {}
        if tool == "nuclei":
            template_manifest = await self._work_manifest(
                action, "template_manifest_ref", ScanWorkManifestKind.TEMPLATE,
            )
            if template_manifest is None:
                raise ScanActionAdapterError(
                    "Nuclei action has no immutable template manifest"
                )
            try:
                template_options = canonical_nuclei_options_for_manifest(
                    template_manifest, action_id=action.action_id,
                )
            except ScanWorkManifestError as exc:
                raise ScanActionAdapterError(str(exc)) from exc
            args.update(template_options)
            scanner_options.update(template_options)
        if tool == "ffuf":
            args["wordlist"] = "common"
            scanner_options["wordlist"] = "common"
        if tool == "dalfox":
            args["severity"] = "high"
            scanner_options["severity"] = "high"
        spec = CAPABILITY_REGISTRY.require(action.capability_name)
        prepared = fit_prepared_scan_capability(
            prepare_scan_external_capability(
                specification=spec,
                target=self.target,
                args=args,
                policy=self.policy,
            ),
            ledger_limits=action.requested_budget,
        )
        candidate_digest = hashlib.sha256(execution_target.encode()).hexdigest()[:16]
        adapter = ScannerExecutionAdapter(
            specification=spec,
            process_payload={
                "job_id": f"{self.job_id}:{action.action_id}:{candidate_digest}",
                "tool_name": tool,
                "execution_target": execution_target,
                "registered_target": registered_target,
                "scanner_options": scanner_options,
                "trusted_headers": primary.headers(),
                "timeout_ms": int(action.requested_budget.get("tool_wall_seconds") or 1) * 1_000,
                "pinned_address": socket_factory.primary_address,
                "authorized_addresses": list(self.target.allowed_addresses),
                "address_policy": socket_factory.policy_receipt,
                "oob_interactsh_server": None,
                "oob_interactsh_token": None,
            },
            process_runner=self.process_runner,
            requested_budget=action.requested_budget,
            redacted_execution=prepared.redacted_execution,
        )
        return await self._execute_adapter(
            action, adapter, heartbeat, managed_cancellation=True,
        )

    async def _external_batch(
        self, action: ScanAction, heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        """Run a resumable ranked manifest slice under one durable reservation."""
        batch_contracts = {
            "xss.verify_batch": ("xss.verify", "dalfox", ScanWorkManifestKind.CANDIDATE),
            "sqli.verify_batch": ("sqli.verify", "sqlmap", ScanWorkManifestKind.CANDIDATE),
            "templates.passive_batch": (
                "templates.passive_scan", "nuclei", ScanWorkManifestKind.ENDPOINT,
            ),
            "templates.active_batch": (
                "templates.scan", "nuclei", ScanWorkManifestKind.ENDPOINT,
            ),
        }
        legacy_capability, tool, manifest_kind = batch_contracts[action.capability_name]
        manifest_argument = (
            "candidate_manifest_ref"
            if manifest_kind is ScanWorkManifestKind.CANDIDATE
            else "target_manifest_ref"
        )
        manifest = await self._work_manifest(action, manifest_argument, manifest_kind)
        endpoints = (
            await self._work_manifest(
                action, "endpoint_manifest_ref", ScanWorkManifestKind.ENDPOINT,
            )
            if manifest_kind is ScanWorkManifestKind.CANDIDATE else manifest
        )
        if manifest is None or endpoints is None:
            return self._skip(action, "manifest_unavailable")
        raw_slice = action.capability_args.get("slice")
        if not isinstance(raw_slice, Mapping):
            raise ScanActionAdapterError("batch action slice is invalid")
        start = raw_slice.get("start")
        count = raw_slice.get("count")
        if (
            isinstance(start, bool) or not isinstance(start, int) or start < 0
            or isinstance(count, bool) or not isinstance(count, int)
            or not 1 <= count <= 50
        ):
            raise ScanActionAdapterError("batch action slice is invalid")
        stop = min(len(manifest.entries), start + count)
        rows = tuple(enumerate(manifest.entries[start:stop], start=start))
        if not rows:
            return self._skip(action, "not_applicable")
        template_options: dict[str, Any] = {}
        if tool == "nuclei":
            template_manifest = await self._work_manifest(
                action, "template_manifest_ref", ScanWorkManifestKind.TEMPLATE,
            )
            if template_manifest is None:
                raise ScanActionAdapterError(
                    "Nuclei batch has no immutable template manifest"
                )
            try:
                template_options = canonical_nuclei_options_for_manifest(
                    template_manifest, action_id=action.action_id,
                )
            except ScanWorkManifestError as exc:
                raise ScanActionAdapterError(str(exc)) from exc
        load_attempts = getattr(self.backend, "load_batch_attempts", None)
        checkpoint_attempt = getattr(self.backend, "checkpoint_batch_attempt", None)
        if not callable(load_attempts) or not callable(checkpoint_attempt):
            raise ScanActionAdapterError(
                "batch action backend has no durable attempt checkpoint contract"
            )
        completed = {
            str(item.get("attempt_id") or ""): dict(item)
            for item in await load_attempts(action.action_id)
            if isinstance(item, Mapping)
        }
        manifest_digest = manifest.reference().manifest_digest
        family = {
            "xss.verify_batch": "xss",
            "sqli.verify_batch": "sqli",
            "templates.passive_batch": "nuclei_passive",
            "templates.active_batch": "nuclei_active",
        }[action.capability_name]
        started_at = datetime.now(timezone.utc).isoformat()
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        consumed = {name: 0 for name in action.requested_budget}
        attempted = 0
        resumed = 0
        terminal_failure = False
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=legacy_capability,
        )
        for offset, (manifest_index, row) in enumerate(rows):
            candidate_id = str(
                row.get("candidate_id") or row.get("route_id")
                or hashlib.sha256(str(manifest_index).encode()).hexdigest()
            )
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:{family}:{candidate_id}".encode()
            ).hexdigest()
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                observations.extend(prior.get("observations") or ())
                for name, amount in dict(prior.get("budget_consumed") or {}).items():
                    consumed[name] = consumed.get(name, 0) + int(amount)
                continue
            if self.cancelled():
                break
            if manifest_kind is ScanWorkManifestKind.CANDIDATE:
                execution_target = execution_url_for_manifest_candidate(
                    endpoints, manifest, manifest_index,
                )
            else:
                execution_target = execution_url_for_manifest_endpoint(
                    manifest, manifest_index,
                )
            remaining_attempts = max(1, len(rows) - offset)
            remaining_budget = {
                name: max(0, int(limit) - int(consumed.get(name, 0)))
                for name, limit in action.requested_budget.items()
            }
            sub_budget = {
                name: max(1, amount // remaining_attempts)
                for name, amount in remaining_budget.items() if amount > 0
            }
            if not sub_budget.get("http_requests") or not sub_budget.get("tool_wall_seconds"):
                break
            parsed = urllib.parse.urlsplit(execution_target)
            registered_target = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, "", "", "")
            )
            socket_factory = FrozenTargetSocketFactory(
                hostname=str(parsed.hostname or self.target.canonical_host),
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                frozen_addresses=self.target.allowed_addresses,
            )
            scanner_options = {"_batch_attempt": True}
            args = dict(primary.capability_args())
            if tool == "nuclei":
                scanner_options.update(template_options)
                args.update(template_options)
            elif tool == "dalfox":
                scanner_options["severity"] = "high"
                args["severity"] = "high"
            legacy_spec = CAPABILITY_REGISTRY.require(legacy_capability)
            prepared = fit_prepared_scan_capability(
                prepare_scan_external_capability(
                    specification=legacy_spec,
                    target=self.target,
                    args=args,
                    policy=self.policy,
                ),
                ledger_limits=sub_budget,
            )
            adapter = ScannerExecutionAdapter(
                specification=legacy_spec,
                process_payload={
                    "job_id": f"{self.job_id}:{action.action_id}:{attempt_id[:16]}",
                    "tool_name": tool,
                    "execution_target": execution_target,
                    "registered_target": registered_target,
                    "scanner_options": scanner_options,
                    "trusted_headers": primary.headers(),
                    "timeout_ms": int(sub_budget["tool_wall_seconds"]) * 1_000,
                    "pinned_address": socket_factory.primary_address,
                    "authorized_addresses": list(self.target.allowed_addresses),
                    "address_policy": socket_factory.policy_receipt,
                    "oob_interactsh_server": None,
                    "oob_interactsh_token": None,
                },
                process_runner=self.process_runner,
                requested_budget=sub_budget,
                redacted_execution=prepared.redacted_execution,
            )
            result = await CapabilityExecutor().execute(
                CapabilityExecutionContext(
                    specification=legacy_spec,
                    target=self.target,
                    requested_budget=sub_budget,
                    adapter_managed_cancellation=True,
                ),
                adapter,
                heartbeat=heartbeat,
                cancelled=self.cancelled,
            )
            attempt_observations = tuple({
                **dict(item),
                "attempt_id": attempt_id,
                "candidate_id": candidate_id,
            } for item in result.observations)
            proof_state = next((
                str(item.get("proof_state"))
                for item in attempt_observations if item.get("proof_state")
            ), "unproven")
            response_hashes = sorted({
                str(value)
                for item in attempt_observations
                for key, value in item.items()
                if "sha256" in str(key).lower() and str(value)
            })[:20]
            attempt_observations = (
                {
                    "kind": "candidate_attempt",
                    "attempt_id": attempt_id,
                    "candidate_id": candidate_id,
                    "family": family,
                    "status": result.status,
                    "proof_state": proof_state,
                    "response_hashes": response_hashes,
                    "budget_consumed": dict(result.actual_budget),
                },
                *attempt_observations,
            )
            attempt = {
                "attempt_id": attempt_id,
                "candidate_id": candidate_id,
                "status": result.status,
                "budget_consumed": dict(result.actual_budget),
                "observations": attempt_observations,
                "errors": tuple(result.errors),
                "proof_state": proof_state,
            }
            if result.status != "cancelled":
                await checkpoint_attempt(action.action_id, attempt)
            attempted += 1
            observations.extend(attempt_observations)
            errors.extend(str(item) for item in result.errors)
            for name, amount in result.actual_budget.items():
                consumed[name] = min(
                    int(action.requested_budget.get(name, 0)),
                    consumed.get(name, 0) + int(amount),
                )
            if result.status in {"failed", "timed_out"}:
                terminal_failure = True
            if result.status == "cancelled":
                break
        unattempted = max(0, len(rows) - attempted)
        partial = unattempted > 0 or terminal_failure
        return self._receipt(
            action,
            status="partial" if partial else "success",
            parser_version=CAPABILITY_REGISTRY.require(action.capability_name).output_schema,
            started_at=started_at,
            observations=tuple(observations),
            errors=tuple(errors[:20]),
            consumed=consumed,
            partial=partial,
            timed_out=False,
            redacted_execution={
                "action_id": action.action_id,
                "profile": action.capability_args.get("profile"),
                "proof_policy": action.capability_args.get("proof_policy"),
                "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "candidate_count": len(rows),
                "attempted_count": attempted,
                "resumed_count": resumed,
                "unattempted_count": unattempted,
                "checkpoint_mode": "after_each_candidate",
            },
        )

    async def _authz(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=action.capability_name,
        )
        secondary = resolve_scan_http_principal(
            self.options, lane="secondary", capability_name=action.capability_name,
        )
        if not primary.authenticated or not secondary.authenticated:
            return self._skip(action, "not_applicable")
        endpoint_manifest = await self._work_manifest(
            action, "endpoint_manifest_ref", ScanWorkManifestKind.ENDPOINT,
        )
        if endpoint_manifest is None:
            return self._skip(action, "manifest_unavailable")
        routes = list(execution_routes_for_endpoint_manifest(endpoint_manifest))
        if not routes:
            return self._skip(action, "not_applicable")
        args = {
            "primary_binding_digest": str(primary.binding_digest),
            "secondary_binding_digest": str(secondary.binding_digest),
            "route_inventory_digest": authz_route_inventory_digest(routes),
            "route_count": len(routes),
        }

        async def operation() -> Mapping[str, Any]:
            return await verify_target_bound_object_authorization(
                self.target_url,
                routes,
                target=self.target,
                primary_headers=primary.headers(),
                secondary_headers=secondary.headers(),
            )

        adapter = self._prepared_inline(
            action, args, operation, AuthzVerificationExecutionAdapter,
        )
        return await self._execute_adapter(action, adapter, heartbeat)

    async def _finalize(self, action: ScanAction) -> CapabilityReceipt:
        self._private_replay_plans.clear()
        self._private_requests.clear()
        results = {}
        observations = {}
        for planned in self.plan.actions:
            if planned.action_id == action.action_id:
                continue
            stored = await self.backend.load_result(planned.action_id)
            if stored is None:
                raise ScanActionAdapterError("finalization dependency is not terminal")
            results[planned.action_id] = stored
            observations[planned.action_id] = await self._observations(planned.action_id)
        report = finalize_scan_report(
            plan=self.plan,
            plan_revision=self.plan_revision,
            target_url=self.target_url,
            action_results=results,
            observations=observations,
            work_manifest_references=unique_work_manifest_reference_dicts(
                planned.capability_args for planned in self.plan.actions
            ),
        )
        now = datetime.now(timezone.utc).isoformat()
        return self._receipt(
            action,
            status="success",
            parser_version="pure-receipt-finalizer/v1",
            started_at=now,
            observations=({"kind": "scan_report", "report": report},),
            redacted_execution={
                "action_id": action.action_id,
                "target_traffic": False,
                "plan_digest": self.plan.plan_digest,
            },
        )

    async def __call__(
        self,
        action: ScanAction,
        lease: ActionLease,
        heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        if lease.worker_id != self.worker_id:
            raise ScanActionAdapterError("action lease belongs to another worker")
        if action.action_id == "finalize.report":
            return await self._finalize(action)
        if action.action_id in {"inputs.auth_primary", "inputs.auth_secondary"}:
            return await self._auth_session(action, heartbeat)
        if action.action_id.startswith("inputs.collection_"):
            return await self._collection_replay(action, heartbeat)
        if action.capability_name == "http.request":
            return await self._http(action, heartbeat)
        if action.capability_name == "dns.inspect":
            return await self._dns(action, heartbeat)
        if action.capability_name == "tls.inspect":
            return await self._tls(action, heartbeat)
        if action.capability_name in {
            "ports.discover", "service.fingerprint", "subdomains.discover",
        }:
            return await self._network(action, heartbeat)
        if action.capability_name in {
            "web.probe", "web.crawl", "web.content_discover", "templates.scan",
            "templates.passive_scan",
            "xss.verify", "sqli.verify",
        }:
            return await self._external(action, heartbeat)
        if action.capability_name in {
            "xss.verify_batch", "sqli.verify_batch",
            "templates.passive_batch", "templates.active_batch",
        }:
            return await self._external_batch(action, heartbeat)
        if action.capability_name in {
            "xss.request_verify", "sqli.request_verify",
        }:
            return await self._request_mutation(action, heartbeat)
        if action.capability_name in {
            "xss.request_verify_batch", "sqli.request_verify_batch",
        }:
            return await self._request_mutation_batch(action, heartbeat)
        if action.capability_name == "sqli.prove_batch":
            return await self._sqli_proof_batch(action, heartbeat)
        if action.capability_name == "xss.browser_prove_batch":
            return await self._xss_browser_proof_batch(action, heartbeat)
        if action.capability_name == "exposure.verify_batch":
            return await self._exposure_probe_batch(action, heartbeat)
        if action.capability_name == "nosqli.verify_batch":
            return await self._nosqli_verify_batch(action, heartbeat)
        if action.capability_name == "authz.verify":
            return await self._authz(action, heartbeat)
        raise ScanActionAdapterError(
            f"no database-neutral adapter exists for {action.action_id}"
        )


__all__ = ["DatabaseNeutralScanActionDispatcher", "ScanActionAdapterError"]

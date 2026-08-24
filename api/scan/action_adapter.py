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
    from capabilities.request_mutation import RequestMutationVerificationAdapter
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
    from ..capabilities.request_mutation import RequestMutationVerificationAdapter
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
    from scanner_tools.request_replay import bind_replay_credential_headers
except (ImportError, ModuleNotFoundError):
    from scanner.scanner_tools.common import run_streaming
    from scanner.scanner_tools.request_replay import bind_replay_credential_headers

from .action_plan import ScanAction, ScanActionPlan
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
    execution_url_for_manifest_candidate,
    execution_url_for_manifest_endpoint,
    execution_routes_for_endpoint_manifest,
    unique_work_manifest_reference_dicts,
)


ScannerProcessRunner = Callable[..., Awaitable[Mapping[str, Any]]]
Cancelled = Callable[[], bool]


class ObservationBackend(Protocol):
    async def load_result(self, action_id: str) -> Any: ...
    async def load_observations(
        self, action_id: str,
    ) -> tuple[Mapping[str, Any], ...]: ...
    async def load_work_manifest(
        self, action_id: str, reference: ScanWorkManifestReference,
    ) -> ScanWorkManifest: ...


class ScanActionAdapterError(RuntimeError):
    """One immutable action has no safe database-neutral adapter mapping."""


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
        backend: ObservationBackend,
        process_runner: ScannerProcessRunner,
        cancelled: Cancelled,
        private_inputs: BrokerPrivateScanInputs | None = None,
    ) -> None:
        if not isinstance(plan, ScanActionPlan) or target.digest != plan.target_binding_digest:
            raise ScanActionAdapterError("action dispatcher authority is inconsistent")
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
        self.backend = backend
        self.process_runner = process_runner
        self.cancelled = cancelled
        self._private_replay_plans = dict(
            private_inputs.replay_plans if private_inputs is not None else {}
        )
        # Exact request bodies become verifier inputs only after their replay
        # action actually succeeds.  Preloading them would let a dependent
        # verifier run after a failed or skipped collection action.
        self._private_requests: dict[str, Any] = {}

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
                self.options, lane=lane,
            )
            if credential is None:
                return True
            if resolve_scan_http_principal(
                self.options, lane=lane,
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
                )
                self.options = bind_scan_session_headers(
                    self.options, headers, lane=lane,
                )
            except (ScanPrivateStateError, ValueError, TypeError):
                return False
            return resolve_scan_http_principal(
                self.options, lane=lane,
            ).authenticated
        if action.action_id.startswith("inputs.collection_"):
            plan = self._private_replay_plans.get(action.action_id)
            if plan is None:
                return False
            principal = resolve_scan_http_principal(
                self.options, lane="primary",
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
        primary = resolve_scan_http_principal(self.options, lane="primary")

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
        credential = resolve_scan_interactive_credential(self.options, lane=lane)
        if credential is None:
            return self._skip(action, "not_applicable")

        async def operation() -> Mapping[str, Any]:
            session = await establish_target_bound_http_session(
                credential, target=self.target,
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
        plan = self._private_replay_plans.get(action.action_id)
        if plan is None:
            return self._skip(action, "private_request_unavailable")
        if any(
            int(action.requested_budget.get(name) or 0) < int(amount)
            for name, amount in plan.estimated_budget.items()
        ):
            raise ScanActionAdapterError(
                "private replay plan exceeds its immutable action reservation"
            )
        principal = resolve_scan_http_principal(self.options, lane="primary")
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
        primary = resolve_scan_http_principal(self.options, lane="primary")
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
                "pinned_address": self.target.allowed_addresses[0],
                "authorized_addresses": list(self.target.allowed_addresses),
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

    async def _authz(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        primary = resolve_scan_http_principal(self.options, lane="primary")
        secondary = resolve_scan_http_principal(self.options, lane="secondary")
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
            "xss.request_verify", "sqli.request_verify",
        }:
            return await self._request_mutation(action, heartbeat)
        if action.capability_name == "authz.verify":
            return await self._authz(action, heartbeat)
        raise ScanActionAdapterError(
            f"no database-neutral adapter exists for {action.action_id}"
        )


__all__ = ["DatabaseNeutralScanActionDispatcher", "ScanActionAdapterError"]

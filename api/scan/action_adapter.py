"""Database-neutral execution of immutable Scan actions.

The same adapter boundary can run behind a local PostgreSQL backend or an
outbound-only broker backend.  Durable leasing and settlement stay outside this
module; it performs only the target-bound operation authorized by one action.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import functools
import hashlib
from typing import Any, Awaitable, Callable, Iterable, Mapping, Protocol, Sequence
import json
import math
import statistics
import time
import urllib.parse

try:
    import agent_tools
    from capabilities.auth import establish_target_bound_http_session
    from capabilities.authz import (
        authz_route_inventory_digest,
        verify_target_bound_object_authorization,
    )
    from capabilities.dns import inspect_dns_posture
    from capabilities.infrastructure import inspect_infrastructure_intelligence
    from capabilities.http import execute_bound_http_request
    from capabilities.replay import RecordedReplayTransport
    from capabilities.inline import (
        AuthSessionExecutionAdapter,
        AuthzVerificationExecutionAdapter,
        DnsInspectionExecutionAdapter,
        HttpRequestExecutionAdapter,
        InfrastructureInspectionExecutionAdapter,
        ScanOriginSelectionExecutionAdapter,
        TlsInspectionExecutionAdapter,
    )
    from capabilities.network import NetworkExecutionAdapter, network_capability_adapter
    from capabilities.browser import BrowserCapabilityInputError, XSSBrowserProofAdapter
    from capabilities.request_mutation import RequestMutationVerificationAdapter
    from capabilities.sqli_proof import SQLiProofAdapter, SQLiProofError
    from capabilities.nosqli_verify import NoSQLiVerifyAdapter
    from capabilities.authz_surface import (
        AUTHZ_SURFACE_PARSER_VERSION,
        PrincipalProbe,
        RouteComparison,
        bfla_finding,
        boundary_established,
    )
    from capabilities.hint_files import ingest_hint_documents, HINT_DISCOVERY_PATHS
    from capabilities.spec_ingest import ingest_spec_bodies, SPEC_DISCOVERY_PATHS
    from capabilities.exposure_probe import (
        DIRECTORY_FOLLOW_UP_FLOOR,
        EXPOSURE_PROBE_MIN_START_SECONDS,
        exposure_probe_timeout,
        SENSITIVE_SEED_PATHS,
        SOFT_404_CONTROL_COUNT,
        EXPOSURE_PROBE_PARSER_VERSION,
        is_never_requested,
        is_sensitive_exposure_class,
        classify_confidential_file,
        classify_exposure,
        directory_listing_links,
        redacted_exposure_excerpt,
    )
    from capabilities.secret_material import keyed_body_digest
    from capabilities.scanner import ScannerExecutionAdapter
    from capabilities.tls import inspect_tls_binding
    from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.models import TargetBinding
    from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
    from runtime.receipts import CapabilityReceipt
    from runtime.request_replay_executor import execute_replay_plan
    from runtime.request_shape import nested_json_body
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
    from ..capabilities.infrastructure import inspect_infrastructure_intelligence
    from ..capabilities.http import execute_bound_http_request
    from ..capabilities.replay import RecordedReplayTransport
    from ..capabilities.inline import (
        AuthSessionExecutionAdapter,
        AuthzVerificationExecutionAdapter,
        DnsInspectionExecutionAdapter,
        HttpRequestExecutionAdapter,
        InfrastructureInspectionExecutionAdapter,
        ScanOriginSelectionExecutionAdapter,
        TlsInspectionExecutionAdapter,
    )
    from ..capabilities.network import NetworkExecutionAdapter, network_capability_adapter
    from ..capabilities.browser import BrowserCapabilityInputError, XSSBrowserProofAdapter
    from ..capabilities.request_mutation import RequestMutationVerificationAdapter
    from ..capabilities.sqli_proof import SQLiProofAdapter, SQLiProofError
    from ..capabilities.nosqli_verify import NoSQLiVerifyAdapter
    from ..capabilities.authz_surface import (
        AUTHZ_SURFACE_PARSER_VERSION,
        PrincipalProbe,
        RouteComparison,
        bfla_finding,
        boundary_established,
    )
    from ..capabilities.hint_files import ingest_hint_documents, HINT_DISCOVERY_PATHS
    from ..capabilities.spec_ingest import ingest_spec_bodies, SPEC_DISCOVERY_PATHS
    from ..capabilities.exposure_probe import (
        DIRECTORY_FOLLOW_UP_FLOOR,
        EXPOSURE_PROBE_MIN_START_SECONDS,
        exposure_probe_timeout,
        SENSITIVE_SEED_PATHS,
        SOFT_404_CONTROL_COUNT,
        EXPOSURE_PROBE_PARSER_VERSION,
        is_never_requested,
        is_sensitive_exposure_class,
        classify_confidential_file,
        classify_exposure,
        directory_listing_links,
        redacted_exposure_excerpt,
    )
    from ..capabilities.secret_material import keyed_body_digest
    from ..capabilities.scanner import ScannerExecutionAdapter
    from ..capabilities.tls import inspect_tls_binding
    from ..hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
    from ..runtime.capability_registry import CAPABILITY_REGISTRY
    from ..runtime.models import TargetBinding
    from ..runtime.pinned_http_replay import PinnedAiohttpReplayTransport
    from ..runtime.receipts import CapabilityReceipt
    from ..runtime.request_replay_executor import execute_replay_plan
    from ..runtime.request_shape import nested_json_body
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
    from scanner_tools import http_archive_capture as _scan_capture
    from scanner_tools.common import run_streaming
    from scanner_tools.request_replay import (
        ReplayPlan,
        ReplayRequest,
        bind_replay_credential_headers,
    )
except (ImportError, ModuleNotFoundError):
    from scanner.scanner_tools import http_archive_capture as _scan_capture
    from scanner.scanner_tools.common import run_streaming
    from scanner.scanner_tools.request_replay import (
        ReplayPlan,
        ReplayRequest,
        bind_replay_credential_headers,
    )

from .action_plan import ScanAction, ScanActionPlan
from .sqli_concurrency import (
    CANDIDATE_CONCURRENCY_ARG,
    ELAPSED_DIMENSIONS,
    ConcurrentCandidates,
    RequestRateGate,
    slice_rate_ceiling,
)
from .sqli_stages import (
    budget_inconclusive_record,
    prior_resume,
    prior_stages,
    run_staged_sqli_attempt,
)
from .verification_extension import (
    EXTENDS_ARG,
    SCAN_WALL_SHARE_ARG,
    extension_lineage,
    lane_round_wall_ceiling,
)
from .batch_carry import (
    admission_template_source, carried_records, finished_attempts, proof_signal_sources,
)
from .capability_result import (
    BUDGET_EXHAUSTION_REASONS,
    CEILING_STOP_ERRORS,
    CapabilityResultReason,
    is_process_kill_error,
)
from .external_process import (
    BATCH_ATTEMPT_FLOORS,
    batch_attempt_floor,
    batch_row_cost_class,
    order_batch_rows_by_cost_class,
    template_attempt_wall,
    template_retry_wall,
)
from .continuation import (
    ScanContinuationError,
    ScanPlanRevision,
    root_scan_plan_revision,
)
from .capability_execution import (
    CANONICAL_SCAN_NETWORK_PORTS,
    SCAN_BASE_ORIGIN_CAPABILITIES,
    fit_prepared_scan_capability,
    prepare_scan_external_capability,
    prepare_scan_inline_capability,
    scan_external_execution_target,
    scan_parameterized_execution_candidates,
)
from .execution_backend import ActionHeartbeat, ActionLease
from .finalizer import _observed_url_key, finalize_scan_report
from .nuclei_execution import resolve_active_scan_nuclei_options
from .negative_control import negative_control_entries
from .nuclei_template_index import nuclei_templates_directory
from .private_inputs import BrokerPrivateScanInputs
from .work_manifests import (
    ScanWorkManifest,
    ScanWorkManifestError,
    ScanWorkManifestKind,
    ScanWorkManifestReference,
    canonical_nuclei_options_for_manifest,
    execution_url_for_endpoint,
    execution_request_for_manifest_candidate,
    execution_url_for_manifest_candidate,
    execution_url_for_manifest_endpoint,
    execution_routes_for_endpoint_manifest,
    unique_work_manifest_reference_dicts,
)


# These adapters actually bind resolved principal headers into target traffic. A
# content-free observation is added only after the action consumes HTTP budget, so
# reports can distinguish "credential configured" from "principal context exercised".
_PRIMARY_PRINCIPAL_CAPABILITIES = frozenset({
    "http.request", "collections.replay_safe", "collections.replay_active",
    "collections.replay_authentication",
    "web.probe", "web.crawl", "web.browser_crawl", "web.content_discover",
    "templates.scan", "templates.passive_scan", "templates.active_batch",
    "templates.passive_batch", "xss.verify", "xss.verify_batch",
    "xss.request_verify", "xss.request_verify_batch", "xss.browser_prove_batch",
    "sqli.verify", "sqli.verify_batch", "sqli.request_verify",
    "sqli.request_verify_batch", "sqli.prove_batch", "exposure.verify_batch",
    "nosqli.verify_batch", "authz_surface.verify_batch", "authz.verify",
    "web.spec_ingest",
})


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


# A body candidate cannot reach deterministic proof through a URL. `execution_url_for_
# manifest_candidate` requires the candidate's field to appear in the endpoint's
# `query_parameter_names`, and a body field appears in `body_field_names`, so every proof
# escalation raised "candidate identity conflicts with its endpoint manifest" before it
# executed. The engine could obtain a body signal and never turn it into the verified
# finding the signal exists to produce.
_BODY_PROOF_PLACEHOLDER = "shakerscan"


def _nested_proof_body(fields: Sequence[str]) -> dict[str, Any]:
    """Rebuild a JSON proof body from dotted/flattened field names.

    A proof body of literal flat keys would make the verifier's dotted-path mutator
    traverse a missing node and raise, and would send XSS/SQL proofs the wrong schema.
    The shared renderer also serves the continuation worklist and the discovery tools,
    so every path agrees on one shape.
    """
    return nested_json_body(fields, placeholder=_BODY_PROOF_PLACEHOLDER)


def _candidate_for_synthetic_proof(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Drop an exact-request claim when proof uses a reconstructed request.

    Endpoint candidates retain request references as ranking provenance, but the
    generic candidate lane reconstructs a value-free body from the endpoint
    manifest. Passing that provenance ref to an exact-request proof adapter made
    the adapter correctly reject the synthetic request as a different private
    request. Exact request candidates use their separate private-request lane;
    this copy prevents the generic lane from claiming that authority.
    """
    proof_candidate = dict(candidate)
    proof_candidate["request_ref_id"] = None
    return proof_candidate


def proof_request_for_candidate(
    endpoint_manifest: Any,
    candidate_manifest: Any,
    index: int,
    *,
    request_id: str,
    ordinal: int,
    name: str,
    headers: tuple[tuple[str, str], ...],
    authenticated: bool,
) -> ReplayRequest:
    """Resolve one candidate into the exact request a proof attempt must replay.

    A query candidate is fully described by its URL, exactly as before. A body candidate
    carries its method, content type and a well-formed body whose declared fields hold an
    inert placeholder, so the proof binds to the same field the signal came from.
    """
    resolved = execution_request_for_manifest_candidate(
        endpoint_manifest, candidate_manifest, index,
    )
    fields = [str(item) for item in resolved.get("body_field_names") or () if str(item)]
    method = str(resolved.get("method") or "GET").upper()
    if not fields:
        return ReplayRequest(
            request_id=request_id, ordinal=ordinal, name=name, folder="",
            method=method, url=str(resolved["url"]), headers=headers,
            body=b"", body_mode="none",
            auth_type="broker_session" if authenticated else "none",
            has_sensitive_material=authenticated,
        )
    content_type = str(resolved.get("content_type") or "").lower()
    if "json" in content_type:
        payload = json.dumps(
            _nested_proof_body(fields),
            sort_keys=True, separators=(",", ":"),
        )
        media_type = "application/json"
    else:
        payload = "&".join(
            f"{urllib.parse.quote(field, safe='')}={_BODY_PROOF_PLACEHOLDER}"
            for field in fields
        )
        media_type = "application/x-www-form-urlencoded"
    body_headers = tuple(
        item for item in headers if str(item[0]).lower() != "content-type"
    ) + (("Content-Type", media_type),)
    return ReplayRequest(
        request_id=request_id, ordinal=ordinal, name=name, folder="",
        method=method, url=str(resolved["url"]), headers=body_headers,
        body=payload.encode("utf-8"), body_mode="raw",
        auth_type="broker_session" if authenticated else "none",
        has_sensitive_material=authenticated,
    )


_BATCH_SUCCESS_STATUSES = frozenset({"success", "succeeded", "completed"})


def _batch_candidate_id(row: Mapping[str, Any], manifest_index: int) -> str:
    """The stable identity of one ranked-manifest entry inside a batch action."""
    return str(
        row.get("candidate_id") or row.get("route_id")
        or hashlib.sha256(str(manifest_index).encode()).hexdigest()
    )


def _template_match_identity(item: Mapping[str, Any]) -> tuple[str, str, str]:
    """What makes two template matches the same finding: template, matcher and location.

    The location is the matched URL as the finalizer compares response URLs, so a retry that
    printed the same match with a trailing slash or a differently cased host is the same match.
    """
    location = item.get("matched_at") or item.get("url")
    return (
        str(item.get("template_id") or "").strip().lower(),
        str(item.get("matcher_name") or "").strip().lower(),
        _observed_url_key(location) or str(location or ""),
    )


def merge_retried_template_records(
    observations: Sequence[Any], superseded: Mapping[str, str],
) -> list[Any]:
    """Keep the union of a retried endpoint's matches, each identity once (audit S001).

    ``superseded`` maps an endpoint whose cut-off first attempt was retried to that first
    attempt's id. The retry re-sends the whole pack, so a match it reproduced would only be a
    duplicate: the retry's record stands and names the first attempt it reproduced (with that
    attempt's evidence hashes). A first-attempt match the retry did not reproduce is still
    evidence the target returned, so it is kept as it was -- same proof state, never raised --
    and marked as not reproduced. Every other record, including both attempts' bookkeeping, is
    unchanged. Previously every first-attempt match was dropped, so a retry that found a
    different match, or finished with none, erased what the first attempt had found.
    """
    if not superseded:
        return list(observations)
    first_attempts = set(superseded.values())
    retry_attempts: dict[str, str] = {}
    retry_matches: dict[tuple[str, tuple[str, str, str]], dict[str, Any]] = {}
    merged: list[Any] = []
    for item in observations:
        if (
            isinstance(item, Mapping)
            and item.get("candidate_id") in superseded
            and item.get("attempt_id") not in first_attempts
        ):
            candidate_id = str(item["candidate_id"])
            if item.get("attempt_id"):
                retry_attempts.setdefault(candidate_id, str(item["attempt_id"]))
            if item.get("kind") == "template_match":
                record = dict(item)
                retry_matches.setdefault((candidate_id, _template_match_identity(record)), record)
                merged.append(record)
                continue
        merged.append(item)
    result: list[Any] = []
    for item in merged:
        if not (
            isinstance(item, Mapping)
            and item.get("kind") == "template_match"
            and item.get("attempt_id") in first_attempts
            and superseded.get(str(item.get("candidate_id") or "")) == item.get("attempt_id")
        ):
            result.append(item)
            continue
        candidate_id = str(item["candidate_id"])
        hashes = sorted({
            str(value) for key, value in item.items()
            if "sha256" in str(key).lower() and value
        })
        reproduced = retry_matches.get((candidate_id, _template_match_identity(item)))
        if reproduced is not None:
            # The retry's record is the match; it names where else it was seen.
            reproduced["reproduced_from_attempt_ids"] = sorted({
                *reproduced.get("reproduced_from_attempt_ids", ()), str(item["attempt_id"]),
            })
            if hashes:
                reproduced["reproduced_from_evidence_sha256"] = sorted({
                    *reproduced.get("reproduced_from_evidence_sha256", ()), *hashes,
                })
            continue
        result.append({
            **dict(item),
            "retry_reproduced": False,
            **(
                {"retry_attempt_id": retry_attempts[candidate_id]}
                if candidate_id in retry_attempts else {}
            ),
        })
    return result


def _sqli_fields(
    execution_target: str, body_request: Mapping[str, Any],
) -> tuple[tuple[str, ...] | None, int]:
    """The fields one sqlmap run tests for this candidate, and how many.

    A body candidate hands sqlmap exactly what ``agent_tools`` puts in ``-p`` (a nested JSON
    body's leaf names, de-duplicated); a query candidate is the URL itself, and sqlmap tests
    each of its query parameters.
    """
    if body_request:
        try:
            fields = agent_tools.sqlmap_injection_fields(body_request)
        except ValueError:
            fields = None
        # sqlmap splits ``-p`` on commas, so a name that contains one cannot be named alone;
        # it is left out of the per-field units (a whole-body run could not test it either).
        fields = [name for name in fields or () if "," not in name]
        if fields:
            return tuple(fields), len(fields)
    query = urllib.parse.urlsplit(str(execution_target or "")).query
    return None, max(1, len(urllib.parse.parse_qsl(query, keep_blank_values=True)))


def _staged_resume_fields(result: Any) -> dict[str, Any]:
    """What an unfinished SQLi candidate's next attempt was sized from, for its record."""
    technique = getattr(result, "resume_technique", None)
    if not technique:
        return {}
    rate = getattr(result, "seconds_per_request", None)
    field_name = getattr(result, "resume_field", None)
    return {
        "resume_technique": str(technique),
        **({"resume_field": str(field_name)} if field_name else {}),
        "field_count": int(getattr(result, "field_count", 1) or 1),
        **({"seconds_per_request_ms": round(float(rate) * 1_000)} if rate else {}),
        **({"resume_probe": True} if getattr(result, "resume_probe", False) else {}),
        **({"resume_unconfirmed": True} if getattr(result, "resume_unconfirmed", False) else {}),
        **(
            {"remaining_requests": int(result.remaining_requests)}
            if getattr(result, "remaining_requests", None) else {}
        ),
        **(
            {"remaining_wall_seconds": int(result.remaining_wall_seconds)}
            if getattr(result, "remaining_wall_seconds", None) else {}
        ),
    }


def _budget_verdict(
    result: Any, *, candidate_id: str, ceiling: int | None,
    fields: Sequence[str] | None,
    scan_wall_share: int | None = None,
) -> dict[str, Any] | None:
    """The per-technique budget verdict of a candidate, or None when it has none.

    A technique is inconclusive for budget when ``sqli_stages.resume_plan`` judges it
    unfundable (two or more rate samples, judged by their minimum, put it above the round's
    share or the candidate's fair part of the Scan's residual). A cancelled attempt never gets
    a verdict: it stopped because it was told to.
    """
    if not ceiling or str(getattr(result, "status", "")) == "cancelled":
        return None
    unfundable = tuple(getattr(result, "unfundable_techniques", ()) or ())
    closed = bool(getattr(result, "budget_inconclusive", False))
    settled = tuple(getattr(result, "settled_units", ()) or ())
    if not unfundable:
        return None
    return budget_inconclusive_record(
        candidate_id=candidate_id,
        finished=settled,
        unfundable_techniques=unfundable,
        fields=fields,
        field_count=getattr(result, "field_count", 1),
        seconds_per_request=getattr(result, "seconds_per_request", None),
        round_wall_ceiling_seconds=int(ceiling),
        scan_wall_share_seconds=scan_wall_share,
        closed=closed,
        next_technique=getattr(result, "resume_technique", None),
        next_field=getattr(result, "resume_field", None),
    )


def _deferred_budget_verdict(
    resume: Any, prior: Any, *, closed: bool, candidate_id: str,
    fields: Sequence[str] | None, field_count: int, ceiling: int | None,
    scan_wall_share: int | None, execution_target: str, method: str,
) -> list[dict[str, Any]]:
    """The budget verdict of a SQLi candidate deferred before any traffic, if it has one."""
    unfundable = tuple(getattr(resume, "unfundable", ()) or ())
    if not ceiling or not unfundable:
        return []
    return [{
        "url": redact_url(execution_target),
        "method": method,
        **budget_inconclusive_record(
            candidate_id=candidate_id,
            finished=prior.finished,
            unfundable_techniques=unfundable,
            fields=fields,
            field_count=field_count,
            seconds_per_request=prior.seconds_per_request,
            round_wall_ceiling_seconds=int(ceiling),
            scan_wall_share_seconds=scan_wall_share,
            closed=closed or bool(getattr(resume, "budget_inconclusive", False)),
            next_technique=getattr(resume, "technique", None),
            next_field=getattr(resume, "field_name", None),
        ),
    }]


def _no_tool_output(observations: Any) -> bool:
    """True when a checkpointed attempt holds only its own bookkeeping record."""
    return all(
        isinstance(item, Mapping) and item.get("kind") == "candidate_attempt"
        for item in observations or ()
    )


def batch_outcome(
    attempts: Sequence[Any], unattempted: int,
) -> tuple[str, bool, bool]:
    """Return (status, partial, timed_out) for a batch from its attempts.

    Every batch handler decided this independently and all of them looked only at
    `unattempted`, so a batch whose every attempt failed or was wall-killed -- with each
    candidate duly started -- reported `success` with `timed_out=False`. That is how a
    family showed complete coverage while proving nothing.

    A completed attempt that reached "not proven" is still a success: not finding a
    vulnerability is a result. An attempt that never finished is not.
    """
    normalized = tuple(
        (
            str(item.get("status") or "").strip().lower(),
            bool(item.get("timed_out")),
        )
        if isinstance(item, Mapping)
        else (str(item or "").strip().lower(), False)
        for item in attempts
    )
    failed = any(status not in _BATCH_SUCCESS_STATUSES for status, _ in normalized)
    # Partial is a completion-quality state, not a timeout synonym. Adapters report
    # timeout independently because parser/network/browser partials are legitimate.
    timed_out = any(status == "timed_out" or explicit for status, explicit in normalized)
    partial = bool(unattempted) or failed
    return ("partial" if partial else "success", partial, timed_out)


def attempt_ceiling_stops(errors: Sequence[Any]) -> set[str]:
    """The non-time budget dimensions whose ceiling stopped one attempt's tool."""
    tokens = (str(item or "").strip().lower().split(":", 1)[0] for item in errors or ())
    return {CEILING_STOP_ERRORS[token] for token in tokens if token in CEILING_STOP_ERRORS}


def batch_stop_reason(
    attempt_errors: Sequence[Any],
    *,
    unattempted: int,
    ceiling_stops: Iterable[str] = (),
    exhausted: Iterable[str] = (),
    cancelled: bool = False,
    unexamined: int = 0,
) -> str:
    """The one reason a partial batch states, naming the dimension that actually stopped it.

    A batch whose attempts were all wall-killed timed out. A batch stopped by the pinned
    transport's request ceiling, or left with candidates its remaining request or
    mutation allowance could not fund, ran out of THAT dimension: reporting it as
    ``timed_out`` (126 of 126 requests spent in 83 of 216 seconds) sent every reader to
    the wall instead. A leftover candidate is a timeout only when the action's own wall
    is what ran out; anything else unfunded stays ``insufficient_plan_budget``.
    """
    if cancelled:
        # Cancellation stops execution; whatever budget was left is not why the batch ended.
        return CapabilityResultReason.CANCELLED.value
    lowered = [str(item).strip().lower() for item in attempt_errors or ()]
    stops = set(ceiling_stops)
    # Work left over -- a candidate never attempted, or an endpoint whose wall-killed attempt
    # could not be retried -- was stopped by whichever dimension could not fund it. On the
    # soak the required passive batch had every endpoint attempted and charged its pack's
    # seven requests, so the retry its wall-killed endpoint needed found the request hold
    # spent; the batch said `timed_out` and the request ceiling never appeared.
    spent = set(exhausted) if unattempted or unexamined else set()
    for dimension in ("http_requests", "state_changing_requests"):
        if dimension in spent:
            return BUDGET_EXHAUSTION_REASONS[dimension].value
    memory = CapabilityResultReason.CRAWLER_MEMORY_BOUND_EXCEEDED.value
    if lowered and not stops and all(
        item in {"timeout", memory} or is_process_kill_error(item) for item in lowered
    ):
        # Only the worker's own deadline is a timeout (`timeout`, with timed_out set on
        # the attempt). A tool killed by the kernel's OOM killer or the memory ceiling
        # (`exit_-9`) was not timed out, and the receipt does not claim it was.
        if "timeout" in lowered:
            return CapabilityResultReason.TIMED_OUT.value
        if all(item == memory for item in lowered):
            return memory
        return CapabilityResultReason.PROCESS_KILLED.value
    for dimension in ("http_requests", "state_changing_requests"):
        if dimension in stops or dimension in spent:
            return BUDGET_EXHAUSTION_REASONS[dimension].value
    if "tool_wall_seconds" in spent:
        return CapabilityResultReason.TIMED_OUT.value
    if unattempted or CapabilityResultReason.INSUFFICIENT_PLAN_BUDGET.value in lowered:
        # A SQLi candidate closed for budget names it (soak N55).
        return CapabilityResultReason.INSUFFICIENT_PLAN_BUDGET.value
    return CapabilityResultReason.ADAPTER_FAILED.value


# What one batch candidate may raise without failing the whole batch action.
_BATCH_CANDIDATE_ERRORS = (
    ScanWorkManifestError, ValueError, KeyError, TypeError, IndexError, AttributeError,
)


class ScanActionAdapterError(RuntimeError):
    """One immutable action has no safe database-neutral adapter mapping."""


def _exposure_observation(
    url: str, discovered_via: str, signature: Any, result: Any,
) -> Mapping[str, Any]:
    """Keep reachability metadata distinct from content-specific secret proof."""
    proven = is_sensitive_exposure_class(signature.exposure_class)
    content_type = next((
        str(value) for name, value in result.response_headers.items()
        if str(name).lower() == "content-type"
    ), "")
    return {
        "kind": "sensitive_exposure_proof",
        "proof_state": "verified" if proven else "not_proven",
        "finding_verdict": "verified" if proven else "not_proven",
        "exposure_class": signature.exposure_class,
        "severity": signature.severity,
        "proof_contract": signature.proof_contract,
        "request_url": url,
        "discovered_via": discovered_via,
        "response_status": result.status_code,
        "content_type": content_type,
        # A body that may hold secret material keeps only an installation-keyed digest: a
        # plain SHA-256 of a small leaked file lets anyone holding the evidence confirm a
        # guess of the whole file offline.
        **({"response_body_sha256": None,
            "response_body_hmac": keyed_body_digest(result.response_body)}
           if signature.withholds_content else
           {"response_body_sha256": hashlib.sha256(result.response_body).hexdigest()}),
        "matched_signature": signature.matched_pattern,
        "redacted_excerpt": redacted_exposure_excerpt(result.response_body, signature),
        # Key names, provider categories and scrypt fingerprints of the proven secrets:
        # enough to match a repeat sighting or a rotation, never the value itself.
        "exposure_fingerprints": signature.secret_evidence(),
        "proof_producer": "shakerscan",
        "secret_values_visible": False,
    }


def _directory_listing_child_url(directory_url: str, link: str) -> str:
    """Resolve one listing entry against the directory that produced it.

    Listing generators disagree about what their hrefs are relative to. Apache
    and nginx emit a bare filename, which resolves against the directory. The
    Node/Express serve-index middleware emits the path from the site root --
    ``ftp/acquisitions.md`` for a listing of ``/ftp`` -- which resolved to
    ``/ftp/ftp/acquisitions.md`` and was refused, so the confidential files a
    browsable directory exposes were never actually reached.
    """
    base = directory_url.rstrip("/") + "/"
    relative = link[2:] if link.startswith("./") else link
    segments = [item for item in urllib.parse.urlsplit(base).path.split("/") if item]
    if segments and relative.lstrip("/").startswith(f"{segments[-1]}/"):
        # The entry repeats the directory's own segment: it is relative to the
        # site root, so resolve it one level up instead of nesting it.
        return urllib.parse.urljoin(base, "../" + relative.lstrip("/"))
    return urllib.parse.urljoin(base, link)


_OFF_ORIGIN_SPEC_ISSUES = frozenset({"spec_off_origin_server", "spec_server_scheme_mismatch"})


def _spec_ingest_partial_reason(
    issues: Sequence[str], *, spec_routes: int = 0,
) -> CapabilityResultReason:
    """The honest reason a spec/hint ingestion is partial, most severe first.

    A ``*_limit`` / ``*_limit_reached`` issue is a real bound: routes beyond it were dropped,
    so the output was truncated. A hint file the target answered with its HTML shell was never
    published -- nothing was dropped or misparsed. A spec whose operations declare only servers
    on another origin (another host, port or scheme) parsed, but those routes are outside the
    binding: when no spec route was ingested the description is out of scope, and when some were
    it is partly so. Anything else is a document the parser could only partly model (an
    unsupported media type, an unresolvable reference, a hint parse error).
    """
    tokens = [str(issue or "").split(":", 1)[0] for issue in issues]
    if any(token.endswith(("_limit", "_limit_reached")) for token in tokens):
        return CapabilityResultReason.OUTPUT_TRUNCATED
    if tokens and all(token == "hint_document_is_markup" for token in tokens):
        return CapabilityResultReason.SOURCE_NOT_PUBLISHED
    # A spec that names another origin parsed fine: its routes are out of scope, not misread.
    if _OFF_ORIGIN_SPEC_ISSUES.intersection(tokens) and all(
        token in _OFF_ORIGIN_SPEC_ISSUES or token == "hint_document_is_markup" for token in tokens
    ):
        if spec_routes > 0:
            return CapabilityResultReason.DECLARED_PARTLY_OUT_OF_SCOPE
        return CapabilityResultReason.DECLARED_OUT_OF_SCOPE
    return CapabilityResultReason.PARSER_FAILED


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
        browser_login_adapter_factory: Callable[..., Any] | None = None,
        authentication_health_adapter_factory: Callable[..., Any] | None = None,
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
        # The first candidate is only a report fallback. No base-URL action may use it
        # until origin.select has produced a measured, persisted choice.
        self.target_url = scan_external_execution_target(
            target.inferred_origins[0] if target.inferred_origins else target_url,
            target=target,
        )
        self._origin_selected = not bool(target.inferred_origins)
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
        from .action_interruption import action_interrupted
        self.cancelled = lambda: cancelled() or action_interrupted()
        self._private_replay_plan_loader = private_replay_plan_loader
        self._browser_login_adapter_factory = browser_login_adapter_factory
        self._authentication_health_adapter_factory = authentication_health_adapter_factory
        self._authentication_health_records: dict[str, Any] = {}
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
        recorded_observations = list(observations)
        consumed_budget = dict(consumed or {
            name: 0 for name in action.requested_budget
        })
        exercised_http = int(consumed_budget.get("http_requests") or 0) > 0
        uses_primary = (
            action.capability_name in _PRIMARY_PRINCIPAL_CAPABILITIES
            and not (
                action.capability_name == "http.request"
                and action.action_id != "baseline.http"
            )
        )
        lanes = (
            ("primary", "secondary")
            if action.capability_name == "authz.verify" else ("primary",)
        ) if uses_primary else ()
        if exercised_http and status != "skipped":
            for lane in lanes:
                principal = resolve_scan_http_principal(
                    self.options, lane=lane,
                    capability_name=action.capability_name,
                )
                if principal.authenticated and principal.binding_digest:
                    recorded_observations.append({
                        "kind": "principal_context",
                        "lane": lane,
                        "authenticated": True,
                        "binding_digest": str(principal.binding_digest),
                        "source": "server_runtime",
                    })
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
            budget_consumed=consumed_budget,
            observations=tuple(recorded_observations),
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

    def _empty_slice_reason(self, manifest: ScanWorkManifest) -> str:
        """Do not launder an incomplete producer into clean not-applicable coverage."""
        if str(getattr(manifest, "status", "complete")) != "complete":
            return "dependency_incomplete"
        return "not_applicable"

    async def _observations(self, action_id: str) -> tuple[Mapping[str, Any], ...]:
        return await self.backend.load_observations(action_id)

    async def _restore_selected_origin(self) -> bool:
        if self._origin_selected:
            return True
        from .origin_selection import selected_origin_from_observations
        origin_action = next((item for item in self.plan.actions
                              if item.capability_name == "scan.origin_select"), None)
        if origin_action is None:
            return False
        selected = selected_origin_from_observations(
            await self._observations(origin_action.action_id), self.target,
        )
        if selected:
            self.target_url = scan_external_execution_target(selected, target=self.target)
            self._origin_selected = True
        return self._origin_selected

    @staticmethod
    def _scan_call_recorder(action: ScanAction, *, source: str = "http.request") -> Any:
        """Archive callback that names the capability, not only the transport."""
        return functools.partial(
            _scan_capture.record_scan_call,
            capability_name=action.capability_name, source=source,
        )

    def _scan_replay_transport(
        self, action: ScanAction, *, principal_slot: str | None = None,
        private: bool = False, **transport_options: Any,
    ) -> Any:
        """The pinned replay transport, recording every call into the scan archive.

        Engine capabilities that send in-process are within reach of the archive; only the
        external scanner processes behind the opaque tunnel are not. ``private`` marks rows
        whose values (replayed collection bodies, session headers under arbitrary names,
        fetched secret files) masked archive views must withhold.
        """
        return RecordedReplayTransport(
            PinnedAiohttpReplayTransport(**transport_options),
            self._scan_call_recorder(action, source="replay_transport"),
            principal_slot=principal_slot,
            private=private,
        )

    async def _origin_select(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        from .origin_selection import select_inferred_scan_origin, selected_origin_from_observations

        async def operation() -> Mapping[str, Any]:
            return await select_inferred_scan_origin(
                target=self.target,
                transaction_recorder=self._scan_call_recorder(action),
                timeout_seconds=int(action.requested_budget.get("tool_wall_seconds") or 20),
            )

        adapter = self._prepared_inline(
            action, {"origins": list(self.target.inferred_origins)}, operation,
            ScanOriginSelectionExecutionAdapter,
        )
        receipt = await self._execute_adapter(action, adapter, heartbeat, managed_cancellation=True)
        selected = selected_origin_from_observations(receipt.observations, self.target)
        if selected:
            self.target_url = scan_external_execution_target(selected, target=self.target)
            self._origin_selected = True
        return receipt

    async def restore_terminal_state(
        self, action: ScanAction, _result: Any,
    ) -> bool:
        """Rehydrate sealed prerequisites without repeating completed traffic."""
        if "authentication_profile_ref" in action.capability_args:
            return False  # A prior process's health sample cannot authorize resumed traffic.
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

    def authentication_health_status(self, action: ScanAction) -> str | None:
        from authenticated_assurance.scan_health import scan_health_status
        return scan_health_status(self._authentication_health_records, self.options, action)

    async def _http(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        if "authentication_profile_ref" in action.capability_args:
            if self._authentication_health_adapter_factory is None:
                return self._skip(action, "authentication_uncertain")
            try:
                adapter = self._authentication_health_adapter_factory(action=action, dispatcher=self)
            except (ValueError, TypeError):
                return self._skip(action, "authentication_uncertain")
            receipt = await self._execute_adapter(action, adapter, heartbeat)
            for observation in receipt.observations:
                if observation.get("kind") == "authentication_health":
                    record = dict(observation["record"])
                    self._authentication_health_records[str(record["profile_id"])] = record
            return receipt
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
                # The deterministic Scan plane records here for the same reason Hunt does:
                # without it a scan export was empty while the endpoint claimed coverage.
                transaction_recorder=self._scan_call_recorder(action),
                timeout_seconds=max(1, int(action.requested_budget.get("tool_wall_seconds") or 1)),
                allow_bound_origin_redirects=follow,
                trusted_headers=(
                    primary.headers()
                    if action.action_id == "baseline.http" else None
                ),
                principal_slot=(
                    "primary"
                    if action.action_id == "baseline.http" and primary.authenticated
                    else "anonymous"
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

    async def _infrastructure(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        async def operation() -> Mapping[str, Any]:
            return await inspect_infrastructure_intelligence(
                self.target,
                timeout_seconds=max(1, int(action.requested_budget.get("tool_wall_seconds") or 1)),
            )

        adapter = self._prepared_inline(
            action, {}, operation, InfrastructureInspectionExecutionAdapter,
        )
        return await self._execute_adapter(action, adapter, heartbeat)

    async def _tls(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        # A scheme-inferred target already proved that its HTTPS candidate did not
        # answer before selecting HTTP. Repeating TLS on that same service would
        # turn an examined HTTP application into a failed Scan for a transport it
        # does not serve. The selector's refused attempt remains in the report.
        if (self.target.inferred_origins and self._origin_selected
                and urllib.parse.urlsplit(self.target_url).scheme == "http"):
            return self._skip(action, "not_applicable")
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
            # Collection requests carry the operator's private workflow values, so the
            # archived rows are withheld from masked views as Hunt's collection rows are.
            transport=self._scan_replay_transport(
                action,
                principal_slot="primary" if primary_profile_bound else None,
                private=True,
            ),
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
            transport=self._scan_replay_transport(action, private=True),
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
            return self._skip(action, self._empty_slice_reason(manifest))
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
        attempt_statuses: list[Mapping[str, Any]] = []
        resumed = 0
        exhausted: set[str] = set()
        stopped_by_cancel = False
        for offset, candidate in enumerate(rows):
            candidate_id = str(candidate["candidate_id"])
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:{family}:{candidate_id}".encode()
            ).hexdigest()
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                attempt_statuses.append(prior)
                observations.extend(prior.get("observations") or ())
                for name, amount in dict(prior.get("budget_consumed") or {}).items():
                    consumed[name] = consumed.get(name, 0) + int(amount)
                continue
            if self.cancelled():
                stopped_by_cancel = True
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
            short = {
                name for name, minimum in (
                    ("http_requests", 2), ("tool_wall_seconds", 1),
                    *((("state_changing_requests", 2),)
                      if request_class == "confirmed_mutation" else ()),
                )
                if sub_budget.get(name, 0) < minimum
            }
            if request is None or not authorized or short:
                exhausted |= short
                break
            specification = CAPABILITY_REGISTRY.require(action.capability_name)
            adapter = RequestMutationVerificationAdapter(
                specification=specification,
                target=self.target,
                request=request,
                candidate=candidate,
                transport=self._scan_replay_transport(action, private=True),
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
                "timed_out": bool(result.timed_out),
                "budget_consumed": dict(result.actual_budget),
                "observations": attempt_observations,
                "errors": tuple(result.errors),
                "proof_state": proof_state,
            }
            if result.status != "cancelled":
                await checkpoint_attempt(action.action_id, attempt)
            attempt_statuses.append({
                "status": str(result.status),
                "timed_out": bool(result.timed_out),
            })
            attempted += 1
            observations.extend(attempt_observations)
            errors.extend(str(item) for item in result.errors)
            for name, amount in result.actual_budget.items():
                consumed[name] = min(
                    int(action.requested_budget.get(name, 0)),
                    consumed.get(name, 0) + int(amount),
                )
            if result.status == "cancelled":
                stopped_by_cancel = True
                break
        unattempted = max(0, len(rows) - attempted)
        # State why the batch is partial. Attempts stop when the remaining
        # reservation can no longer fund one that could reach a verdict, so the
        # candidates left over are a budget outcome, not truncated output.
        # Say why this batch is partial, ahead of any per-attempt tool errors, so
        # the durable reason is the real one. A tool error string like "timeout"
        # is not a reason code, so without this the result fell back to
        # "output_truncated" and put a false reason on a required action.
        batch_errors = list(errors[:20])
        if unattempted or stopped_by_cancel:
            stated = batch_stop_reason(
                batch_errors, unattempted=unattempted, exhausted=exhausted,
                ceiling_stops=attempt_ceiling_stops(batch_errors),
                cancelled=stopped_by_cancel,
            )
            batch_errors.insert(0, stated)
        _batch_status, _batch_partial, _batch_timed_out = batch_outcome(
            attempt_statuses, unattempted,
        )
        return self._receipt(
            action,
            status="cancelled" if stopped_by_cancel else _batch_status,
            parser_version=CAPABILITY_REGISTRY.require(action.capability_name).output_schema,
            started_at=started_at,
            observations=tuple(observations),
            errors=tuple(batch_errors),
            consumed=consumed,
            partial=_batch_partial,
            timed_out=_batch_timed_out,
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
            return self._skip(action, self._empty_slice_reason(manifest))
        candidate_signals: set[str] = set()
        for dependency in proof_signal_sources(action, self.plan):
            for item in await self._observations(dependency):
                if (
                    str(item.get("kind") or "") in {"xss_alert", "request_body_verification"}
                    and str(item.get("candidate_id") or "")
                    and str(item.get("proof_state") or item.get("proof_status") or "")
                    not in {"not_proven", "unproven", ""}
                ):
                    candidate_signals.add(str(item["candidate_id"]))
        # A URL fragment never reaches a server-side verifier, so requiring an upstream reflection
        # signal makes DOM-only XSS impossible to prove. The immutable fragment candidate itself is
        # sufficient authority for a bounded same-origin browser attempt.
        candidate_signals.update(
            str(candidate.get("candidate_id") or "")
            for _index, candidate in rows
            if candidate.get("browser_fragment_query_parameter_names")
            and str(candidate.get("parameter_name") or "")
            in candidate.get("browser_fragment_query_parameter_names", ())
        )
        candidate_signals.discard("")
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

        # A proof re-planned behind a verification extension carries every candidate the
        # escalation it extends already took to a verdict: no candidate is proven twice. A
        # proof re-planned again reads its whole chain, nearest first.
        extends = str(action.capability_args.get(EXTENDS_ARG) or "")
        carried: dict[str, dict] = {}
        carried_source: dict[str, str] = {}
        for source in extension_lineage(action, self.plan):
            for finished_id, item in finished_attempts(await load_attempts(source)).items():
                if finished_id not in completed and finished_id not in carried:
                    carried[finished_id] = item
                    carried_source[finished_id] = source
        carried_count = 0
        manifest_digest = manifest.reference().manifest_digest
        started_at = datetime.now(timezone.utc).isoformat()
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        consumed = {name: 0 for name in action.requested_budget}
        attempted = resumed = 0
        attempt_statuses: list[Mapping[str, Any]] = []
        # Discovery (xss.verify_batch) ran under the primary principal, so the proof must
        # too: replaying an authenticated candidate anonymously renders a login or 401 page
        # and can never verify. The receipt's principal_context already claims this lane.
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=action.capability_name,
        )
        proof_headers = primary.headers() if primary.authenticated else None
        for offset, (manifest_index, candidate) in enumerate(rows):
            candidate_id = str(candidate.get("candidate_id") or "")
            if candidate_id not in candidate_signals:
                continue
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:xss_browser_proof:{candidate_id}".encode()
            ).hexdigest()
            if attempt_id in carried:
                carried_count += 1
                attempted += 1
                attempt_statuses.append({"status": "success", "timed_out": False})
                observations.extend(carried_records(
                    carried[attempt_id], source=carried_source[attempt_id],
                ))
                continue
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                attempt_statuses.append(prior)
                observations.extend(prior.get("observations") or ())
                for name, amount in dict(prior.get("budget_consumed") or {}).items():
                    consumed[name] = consumed.get(name, 0) + int(amount)
                continue
            if self.cancelled():
                break
            resolved_request = execution_request_for_manifest_candidate(
                endpoints, manifest, manifest_index,
            )
            body_fields = tuple(
                str(item) for item in resolved_request.get("body_field_names") or ()
            )
            if body_fields and not self.policy.allow_state_changing_http:
                continue
            execution_url = str(resolved_request["url"])
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
            if body_fields and sub_budget.get("state_changing_requests", 0) < 1:
                break
            try:
                prepared = XSSBrowserProofAdapter.prepare(
                    target=self.target, execution_url=execution_url,
                    candidate_id=candidate_id,
                    parameter_name=str(candidate.get("parameter_name") or ""),
                    method=str(resolved_request.get("method") or "GET"),
                    content_type=(
                        str(resolved_request.get("content_type"))
                        if resolved_request.get("content_type") else None
                    ),
                    body_field_names=body_fields,
                )
            except BrowserCapabilityInputError as exc:
                # One unprovable candidate is that candidate's failed attempt; it must
                # never abort the rest of the batch.
                rejected = {
                    "attempt_id": attempt_id, "candidate_id": candidate_id,
                    "status": "failed", "timed_out": False, "budget_consumed": {},
                    "observations": ({
                        "kind": "candidate_attempt", "attempt_id": attempt_id,
                        "candidate_id": candidate_id, "family": "xss_browser_proof",
                        "status": "failed", "proof_state": "not_proven",
                        "budget_consumed": {},
                    },),
                    "errors": (f"xss_proof_input_rejected:{exc}",),
                    "proof_state": "not_proven",
                }
                await checkpoint_attempt(action.action_id, rejected)
                attempt_statuses.append({"status": "failed", "timed_out": False})
                attempted += 1
                observations.extend(rejected["observations"])
                errors.append(rejected["errors"][0])
                continue
            adapter = XSSBrowserProofAdapter(prepared, trusted_headers=proof_headers)
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
                "status": result.status, "timed_out": bool(result.timed_out),
                "budget_consumed": dict(result.actual_budget),
                "observations": bundled, "errors": tuple(result.errors),
                "proof_state": proof_state,
            }
            if result.status != "cancelled":
                await checkpoint_attempt(action.action_id, attempt)
            attempt_statuses.append({
                "status": str(result.status),
                "timed_out": bool(result.timed_out),
            })
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
        _batch_status, _batch_partial, _batch_timed_out = batch_outcome(
            attempt_statuses, unattempted,
        )
        return self._receipt(
            action, status=_batch_status,
            parser_version=CAPABILITY_REGISTRY.require(action.capability_name).output_schema,
            started_at=started_at, observations=tuple(observations),
            errors=tuple(errors[:20]), consumed=consumed,
            partial=_batch_partial, timed_out=_batch_timed_out,
            redacted_execution={
                "action_id": action.action_id, "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "eligible_count": eligible, "attempted_count": attempted,
                "resumed_count": resumed, "unattempted_count": unattempted,
                "checkpoint_mode": "after_each_candidate",
                **({"extends": extends, "carried_count": carried_count} if extends else {}),
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
            return self._skip(action, self._empty_slice_reason(manifest))
        candidate_signals: set[str] = set()
        for dependency in proof_signal_sources(action, self.plan):
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

        # A proof re-planned behind a verification extension carries every candidate the
        # escalation it extends already took to a verdict: no candidate is proven twice. A
        # proof re-planned again reads its whole chain, nearest first.
        extends = str(action.capability_args.get(EXTENDS_ARG) or "")
        carried: dict[str, dict] = {}
        carried_source: dict[str, str] = {}
        for source in extension_lineage(action, self.plan):
            for finished_id, item in finished_attempts(await load_attempts(source)).items():
                if finished_id not in completed and finished_id not in carried:
                    carried[finished_id] = item
                    carried_source[finished_id] = source
        carried_count = 0
        manifest_digest = manifest.reference().manifest_digest
        started_at = datetime.now(timezone.utc).isoformat()
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        consumed = {name: 0 for name in action.requested_budget}
        attempted = resumed = 0
        attempt_statuses: list[Mapping[str, Any]] = []
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=action.capability_name,
        )
        for offset, (manifest_index, candidate) in enumerate(rows):
            candidate_id = str(candidate.get("candidate_id") or "")
            # A fragment-located candidate (family_hints: ["xss"]) lives only in the
            # SPA hash route the server never receives, so a server-side SQL proof
            # would waste budget on a parameter the origin never sees. It belongs to
            # the browser XSS proof; skip it here.
            if candidate.get("browser_fragment_path"):
                continue
            # A path-segment candidate has no request field to mutate; the repeated differential
            # proof operates on a body or query parameter, so a path SQLi is left at the sqlmap
            # verification tier rather than proven here.
            if candidate.get("parameter_location") == "path":
                continue
            if candidate_id not in candidate_signals:
                continue
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:sqli_proof:{candidate_id}".encode()
            ).hexdigest()
            if attempt_id in carried:
                carried_count += 1
                attempted += 1
                attempt_statuses.append({"status": "success", "timed_out": False})
                observations.extend(carried_records(
                    carried[attempt_id], source=carried_source[attempt_id],
                ))
                continue
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                attempt_statuses.append(prior)
                observations.extend(prior.get("observations") or ())
                for name, amount in dict(prior.get("budget_consumed") or {}).items():
                    consumed[name] = consumed.get(name, 0) + int(amount)
                continue
            if self.cancelled():
                break
            request_class = str(candidate.get("request_class") or "safe_read")
            proof_candidate = dict(candidate)
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
                proof_candidate = _candidate_for_synthetic_proof(candidate)
                # A body candidate mutates, so it needs the same authority the private
                # request path above demands before it may be replayed.
                if (
                    candidate.get("body_field_names")
                    and not (
                        self.policy.allow_state_changing_http
                        and self.policy.approval_receipt_id
                    )
                ):
                    continue
                if candidate.get("body_field_names"):
                    path = str(candidate.get("canonical_path") or "").lower()
                    proof_candidate["request_class"] = (
                        "safe_authentication"
                        if any(token in path for token in ("/login", "/auth", "/session"))
                        else "confirmed_mutation"
                    )
                request = proof_request_for_candidate(
                    endpoints, manifest, manifest_index,
                    request_id=f"candidate:{candidate_id}",
                    ordinal=manifest_index,
                    name="canonical SQLi candidate",
                    headers=tuple(primary.headers().items()),
                    authenticated=primary.authenticated,
                )
                execution_url = request.url
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
            # Constructing the adapter validates this candidate's request against the
            # sub-budget -- a body candidate in a slice whose reservation tier carries
            # no state_changing_requests cannot be funded, for one example. That is one
            # candidate's problem, not the slice's: record it as a failed attempt with a
            # reason and keep proving the rest, instead of letting the raise abort the
            # whole batch.
            try:
                adapter = SQLiProofAdapter(
                    specification=specification,
                    target=self.target,
                    request=request,
                    candidate=proof_candidate,
                    transport=self._scan_replay_transport(action, private=True),
                    requested_budget=sub_budget,
                )
            except SQLiProofError as exc:
                attempt = {
                    "attempt_id": attempt_id, "candidate_id": candidate_id,
                    "status": "failed", "timed_out": False,
                    "budget_consumed": {},
                    "observations": ({
                        "kind": "candidate_attempt",
                        "attempt_id": attempt_id,
                        "candidate_id": candidate_id,
                        "family": "sqli_proof",
                        "status": "failed",
                        "proof_state": "not_proven",
                        "budget_consumed": {},
                    },),
                    "errors": (f"sqli_proof_unconstructable:{exc}",),
                    "proof_state": "not_proven",
                }
                await checkpoint_attempt(action.action_id, attempt)
                attempt_statuses.append({"status": "failed", "timed_out": False})
                attempted += 1
                observations.extend(attempt["observations"])
                errors.append(str(attempt["errors"][0]))
                continue
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
                "status": result.status, "timed_out": bool(result.timed_out),
                "budget_consumed": dict(result.actual_budget),
                "observations": bundled, "errors": tuple(result.errors),
                "proof_state": proof_state,
            }
            if result.status != "cancelled":
                await checkpoint_attempt(action.action_id, attempt)
            attempt_statuses.append({
                "status": str(result.status),
                "timed_out": bool(result.timed_out),
            })
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
        _batch_status, _batch_partial, _batch_timed_out = batch_outcome(
            attempt_statuses, unattempted,
        )
        return self._receipt(
            action, status=_batch_status,
            parser_version=CAPABILITY_REGISTRY.require(action.capability_name).output_schema,
            started_at=started_at, observations=tuple(observations),
            errors=tuple(errors[:20]), consumed=consumed,
            partial=_batch_partial, timed_out=_batch_timed_out,
            redacted_execution={
                "action_id": action.action_id, "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "eligible_count": eligible, "attempted_count": attempted,
                "resumed_count": resumed, "unattempted_count": unattempted,
                "checkpoint_mode": "after_each_candidate",
                **({"extends": extends, "carried_count": carried_count} if extends else {}),
                "secret_values_visible": False,
            },
        )

    async def _spec_ingest(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        """Fetch what the target declares about itself and turn it into routes.

        A crawl only observes the endpoints an application happens to call. Its own
        description declares the rest: an OpenAPI document gives the body-bearing
        routes a black-box crawl never exercises, and robots.txt and llms.txt give
        the paths an operator wrote down by hand -- including the ones deliberately
        kept out of the link graph, which is exactly the surface a crawl cannot see.

        Each conventional location is fetched once over the pinned transport, under
        the primary principal so an authenticated document is reachable, and parsed
        into value-free ``discovered_route`` observations that flow into the same
        endpoint manifest as the crawl. A declared path is a claim, never a
        confirmed route; it is probed like any other candidate.
        """
        origin = self._exposure_origin()
        if origin is None:
            return self._skip(action, "no_canonical_origin")
        base_origin, _scheme = origin
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name="web.spec_ingest",
        )
        header_items = tuple(
            (str(name), str(value)) for name, value in primary.headers().items()
        )
        http_ceiling = int(action.requested_budget.get("http_requests") or 0)
        wall_ceiling = max(1, int(action.requested_budget.get("tool_wall_seconds") or 1))
        # An authenticated fetch carries the principal's headers, whose names are not
        # known to key-name masking, so it is archived as private.
        transport = self._scan_replay_transport(
            action,
            principal_slot="primary" if header_items else "anonymous",
            private=bool(header_items),
        )
        started_at = datetime.now(timezone.utc).isoformat()
        documents: list[tuple[str, bytes, str | None]] = []
        errors: list[str] = []
        attempted = 0
        hint_documents: list[tuple[str, bytes, str | None]] = []
        for path in (*SPEC_DISCOVERY_PATHS, *HINT_DISCOVERY_PATHS):
            if self.cancelled() or attempted >= http_ceiling:
                break
            spec_url = f"{base_origin}{path}"
            request = ReplayRequest(
                request_id=f"spec:{attempted}", ordinal=attempted,
                name="spec probe", folder="", method="GET", url=spec_url,
                headers=header_items, body=b"", body_mode="none",
                auth_type="bearer" if header_items else "none",
                has_sensitive_material=bool(header_items),
            )
            remaining = max(1, http_ceiling - attempted)
            result = await transport.send(
                request, target=self.target,
                timeout_seconds=max(0.5, min(15.0, wall_ceiling / remaining)),
                follow_redirects=False,
            )
            attempted += 1
            await heartbeat()
            if result.error_code:
                errors.append(str(result.error_code))
                continue
            if (result.status_code or 0) == 200 and result.response_body:
                content_type = str(
                    result.response_headers.get("content-type")
                    or result.response_headers.get("Content-Type") or ""
                ) or None
                target = (
                    hint_documents if path in HINT_DISCOVERY_PATHS else documents
                )
                target.append((spec_url, result.response_body, content_type))
        ingestion_issues: list[str] = []
        routes = ingest_spec_bodies(documents, origin=base_origin, issues=ingestion_issues)
        spec_route_count = len(routes)
        # The hint files are an optional extra source. Whatever they do, the
        # specification results this action already parsed must survive them.
        try:
            routes = list(routes) + ingest_hint_documents(
                hint_documents, origin=base_origin, issues=ingestion_issues,
            )
        except Exception as hint_error:  # noqa: BLE001 - target-supplied content
            routes = list(routes)
            ingestion_issues.append(
                f"hint_ingestion_failed:{type(hint_error).__name__}"
            )
        if ingestion_issues:
            # State why the action is partial. Without a stated reason the backend falls back to
            # output_truncated, which told the operator a bounded limit was reached when the
            # target had only answered robots.txt with its HTML shell.
            errors.insert(0, _spec_ingest_partial_reason(
                ingestion_issues, spec_routes=spec_route_count,
            ).value)
        errors.extend(ingestion_issues)
        # Value-free: the observation carries the route shape and field names, never a spec value.
        observations = tuple(dict(route) for route in routes)
        consumed = {
            name: 0 for name in action.requested_budget
        }
        if "http_requests" in consumed:
            consumed["http_requests"] = min(http_ceiling, attempted)
        if "tool_wall_seconds" in consumed:
            consumed["tool_wall_seconds"] = min(wall_ceiling, max(1, attempted))
        return self._receipt(
            action,
            status="partial" if ingestion_issues else "success",
            parser_version="spec-ingest/v1",
            started_at=started_at,
            observations=observations,
            errors=tuple(errors[:20]),
            consumed=consumed,
            partial=bool(ingestion_issues),
            redacted_execution={
                "action_id": action.action_id,
                "specs_probed": attempted,
                "specs_parsed": len(documents),
                "hint_documents_parsed": len(hint_documents),
                "routes_declared": len(routes),
                "ingestion_limitations": ingestion_issues,
                "authenticated": bool(header_items),
            },
        )

    def _exposure_origin(self) -> tuple[str, str] | None:
        """Return the (origin, scheme) for canonical-host seed probing.

        A target entered without a scheme is frozen with both origins, http first; its probes
        run against the origin ``scan.origin_select`` measured (HTTPS when it answers), like
        every other action, never simply the first frozen one (soak N38).
        """
        if self.target.inferred_origins:
            if not self._origin_selected:
                return None
            parsed = urllib.parse.urlsplit(str(self.target_url))
            if not parsed.scheme or not parsed.netloc:
                return None
            return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}", parsed.scheme.lower()
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
        # Content discovery requests the same curated paths, so a seed that answered
        # is also a discovered endpoint; probing it twice would spend a request on a
        # body this batch has already classified.
        seed_urls = {f"{base_origin}{path}" for path in SENSITIVE_SEED_PATHS}
        window = endpoints.entries[start:min(len(endpoints.entries), start + count)]
        for entry in window:
            try:
                url = execution_url_for_endpoint(entry)
            except (ScanWorkManifestError, KeyError):
                continue
            if url in seed_urls or is_never_requested(url):
                continue
            probes.append((url, "discovered_endpoint"))

        # Content disclosure is often served by middleware that overstates
        # Content-Length or closes mid-body (a directory index is the common
        # case); keep the bytes already received so a real disclosure on a
        # badly-framed response is still classified rather than dropped.
        # The probes target key files, dumps and environment files on purpose, so the
        # archived bodies are kept out of masked views even though no principal is sent.
        transport = self._scan_replay_transport(
            action, principal_slot="anonymous", private=True,
            tolerate_incomplete_body=True,
        )
        started_at = datetime.now(timezone.utc).isoformat()
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        consumed = {name: 0 for name in action.requested_budget}
        http_ceiling = int(action.requested_budget.get("http_requests") or 0)
        wall_ceiling = max(1, int(action.requested_budget.get("tool_wall_seconds") or 1))
        attempted = resumed = 0
        # Directory-listing follow-up is bounded independently of the sweep so a
        # browsable directory can never starve the probe list that found it.
        follow_up_ceiling = max(DIRECTORY_FOLLOW_UP_FLOOR, http_ceiling // 10)
        follow_up_spent = 0
        # A host that answers every path with the same 200 body would make one
        # lucky body match "prove" every seed. Paths that cannot exist are read the
        # first time a signature matches, and a match whose body is byte-identical
        # to the host's answer for an absent path is not specific to that path.
        absent_bodies: set[str] | None = None
        indistinguishable = 0

        # Every probe waits a realistic time sized from the latency this batch measured, never
        # past the batch's own wall (soak N37: wall / allowance gave /.env 0.86 s).
        wall_deadline = time.monotonic() + wall_ceiling
        measured_ms: list[int] = []
        stopped_by_wall = False

        def remaining_wall() -> float:
            return wall_deadline - time.monotonic()

        def timed_out(result: Any) -> bool:
            return result.status_code is None and (
                bool(getattr(result, "timed_out", False))
                or str(result.error_code or "").lower() == "timeout"
            )

        async def probe(url: str, ordinal: int, *, retry: bool = False) -> Any:
            nonlocal consumed
            request = ReplayRequest(
                request_id=f"exposure:{ordinal}", ordinal=ordinal,
                name="exposure probe", folder="", method="GET", url=url,
                headers=(), body=b"", body_mode="none",
                auth_type="none", has_sensitive_material=False,
            )
            result = await transport.send(
                request, target=self.target,
                timeout_seconds=exposure_probe_timeout(
                    measured_ms=measured_ms, remaining_wall_seconds=remaining_wall(),
                    retry=retry,
                ),
                follow_redirects=False,
            )
            consumed["http_requests"] = min(
                http_ceiling, consumed["http_requests"] + 1,
            )
            if result.status_code is not None and int(result.elapsed_ms or 0) > 0:
                measured_ms.append(int(result.elapsed_ms))
            await heartbeat()
            return result

        def can_start() -> bool:
            nonlocal stopped_by_wall
            if remaining_wall() < EXPOSURE_PROBE_MIN_START_SECONDS:
                stopped_by_wall = True
                return False
            return True

        async def settle(
            probe_url: str, discovered_via: str, attempt_id: str, result: Any,
        ) -> None:
            nonlocal ordinal, absent_bodies, indistinguishable, follow_up_spent, attempted
            if result.error_code:
                errors.append(str(result.error_code))
            # Classification parses up to a megabyte of hostile content: it runs off the
            # event loop so heartbeats and cancellation keep working while it does.
            signature = await asyncio.to_thread(
                functools.partial(
                    classify_exposure, path=probe_url, status=result.status_code or 0,
                    headers=result.response_headers, body=result.response_body,
                ),
            )
            if signature is not None:
                if absent_bodies is None:
                    absent_bodies = set()
                    for control in negative_control_entries(
                        SOFT_404_CONTROL_COUNT, seed=action.action_id,
                    ):
                        if (
                            self.cancelled() or consumed["http_requests"] >= http_ceiling
                            or not can_start()
                        ):
                            break
                        ordinal += 1
                        answer = await probe(f"{base_origin}/{control}", ordinal)
                        if answer.status_code == 200 and answer.response_body:
                            absent_bodies.add(hashlib.sha256(answer.response_body).hexdigest())
                if hashlib.sha256(result.response_body).hexdigest() in absent_bodies:
                    indistinguishable += 1
                    signature = None
            attempt_observations: list[Mapping[str, Any]] = []
            if signature is not None:
                attempt_observations.append(await asyncio.to_thread(
                    _exposure_observation, probe_url, discovered_via, signature, result,
                ))
                # A listing is metadata, not proof that children are confidential.
                # Existing bounded follow-up still records content observations.
                if (
                    signature.exposure_class == "directory_listing"
                    and consumed["http_requests"] < http_ceiling
                ):
                    links = await asyncio.to_thread(
                        functools.partial(
                            directory_listing_links, result.response_body, limit=10,
                        ),
                    )
                    for link in links:
                        if (
                            self.cancelled() or consumed["http_requests"] >= http_ceiling
                            or not can_start()
                        ):
                            break
                        # Follow-up gets a small fixed share of the batch, not
                        # whatever the primary sweep has not spent yet. Letting
                        # it borrow against the remainder drained the ceiling on
                        # one directory's children and abandoned the rest of the
                        # sweep, costing this batch /ftp and /metrics.
                        if follow_up_spent >= follow_up_ceiling:
                            break
                        follow_up_spent += 1
                        child_url = _directory_listing_child_url(probe_url, link)
                        if urllib.parse.urlsplit(child_url).netloc != \
                                urllib.parse.urlsplit(probe_url).netloc:
                            continue
                        ordinal += 1
                        child = await probe(child_url, ordinal)
                        child_signature = await asyncio.to_thread(
                            functools.partial(
                                classify_confidential_file, path=child_url,
                                status=child.status_code or 0,
                                headers=child.response_headers, body=child.response_body,
                            ),
                        )
                        if child_signature is not None:
                            attempt_observations.append(await asyncio.to_thread(
                                _exposure_observation, child_url, "directory_listing_follow",
                                child_signature, child,
                            ))
            proven = any(item.get("proof_state") == "verified" for item in attempt_observations)
            bundled = ({
                "kind": "candidate_attempt", "attempt_id": attempt_id,
                "candidate_id": attempt_id[:32], "family": "sensitive_exposure",
                "status": "success", "proof_state": (
                    "verified" if proven else "not_proven"
                ),
                "budget_consumed": {"http_requests": 1},
            }, *attempt_observations)
            attempt = {
                "attempt_id": attempt_id, "candidate_id": attempt_id[:32],
                "status": "success", "budget_consumed": {"http_requests": 1},
                "observations": bundled,
                "proof_state": "verified" if proven else "not_proven",
            }
            if not self.cancelled():
                await checkpoint_attempt(action.action_id, attempt)
            attempted += 1
            observations.extend(bundled)

        # A probe that timed out is never recorded as examined: it is retried once, after the
        # sweep, with the ceiling (or what the wall has left).
        deferred: list[tuple[str, str, str, float]] = []
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
            if (
                self.cancelled() or consumed["http_requests"] >= http_ceiling
                or not can_start()
            ):
                break
            ordinal += 1
            waited = exposure_probe_timeout(
                measured_ms=measured_ms, remaining_wall_seconds=remaining_wall(),
            )
            result = await probe(probe_url, ordinal)
            if timed_out(result):
                deferred.append((probe_url, discovered_via, attempt_id, waited))
                continue
            await settle(probe_url, discovered_via, attempt_id, result)
        slow_probes: list[Mapping[str, Any]] = []
        for probe_url, discovered_via, attempt_id, waited in deferred:
            retry_wait = 0.0
            if (
                not self.cancelled() and consumed["http_requests"] < http_ceiling
                and can_start()
            ):
                ordinal += 1
                retry_wait = exposure_probe_timeout(
                    measured_ms=measured_ms, remaining_wall_seconds=remaining_wall(),
                    retry=True,
                )
                result = await probe(probe_url, ordinal, retry=True)
                if not timed_out(result):
                    await settle(probe_url, discovered_via, attempt_id, result)
                    continue
            # Still unanswered: a coverage gap named by its path, never "not proven". It is not
            # checkpointed, so a resumed batch probes it again.
            attempted += 1
            observations.append({
                "kind": "candidate_attempt", "attempt_id": attempt_id,
                "candidate_id": attempt_id[:32], "family": "sensitive_exposure",
                "status": "timed_out", "proof_state": "unproven",
                "budget_consumed": {"http_requests": 2 if retry_wait else 1},
            })
            slow_probes.append({
                "kind": "exposure_probe_timeout", "candidate_id": attempt_id[:32],
                "url": redact_url(probe_url), "discovered_via": discovered_via,
                "first_timeout_seconds": round(waited, 2),
                "retry_timeout_seconds": round(retry_wait, 2) if retry_wait else None,
            })
        observations.extend(slow_probes)
        unattempted = max(0, len(probes) - attempted)
        consumed["tool_wall_seconds"] = min(
            wall_ceiling, max(1, len(probes)),
        ) if "tool_wall_seconds" in consumed else consumed.get("tool_wall_seconds", 0)
        partial = bool(unattempted or slow_probes)
        batch_errors = list(errors[:20])
        if unattempted and stopped_by_wall:
            # The batch's own wall ran out with probes left: a real timeout.
            batch_errors.insert(0, CapabilityResultReason.TIMED_OUT.value)
        elif slow_probes and not unattempted:
            # Every probe ran; the only gap is the named probes no retry could get an answer for.
            batch_errors.insert(0, CapabilityResultReason.SLOW_ENDPOINTS.value)
        return self._receipt(
            action, status="partial" if partial else "success",
            parser_version=EXPOSURE_PROBE_PARSER_VERSION,
            started_at=started_at, observations=tuple(observations),
            errors=tuple(batch_errors[:21]), consumed=consumed,
            partial=partial, timed_out=bool(unattempted and stopped_by_wall),
            redacted_execution={
                "action_id": action.action_id, "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "probe_count": len(probes), "attempted_count": attempted,
                "resumed_count": resumed, "unattempted_count": unattempted,
                "retried_count": len(deferred), "timed_out_count": len(slow_probes),
                "indistinguishable_from_absent": indistinguishable,
                "soft_404_controls_requested": absent_bodies is not None,
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
            return self._skip(action, self._empty_slice_reason(manifest))
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
        attempt_statuses: list[Mapping[str, Any]] = []
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=action.capability_name,
        )
        for offset, (manifest_index, candidate) in enumerate(rows):
            candidate_id = str(candidate.get("candidate_id") or "")
            # A fragment-located candidate (family_hints: ["xss"]) never reaches the
            # server, so its parameter is absent from the server query/body and the
            # NoSQL differential would search for a parameter that does not exist and
            # block. It belongs to the browser XSS proof; skip it here.
            if candidate.get("browser_fragment_path"):
                continue
            # A path segment is not a NoSQL operator-injection site (no field to replace with an
            # operator object); skip it here, it belongs to the SQLi verifier.
            if candidate.get("parameter_location") == "path":
                continue
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:nosqli:{candidate_id}".encode()
            ).hexdigest()
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                attempt_statuses.append(prior)
                observations.extend(prior.get("observations") or ())
                for name, amount in dict(prior.get("budget_consumed") or {}).items():
                    consumed[name] = consumed.get(name, 0) + int(amount)
                continue
            if self.cancelled():
                break
            request_class = str(candidate.get("request_class") or "safe_read")
            proof_candidate = dict(candidate)
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
                proof_candidate = _candidate_for_synthetic_proof(candidate)
                # A body candidate mutates, so it needs the same authority the private
                # request path above demands before it may be replayed.
                if (
                    candidate.get("body_field_names")
                    and not (
                        self.policy.allow_state_changing_http
                        and self.policy.approval_receipt_id
                    )
                ):
                    continue
                request = proof_request_for_candidate(
                    endpoints, manifest, manifest_index,
                    request_id=f"candidate:{candidate_id}",
                    ordinal=manifest_index,
                    name="canonical NoSQLi candidate",
                    headers=tuple(primary.headers().items()),
                    authenticated=primary.authenticated,
                )
                execution_url = request.url
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
                candidate=proof_candidate,
                transport=self._scan_replay_transport(action, private=True),
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
                "status": result.status, "timed_out": bool(result.timed_out),
                "budget_consumed": dict(result.actual_budget),
                "observations": bundled, "errors": tuple(result.errors),
                "proof_state": proof_state,
            }
            if result.status != "cancelled":
                await checkpoint_attempt(action.action_id, attempt)
            attempt_statuses.append({
                "status": str(result.status),
                "timed_out": bool(result.timed_out),
            })
            attempted += 1
            observations.extend(bundled)
            errors.extend(str(item) for item in result.errors)
            for name, amount in result.actual_budget.items():
                consumed[name] = min(
                    int(action.requested_budget.get(name, 0)),
                    consumed.get(name, 0) + int(amount),
                )
        unattempted = max(0, len(rows) - attempted)
        _batch_status, _batch_partial, _batch_timed_out = batch_outcome(
            attempt_statuses, unattempted,
        )
        return self._receipt(
            action, status=_batch_status,
            parser_version=CAPABILITY_REGISTRY.require(action.capability_name).output_schema,
            started_at=started_at, observations=tuple(observations),
            errors=tuple(errors[:20]), consumed=consumed,
            partial=_batch_partial, timed_out=_batch_timed_out,
            redacted_execution={
                "action_id": action.action_id, "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "candidate_count": len(rows), "attempted_count": attempted,
                "resumed_count": resumed, "unattempted_count": unattempted,
                "checkpoint_mode": "after_each_candidate",
                "secret_values_visible": False,
            },
        )

    async def _authz_surface_batch(
        self, action: ScanAction, heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        """Prove BFLA by contrasting anonymous and authenticated route access."""
        endpoints = await self._work_manifest(
            action, "endpoint_manifest_ref", ScanWorkManifestKind.ENDPOINT,
        )
        if endpoints is None:
            return self._skip(action, "manifest_unavailable")
        raw_slice = action.capability_args.get("slice")
        if not isinstance(raw_slice, Mapping):
            raise ScanActionAdapterError("authz surface batch slice is invalid")
        start, count = raw_slice.get("start"), raw_slice.get("count")
        if (
            isinstance(start, bool) or not isinstance(start, int) or start < 0
            or isinstance(count, bool) or not isinstance(count, int)
            or not 1 <= count <= 100
        ):
            raise ScanActionAdapterError("authz surface batch slice is invalid")
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=action.capability_name,
        )
        if not primary.authenticated:
            return self._skip(action, "no_primary_principal")
        load_attempts = getattr(self.backend, "load_batch_attempts", None)
        checkpoint_attempt = getattr(self.backend, "checkpoint_batch_attempt", None)
        if not callable(load_attempts) or not callable(checkpoint_attempt):
            raise ScanActionAdapterError("authz surface backend lacks durable checkpoints")
        completed = {
            str(item.get("attempt_id") or ""): dict(item)
            for item in await load_attempts(action.action_id)
            if isinstance(item, Mapping)
        }
        manifest_digest = endpoints.reference().manifest_digest
        window = tuple(enumerate(
            endpoints.entries[start:min(len(endpoints.entries), start + count)],
            start=start,
        ))
        # Anonymous and primary probes share one transport, so no single slot applies.
        transport = self._scan_replay_transport(action, principal_slot=None, private=True)
        started_at = datetime.now(timezone.utc).isoformat()
        consumed = {name: 0 for name in action.requested_budget}
        http_ceiling = int(action.requested_budget.get("http_requests") or 0)
        wall_ceiling = max(1, int(action.requested_budget.get("tool_wall_seconds") or 1))
        errors: list[str] = []
        attempted = resumed = 0
        attempt_statuses: list[Mapping[str, Any]] = []

        def probe_of(result: Any) -> PrincipalProbe:
            content_type = next((
                str(value).lower() for name, value in result.response_headers.items()
                if str(name).lower() == "content-type"
            ), "")
            return PrincipalProbe(
                status=result.status_code,
                body_sha256=hashlib.sha256(result.response_body).hexdigest(),
                body_len=len(result.response_body),
                is_json="json" in content_type,
                error=bool(result.error_code),
            )

        async def send(url: str, headers: tuple, ordinal: int) -> Any:
            nonlocal consumed
            request = ReplayRequest(
                request_id=f"authz:{ordinal}", ordinal=ordinal,
                name="authz surface probe", folder="", method="GET", url=url,
                headers=headers, body=b"", body_mode="none",
                auth_type="broker_session" if headers else "none",
                has_sensitive_material=bool(headers),
            )
            remaining = max(1, http_ceiling - consumed["http_requests"])
            result = await transport.send(
                request, target=self.target,
                timeout_seconds=max(0.5, min(15.0, wall_ceiling / remaining)),
                follow_redirects=False,
            )
            consumed["http_requests"] = min(http_ceiling, consumed["http_requests"] + 1)
            await heartbeat()
            return result

        comparisons: list[RouteComparison] = []
        primary_headers = tuple(primary.headers().items())
        ordinal = start * 1000
        for manifest_index, entry in window:
            route_id = str(entry.get("route_id") or "")
            attempt_id = hashlib.sha256(
                f"{manifest_digest}:authz_surface:{route_id}".encode()
            ).hexdigest()
            prior = completed.get(attempt_id)
            if prior is not None:
                resumed += 1
                attempted += 1
                attempt_statuses.append(prior)
                comparisons.append(RouteComparison(
                    route_id=route_id, url=str(prior.get("url") or ""),
                    anonymous=tuple(
                        PrincipalProbe(**probe) for probe in prior.get("anonymous") or ()
                    ),
                    authenticated=tuple(
                        PrincipalProbe(**probe) for probe in prior.get("authenticated") or ()
                    ),
                ))
                continue
            if self.cancelled() or consumed["http_requests"] + 4 > http_ceiling:
                break
            try:
                url = execution_url_for_endpoint(entry)
            except (ScanWorkManifestError, KeyError):
                continue
            anon_probes: list[PrincipalProbe] = []
            authed_probes: list[PrincipalProbe] = []
            for _repeat in range(2):
                ordinal += 1
                anon_result = await send(url, (), ordinal)
                if anon_result.error_code:
                    errors.append(str(anon_result.error_code))
                anon_probes.append(probe_of(anon_result))
                ordinal += 1
                authed_result = await send(url, primary_headers, ordinal)
                if authed_result.error_code:
                    errors.append(str(authed_result.error_code))
                authed_probes.append(probe_of(authed_result))
            comparison = RouteComparison(
                route_id=route_id, url=url,
                anonymous=tuple(anon_probes), authenticated=tuple(authed_probes),
            )
            comparisons.append(comparison)
            checkpoint = {
                "attempt_id": attempt_id, "candidate_id": attempt_id[:32],
                # The durable checkpoint contract requires a terminal status.
                # Without it every checkpoint was rejected as invalid, so this
                # family could not complete a single batch and every action it
                # planned failed.
                "status": "success",
                "route_id": route_id, "url": url,
                "anonymous": [vars(probe) for probe in anon_probes],
                "authenticated": [vars(probe) for probe in authed_probes],
                "budget_consumed": {"http_requests": 4},
            }
            if not self.cancelled():
                await checkpoint_attempt(action.action_id, checkpoint)
            # This family's attempts are in-process cross-principal comparisons: there is
            # no external process to be cut off, so the checkpoint's own status is the
            # attempt outcome.
            attempt_statuses.append(checkpoint)
            attempted += 1

        # A finding needs proof the app gates function access somewhere; without an
        # established boundary a fully-public app yields nothing.
        boundary = boundary_established(comparisons)
        observations: list[Mapping[str, Any]] = []
        for comparison in comparisons:
            proven = bfla_finding(comparison) if boundary else None
            observations.append({
                "kind": "candidate_attempt",
                "attempt_id": hashlib.sha256(
                    f"{manifest_digest}:authz_surface:{comparison.route_id}".encode()
                ).hexdigest(),
                "candidate_id": comparison.route_id,
                "family": "authz_surface",
                "status": "success",
                "proof_state": "verified" if proven else "not_proven",
            })
            if proven is not None:
                observations.append(proven)
        unattempted = max(0, len(window) - attempted)
        _batch_status, _batch_partial, _batch_timed_out = batch_outcome(
            attempt_statuses, unattempted,
        )
        return self._receipt(
            action, status=_batch_status,
            parser_version=AUTHZ_SURFACE_PARSER_VERSION,
            started_at=started_at, observations=tuple(observations),
            errors=tuple(errors[:20]), consumed=consumed,
            partial=_batch_partial, timed_out=_batch_timed_out,
            redacted_execution={
                "action_id": action.action_id, "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "route_count": len(window), "attempted_count": attempted,
                "resumed_count": resumed, "unattempted_count": unattempted,
                "boundary_established": boundary,
                "checkpoint_mode": "after_each_route",
                "secret_values_visible": False,
            },
        )

    async def _external(self, action: ScanAction, heartbeat: ActionHeartbeat) -> CapabilityReceipt:
        tool_by_capability = {
            "web.probe": "httpx",
            "web.crawl": "katana",
            "web.browser_crawl": "katana_headless",
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
        requested_budget = dict(action.requested_budget)
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
            if action.capability_name == "templates.scan":
                # Old durable single actions may have no mutation hold even when
                # their policy permits POST. Never enlarge an immutable hold;
                # those actions can still execute the GET/HEAD part of the pack.
                resolved = resolve_active_scan_nuclei_options(
                    template_options,
                    templates_dir=nuclei_templates_directory(),
                    allow_state_changing_http=bool(
                        self.policy.allow_state_changing_http
                        and requested_budget.get("state_changing_requests", 0) > 0
                    ),
                )
                if resolved.skip_reason:
                    return self._skip(action, resolved.skip_reason)
                args.update(resolved.capability_args)
                scanner_options.update(resolved.worker_options)
                # Reuse the same reservation-derived pacing as a batch attempt,
                # including legacy holds smaller than the former fixed profile.
                scanner_options["_batch_attempt"] = True
                if scanner_options["nuclei_active_state_changing"]:
                    # Every emitted request may mutate state. The process ceiling
                    # and mutation settlement must both fit the saved reservation.
                    http = min(
                        int(requested_budget.get("http_requests", 0)),
                        int(requested_budget.get("state_changing_requests", 0)),
                    )
                    requested_budget.update(
                        http_requests=http, state_changing_requests=http,
                    )
            else:
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
            ledger_limits=requested_budget,
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
                "browser_storage": (
                    self.options.get("auth_browser_storage")
                    if tool == "katana_headless" else None
                ),
                "timeout_ms": int(requested_budget.get("tool_wall_seconds") or 1) * 1_000,
                "pinned_address": socket_factory.primary_address,
                "authorized_addresses": list(self.target.allowed_addresses),
                "address_policy": socket_factory.policy_receipt,
                "oob_interactsh_server": None,
                "oob_interactsh_token": None,
            },
            process_runner=self.process_runner,
            requested_budget=requested_budget,
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
        # Fund cheaper candidate classes before expensive body candidates within the slice, so an
        # expensive attempt runs only on the budget cheaper verdicts did not need and can never
        # displace one (R1: see order_batch_rows_by_cost_class). Score order is preserved inside a
        # class; the slice membership is unchanged, only the attempt order within it.
        rows = tuple(order_batch_rows_by_cost_class(
            enumerate(manifest.entries[start:stop], start=start)
        ))
        if not rows:
            return self._skip(action, self._empty_slice_reason(manifest))
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
        # Worker-process options carry the explicit template allowlist and control
        # flags; the schema-validated capability input stays small (the allowlist
        # can exceed the input-schema string ceiling and the control flags are not
        # declared inputs). Default both to the manifest options for passive runs.
        worker_template_options = dict(template_options)
        args_template_options = dict(template_options)
        if tool == "nuclei" and action.capability_name == "templates.active_batch":
            resolved = resolve_active_scan_nuclei_options(
                template_options,
                templates_dir=nuclei_templates_directory(),
                allow_state_changing_http=bool(
                    self.policy.allow_state_changing_http
                    and action.requested_budget.get("state_changing_requests", 0) > 0
                ),
            )
            if resolved.skip_reason:
                # Fail closed: the active selection could not be resolved (index
                # unavailable, or no permitted template once intrusive/non-GET
                # exclusions apply). Record a coverage gap, never a clean result.
                return self._skip(action, resolved.skip_reason)
            worker_template_options = dict(resolved.worker_options)
            args_template_options = dict(resolved.capability_args)
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
        # An extension re-runs only what its slice could not finish: a candidate the extended
        # action already took to a verdict is carried, with no budget and no repeat traffic.
        # A SQLi extension can extend an extension, so every action in the chain is read,
        # nearest first: a candidate settled two rounds back is carried, not re-run.
        extends = str(action.capability_args.get(EXTENDS_ARG) or "")
        lineage_attempts = [
            (source, tuple(await load_attempts(source)))
            for source in extension_lineage(action, self.plan)
        ]
        carried: dict[str, tuple[dict, str]] = {}
        for source, source_attempts in lineage_attempts:
            for finished_id, item in finished_attempts(source_attempts).items():
                if finished_id not in completed and finished_id not in carried:
                    carried[finished_id] = (item, source)
        staged_sources = (
            [(action.action_id, tuple(completed.values())), *lineage_attempts]
            if tool == "sqlmap" else []
        )
        staged_summary = {"stages_run": 0, "stages_carried": 0, "stages_unfinished": 0}
        # The most wall one continuation round can grant this lane: a candidate whose next
        # technique stage is predicted to need more is inconclusive for budget, not extended.
        round_wall_ceiling = (
            lane_round_wall_ceiling(self.options.get("scan_execution_plan"))
            if tool == "sqlmap" else None
        )
        # A continuation round names each extension's fair part of what the Scan has left; a
        # technique whose remaining units need more is inconclusive for budget (soak N55).
        raw_share = action.capability_args.get(SCAN_WALL_SHARE_ARG)
        scan_wall_share = (
            int(raw_share) if isinstance(raw_share, int) and not isinstance(raw_share, bool)
            and raw_share > 0 and tool == "sqlmap" else None
        )
        # A passive continuation slice carries the routes the required admission pack
        # already examined (the frozen origin and admitted seeds) instead of re-sending
        # the pack to them. The manifests differ, so route identity is the key.
        admission_source = admission_template_source(action, self.plan)
        admitted = finished_attempts(
            await load_attempts(admission_source) if admission_source else (),
            key="candidate_id",
        )
        carried_count = 0
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
        inapplicable = 0
        terminal_failure = False
        attempt_timed_out = False
        # The non-time dimensions that stopped an attempt (the pinned transport refused
        # traffic past the request ceiling) or left a candidate unfundable.
        ceiling_stops: set[str] = set()
        exhausted: set[str] = set()
        stopped_by_cancel = False
        primary = resolve_scan_http_principal(
            self.options, lane="primary", capability_name=legacy_capability,
        )
        # A template sweep attempt that hits its wall before the tool reported anything examined
        # nothing: on a CPU- or network-starved host every endpoint of a slice could die that way
        # and the batch reported zero findings with every candidate "attempted". Such an endpoint
        # gets one retry after the first pass, funded only by what this reservation has left and
        # only when that share is larger than the one it timed out on; an endpoint that still
        # produced nothing is reported as unexamined. Shares in the first pass are unchanged.
        retry_empty_timeouts = tool == "nuclei"
        # The passive pack is seven read-only GETs, so an endpoint the wall cut off part-way is
        # retried too: a pack that sent some of its templates did not examine the endpoint.
        # Soak e5264021 left 5 of 28 attempts on honey's AI endpoints wall-killed at ~12 s with
        # 45 s of the batch's wall unspent, because only an attempt with no output was retried.
        # The first attempt is the latency measurement: an endpoint that did not finish the
        # pack inside its share needs the pack's latency bound (template_retry_wall), and its
        # retry holds that much of what the batch has left.
        retry_partial_timeouts = action.capability_name == "templates.passive_batch"
        empty_timeouts: dict[str, int] = {}
        # The first attempt each retried endpoint was cut off in, and the redacted URL each
        # endpoint was attempted at, so an endpoint that never finished can be named.
        cut_off_attempts: dict[str, str] = {}
        endpoint_urls: dict[str, str] = {}
        retry_walls: dict[str, int] = {}
        retried_with_output: set[str] = set()
        # The wall each finished first-pass template attempt took: the target's measured pack
        # latency, which sizes what later attempts are reserved (template_attempt_wall).
        finished_walls: list[int] = []
        deferred_errors: dict[str, list[str]] = {}
        still_empty: set[str] = set()
        recovered: set[str] = set()
        retried = 0
        attempt_log: list[tuple[str, int, bool, bool]] = []
        work = [(manifest_index, row, 0) for manifest_index, row in rows]
        first_pass = len(work)
        position = 0
        # SQLi candidates of one slice may run concurrently, inside the slice's reservation and
        # its pacing contract (see sqli_concurrency). Only a process runner that enforces the
        # shared request gate in its pinned transport may run more than one; a plan compiled
        # without the bound runs one candidate at a time, exactly as before.
        concurrency_bound = (
            int(action.capability_args.get(CANDIDATE_CONCURRENCY_ARG) or 1)
            if tool == "sqlmap"
            and getattr(self.process_runner, "enforces_request_gate", False) is True
            else 1
        )
        rate_ceiling = slice_rate_ceiling(
            action.requested_budget,
            candidates=len(rows),
            floors=[
                batch_attempt_floor(action.capability_name, body_candidate=bool(cost_class))
                for cost_class in sorted({batch_row_cost_class(row) for _, row in rows})
            ],
        )
        request_gate = (
            RequestRateGate(rate_ceiling) if concurrency_bound > 1 and rate_ceiling > 0 else None
        )
        candidates = ConcurrentCandidates(
            action.requested_budget,
            bound=concurrency_bound if request_gate is not None else 1,
            rate_ceiling=rate_ceiling,
            # The latest response time any candidate measured on this target.
            latency_seconds=(
                prior_stages(staged_sources, "").latency_seconds if tool == "sqlmap" else None
            ),
        )
        concurrent = request_gate is not None
        # Tool wall a concurrent slice is charged: what resumed attempts already spent, plus the
        # elapsed time in which any of its candidates ran -- never each process's seconds summed
        # (soak N40; see sqli_concurrency). A slice that runs one candidate at a time is charged
        # each attempt's wall, which is the same thing.
        resumed_wall = 0

        def charge_wall() -> None:
            if not concurrent or "tool_wall_seconds" not in consumed:
                return
            consumed["tool_wall_seconds"] = min(
                int(action.requested_budget.get("tool_wall_seconds", 0)),
                resumed_wall + math.ceil(candidates.busy_seconds()),
            )

        async def settle_attempt(row: Mapping[str, Any], result: Any, sink: list[Any]) -> None:
            """Count one finished attempt exactly once.

            Nothing is awaited after its consumption is counted, so a concurrent candidate's
            hold (sqli_concurrency.ConcurrentCandidates) returns in the same step.
            """
            nonlocal attempted, retried, terminal_failure, attempt_timed_out, ceiling_stops
            nonlocal stopped_by_cancel
            attempt_id = str(row["attempt_id"])
            candidate_id = str(row["candidate_id"])
            retry_round = int(row["retry_round"])
            execution_target = str(row["execution_target"])
            body_request = dict(row["body_request"])
            sub_budget = dict(row["sub_budget"])
            if tool == "sqlmap":
                for stage in result.stages:
                    key = (
                        "stages_carried" if stage["outcome"] == "carried"
                        else "stages_run" if stage["outcome"] in _BATCH_SUCCESS_STATUSES
                        else "stages_unfinished"
                    )
                    staged_summary[key] += 1
            attempt_observations = tuple({
                # The tool parsers read the tool's own output, which names the vulnerable parameter
                # but not the endpoint. Without the locus a finding has no route, so it cannot be
                # matched to an expectation, routed to a verifier (an unresolved route abstains by
                # design), or acted on by an operator. The adapter resolved the request, so it
                # supplies what the parser cannot -- and never overwrites a locus the parser set.
                "url": execution_target,
                "method": body_request.get("method", "GET"),
                **dict(item), "attempt_id": attempt_id, "candidate_id": candidate_id,
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
                    **({"retry_round": retry_round} if retry_round else {}),
                    # An unfinished SQLi candidate names the least wall its next attempt needs:
                    # its unfinished stage's checkpoint, never less than the attempt floor. The
                    # extension planner sizes the next round from this (audit S002).
                    # A measured SQLi candidate names its next unit's own wall (sqli_stages).
                    **({"resume_wall_seconds": max(
                        int(result.resume_wall_seconds),
                        0 if getattr(result, "seconds_per_request", None) else int(
                            batch_attempt_floor(
                                action.capability_name, body_candidate=bool(body_request),
                            ).get("tool_wall_seconds", 0)
                        ),
                    )} if getattr(result, "resume_wall_seconds", None) else {}),
                    **(_staged_resume_fields(result) if tool == "sqlmap" else {}),
                },
                *attempt_observations,
            )
            if tool == "sqlmap":
                verdict = _budget_verdict(
                    result, candidate_id=candidate_id, ceiling=round_wall_ceiling,
                    fields=row.get("sqli_fields"),
                    scan_wall_share=scan_wall_share,
                )
                if verdict is not None:
                    # Techniques no budget can fund are named on the candidate's record, so it
                    # does not read as a slice that merely ran out of time. The candidate is
                    # inconclusive overall only once nothing fundable is left.
                    head = dict(attempt_observations[0])
                    head["inconclusive_techniques"] = list(verdict["unfundable_techniques"])
                    if verdict["closed"]:
                        head.update({"verdict": "inconclusive", "inconclusive_reason": "budget"})
                        head.pop("resume_wall_seconds", None)
                    attempt_observations = (
                        head,
                        *attempt_observations[1:],
                        {"url": redact_url(execution_target),
                         "method": body_request.get("method", "GET"), **verdict},
                    )
            attempt = {
                "attempt_id": attempt_id,
                "candidate_id": candidate_id,
                "status": result.status,
                "timed_out": bool(result.timed_out),
                "budget_consumed": dict(result.actual_budget),
                "observations": attempt_observations,
                "errors": tuple(result.errors),
                "proof_state": proof_state,
            }
            if result.status != "cancelled":
                await checkpoint_attempt(action.action_id, attempt)
            if retry_round:
                retried += 1
                if result.observations:
                    retried_with_output.add(candidate_id)
            else:
                attempted += 1
            sink.extend(attempt_observations)
            result_timed_out = (
                result.status in {"timed_out", "partial"}
                or bool(getattr(result, "timed_out", False))
            )
            result_wall_killed = (
                bool(getattr(result, "timed_out", False)) or result.status == "timed_out"
            )
            needs_retry = retry_empty_timeouts and result_timed_out and (
                not result.observations or (retry_partial_timeouts and result_wall_killed)
            )
            if needs_retry and not retry_round:
                cut_off_attempts[candidate_id] = attempt_id
            if (
                not retry_round and result.status in _BATCH_SUCCESS_STATUSES
                and int(result.actual_budget.get("tool_wall_seconds", 0) or 0) > 0
            ):
                finished_walls.append(int(result.actual_budget["tool_wall_seconds"]))
            self._settle_template_attempt(
                candidate_id, retry_round,
                needs_retry,
                succeeded=result.status in _BATCH_SUCCESS_STATUSES,
                granted_wall=int(sub_budget.get("tool_wall_seconds", 0)),
                attempt_errors=[str(item) for item in result.errors],
                errors=errors, empty_timeouts=empty_timeouts,
                deferred_errors=deferred_errors, still_empty=still_empty,
                recovered=recovered,
            )
            wall_killed = bool(getattr(result, "timed_out", False)) or result.status == "timed_out"
            ceiling_stops |= attempt_ceiling_stops(result.errors)
            attempt_log.append((
                candidate_id, retry_round,
                result.status in _BATCH_SUCCESS_STATUSES, wall_killed,
            ))
            for name, amount in result.actual_budget.items():
                if concurrent and name in ELAPSED_DIMENSIONS:
                    continue
                consumed[name] = min(
                    int(action.requested_budget.get(name, 0)),
                    consumed.get(name, 0) + int(amount),
                )
            charge_wall()
            # Any attempt that did not succeed counts. A timed-out external tool is
            # normalized to "partial" upstream, and "partial" was absent from this set --
            # so a batch in which every single attempt timed out, with every candidate
            # started, aggregated to unattempted=0, terminal_failure=False and reported
            # `success` with `timed_out=False`. That is how a family showed complete
            # coverage while proving nothing at all.
            if result.status not in {"success", "succeeded", "completed"}:
                terminal_failure = True
            if wall_killed:
                attempt_timed_out = True
            if result.status == "cancelled":
                stopped_by_cancel = True

        async def fail_attempt(
            attempt_id: str, candidate_id: str, retry_round: int, exc: BaseException,
        ) -> None:
            nonlocal attempted, retried, terminal_failure
            # One candidate that raises anywhere in its setup or execution must never fail the
            # whole batch action. execution_request_for_manifest_candidate and the external
            # capability preparation raise ValueError/ScanWorkManifestError on a candidate the
            # manifest shift left unresolvable; without this the orchestrator failed the entire
            # verify.sqli / verify.xss action, so every other candidate -- sqli-search included
            # -- lost its verdict and the family read as gapped. Record this candidate as a
            # failed attempt (checkpointed, counted) and continue to the next one.
            failed_attempt = {
                "attempt_id": attempt_id,
                "candidate_id": candidate_id,
                "status": "failed",
                "timed_out": False,
                "budget_consumed": {},
                "observations": (),
                "errors": (f"candidate_failed:{type(exc).__name__}",),
                "proof_state": "not_proven",
            }
            try:
                await checkpoint_attempt(action.action_id, failed_attempt)
            except Exception:
                pass
            if retry_round:
                retried += 1
                still_empty.discard(candidate_id)
            else:
                attempted += 1
            terminal_failure = True
            attempt_log.append((candidate_id, retry_round, False, False))
            errors.append(f"candidate_failed:{type(exc).__name__}")

        try:
            while True:
                if position >= len(work):
                    if position != first_pass or not still_empty:
                        break
                    if self.cancelled():
                        stopped_by_cancel = True
                        break
                    work.extend(
                        (manifest_index, row, 1) for manifest_index, row in rows
                        if _batch_candidate_id(row, manifest_index) in still_empty
                    )
                    if position >= len(work):
                        break
                manifest_index, row, retry_round = work[position]
                position += 1
                # A path-segment candidate (family_hints: ["sqli"]) carries the sqlmap ``*`` marker in
                # its URL; only the SQLi verifier understands it. Dalfox and the template sweeps would
                # test the literal ``*`` as a value, so they skip it. The skip is recorded and kept
                # out of the unattempted count: counting it there reported the slice partial for
                # "insufficient_plan_budget" over a candidate no budget could have made testable,
                # and that false gap failed the family's coverage.
                if row.get("parameter_location") == "path" and family != "sqli":
                    inapplicable += 1
                    observations.append({
                        "kind": "candidate_inapplicable",
                        "candidate_id": str(row.get("candidate_id") or row.get("route_id") or ""),
                        "family": family,
                        "reason": "path_segment_candidate",
                    })
                    continue
                candidate_id = _batch_candidate_id(row, manifest_index)
                attempt_key = f"{manifest_digest}:{family}:{candidate_id}"
                if retry_round:
                    attempt_key += f":retry:{retry_round}"
                attempt_id = hashlib.sha256(attempt_key.encode()).hexdigest()
                route_identity = str(row.get("candidate_id") or row.get("route_id") or "")
                carry = None if retry_round or attempt_id in completed else (
                    carried[attempt_id] if attempt_id in carried
                    else (admitted[route_identity], admission_source)
                    if route_identity and route_identity in admitted else None
                )
                if carry is not None:
                    carried_count += 1
                    attempted += 1
                    observations.extend(carried_records(carry[0], source=str(carry[1])))
                    attempt_log.append((candidate_id, 0, True, False))
                    continue
                prior = completed.get(attempt_id)
                if prior is not None:
                    resumed += 1
                    if retry_round:
                        retried += 1
                    else:
                        attempted += 1
                    # A resumed attempt keeps the outcome its checkpoint recorded. Counting it
                    # as merely "attempted" let a restart launder failure into success: every
                    # attempt of a wall-killed batch is checkpointed, so replaying them all
                    # produced terminal_failure=False, timed_out=False, unattempted=0 -- a
                    # clean success receipt for a batch that had proven nothing.
                    prior_status = str(prior.get("status") or "success")
                    if prior_status not in {"success", "succeeded", "completed"}:
                        terminal_failure = True
                    # Only a wall-killed attempt timed out; partial is not a timeout.
                    prior_wall_killed = bool(prior.get("timed_out")) or prior_status == "timed_out"
                    if prior_wall_killed:
                        attempt_timed_out = True
                    ceiling_stops |= attempt_ceiling_stops(prior.get("errors") or ())
                    observations.extend(prior.get("observations") or ())
                    prior_timed_out = (
                        prior_status in {"timed_out", "partial"} or bool(prior.get("timed_out"))
                    )
                    prior_empty = retry_empty_timeouts and prior_timed_out and (
                        _no_tool_output(prior.get("observations") or ())
                        or (retry_partial_timeouts and prior_wall_killed)
                    )
                    if prior_empty and not retry_round:
                        cut_off_attempts[candidate_id] = attempt_id
                    if retry_round and not _no_tool_output(prior.get("observations") or ()):
                        retried_with_output.add(candidate_id)
                    prior_wall = int(dict(prior.get("budget_consumed") or {}).get(
                        "tool_wall_seconds", 0,
                    ) or 0)
                    if not retry_round and prior_status in _BATCH_SUCCESS_STATUSES and prior_wall > 0:
                        finished_walls.append(prior_wall)
                    self._settle_template_attempt(
                        candidate_id, retry_round, prior_empty,
                        succeeded=prior_status in _BATCH_SUCCESS_STATUSES,
                        granted_wall=int(dict(prior.get("budget_consumed") or {}).get(
                            "tool_wall_seconds", 0,
                        )),
                        attempt_errors=[str(item) for item in prior.get("errors") or ()],
                        errors=errors, empty_timeouts=empty_timeouts,
                        deferred_errors=deferred_errors, still_empty=still_empty,
                        recovered=recovered,
                    )
                    attempt_log.append((
                        candidate_id, retry_round,
                        prior_status in _BATCH_SUCCESS_STATUSES, prior_wall_killed,
                    ))
                    for name, amount in dict(prior.get("budget_consumed") or {}).items():
                        consumed[name] = consumed.get(name, 0) + int(amount)
                        if name in ELAPSED_DIMENSIONS:
                            resumed_wall += int(amount)
                    charge_wall()
                    if str(prior.get("status") or "") not in _BATCH_SUCCESS_STATUSES:
                        terminal_failure = True
                    continue
                if concurrent:
                    # Wait for a free slot first: this candidate's hold is carved from what the
                    # running ones have neither consumed nor been lent.
                    while candidates.running and candidates.running >= candidates.slots():
                        await candidates.wait()
                if stopped_by_cancel or self.cancelled():
                    stopped_by_cancel = True
                    break
                try:
                    body_request: dict[str, Any] = {}
                    if manifest_kind is ScanWorkManifestKind.CANDIDATE:
                        # A body candidate is not describable by a URL, so resolve the whole request and
                        # keep the body shape for the tool. A query candidate resolves to a bare URL
                        # exactly as before.
                        resolved = execution_request_for_manifest_candidate(
                            endpoints, manifest, manifest_index,
                        )
                        execution_target = str(resolved["url"])
                        if resolved.get("body_field_names"):
                            body_request = {
                                "method": str(resolved["method"]),
                                "content_type": resolved.get("content_type"),
                                "body_field_names": list(resolved["body_field_names"]),
                                "injection_field": str(resolved["field_name"]),
                            }
                    else:
                        execution_target = execution_url_for_manifest_endpoint(
                            manifest, manifest_index,
                        )
                    remaining_attempts = max(1, len(work) - position + 1)
                    # What the slice has neither consumed nor lent to a running candidate.
                    charge_wall()
                    remaining_budget = candidates.holds.available(consumed)
                    # Candidates that run in the same turn share the same seconds, so the
                    # wall left is split across turns, not across candidates.
                    wall_shares = (
                        candidates.wall_shares(remaining_attempts) if concurrent
                        else remaining_attempts
                    )
                    # Never divide the reservation below what one attempt needs to
                    # reach a verdict. An even split gave each of thirteen candidates
                    # twelve seconds of sqlmap, so every attempt returned unproven and
                    # the family spent its whole budget proving nothing. The manifest is
                    # ranked, so funding the top of it and reporting the remainder as
                    # unattempted is strictly more useful than diluting all of it.
                    floor = batch_attempt_floor(
                        action.capability_name, body_candidate=bool(body_request),
                    )
                    if tool == "sqlmap" and staged_sources:
                        # A resumed SQLi candidate runs one unit at a time; once its rate is
                        # measured, its wall floor is what its next unit needs, not the
                        # whole-candidate attempt floor (soak N55 review).
                        early_fields, early_count = _sqli_fields(execution_target, body_request)
                        early_prior = prior_stages(staged_sources, attempt_id, fields=early_fields)
                        early = prior_resume(
                            early_prior, fields=early_fields, field_count=early_count,
                            round_wall_ceiling=round_wall_ceiling,
                            scan_wall_share=scan_wall_share,
                        )
                        if early_prior.rate_samples and early.wall_seconds:
                            floor["tool_wall_seconds"] = min(
                                int(floor.get("tool_wall_seconds", 0)), int(early.wall_seconds),
                            )
                    # Check the floor against what is actually left before building the
                    # slice: a dimension that has run out is absent from the slice
                    # entirely, so testing only the dimensions present would let an
                    # unfundable attempt through and fail it downstream instead.
                    unfundable = {
                        name for name, amount in floor.items()
                        if remaining_budget.get(name, 0) < amount
                    }
                    if unfundable:
                        if candidates.running:
                            # A running candidate may return part of its hold when it settles.
                            position -= 1
                            await candidates.wait()
                            continue
                        # Candidate cost classes can be mixed. An expensive body entry
                        # must not suppress a later fundable query entry in the same
                        # immutable slice.
                        exhausted |= unfundable
                        continue
                    sub_budget = {
                        name: max(1, floor.get(name, 1), amount // (
                            wall_shares if name in ELAPSED_DIMENSIONS else remaining_attempts
                        ))
                        for name, amount in remaining_budget.items() if amount > 0
                    }
                    if tool == "nuclei" and sub_budget.get("tool_wall_seconds"):
                        planned_share = (
                            int(action.requested_budget.get("tool_wall_seconds") or 0)
                            // max(1, first_pass)
                        )
                        passive_pack = action.capability_name == "templates.passive_batch"
                        sub_budget["tool_wall_seconds"] = (
                            template_retry_wall(
                                remaining_wall=remaining_budget["tool_wall_seconds"],
                                planned_share=planned_share,
                                passive_pack=passive_pack,
                            )
                            if retry_round else
                            template_attempt_wall(
                                remaining_wall=remaining_budget["tool_wall_seconds"],
                                remaining_attempts=remaining_attempts,
                                planned_share=planned_share,
                                passive_pack=passive_pack,
                                measured_wall=(
                                    statistics.median_low(finished_walls) if finished_walls else None
                                ),
                            )
                        )
                    if body_request:
                        # Every request a body attempt sends is a mutation, so the body scanner
                        # requires state_changing_requests >= http_requests (capabilities/scanner.py).
                        # The slice scales http_requests up with the abundant HTTP budget while the
                        # state-changing budget stays near its floor, which left http > state_changing
                        # and raised "body scanner requires a conservative state-changing reservation"
                        # -- crashing the whole verify.sqli/verify.xss action. Bind the two: a body
                        # attempt's HTTP reservation equals its state-changing reservation.
                        state_changing = int(sub_budget.get("state_changing_requests", 0))
                        if state_changing > 0:
                            sub_budget["http_requests"] = min(
                                int(sub_budget.get("http_requests", 0)), state_changing,
                            )
                    elif tool == "nuclei" and worker_template_options.get(
                        "nuclei_active_state_changing"
                    ):
                        # Active Nuclei runs non-GET templates: conservatively every
                        # request it sends may be a mutation, so bind the state-changing
                        # reservation to the HTTP reservation exactly as a body attempt
                        # does, so the adapter can settle it against requests sent.
                        state_changing = int(sub_budget.get("state_changing_requests", 0))
                        if state_changing > 0:
                            sub_budget["http_requests"] = min(
                                int(sub_budget.get("http_requests", 0)), state_changing,
                            )
                            sub_budget["state_changing_requests"] = int(
                                sub_budget["http_requests"]
                            )
                    # sqlmap runs each technique over every field it is handed (``-p``); a body
                    # with several is verified one field per run (sqli_stages).
                    sqli_fields, field_count = _sqli_fields(execution_target, body_request)
                    candidate_prior = (
                        prior_stages(staged_sources, attempt_id, fields=sqli_fields)
                        if tool == "sqlmap" else None
                    )
                    candidate_resume = (
                        prior_resume(
                            candidate_prior, fields=sqli_fields, field_count=field_count,
                            round_wall_ceiling=round_wall_ceiling,
                            scan_wall_share=scan_wall_share,
                        )
                        if candidate_prior is not None else None
                    )
                    stage_need = (
                        candidate_resume.wall_seconds if candidate_resume is not None else None
                    )
                    if (
                        candidate_resume is not None and candidate_resume.budget_inconclusive
                        and stage_need is None
                    ):
                        # Nothing it still has to run is fundable: inconclusive for budget, and
                        # not funded again (soak N55).
                        observations.append({
                            "kind": "candidate_deferred",
                            "candidate_id": candidate_id,
                            "family": family,
                            "reason": "budget_inconclusive",
                            "verdict": "inconclusive",
                        })
                        observations.extend(_deferred_budget_verdict(
                            candidate_resume, candidate_prior, closed=True,
                            candidate_id=candidate_id, fields=sqli_fields,
                            field_count=field_count, ceiling=round_wall_ceiling,
                            scan_wall_share=scan_wall_share, execution_target=execution_target,
                            method=body_request.get("method", "GET"),
                        ))
                        continue
                    if stage_need is not None and sub_budget.get("tool_wall_seconds"):
                        # A resumed candidate re-runs its unfinished stage only on a hold
                        # strictly larger than any it ran out of (audit S002). Fund that from
                        # what the slice has left; if the slice cannot, defer the candidate
                        # before any traffic instead of dispatching a guaranteed no-op. What
                        # this action already spent on the candidate counts against the hold.
                        stage_need = max(stage_need, int(floor.get("tool_wall_seconds", 0)))
                        own_spent = int(candidate_prior.spent.get(action.action_id, {}).get(
                            "tool_wall_seconds", 0,
                        ))
                        available = int(remaining_budget.get("tool_wall_seconds", 0))
                        if available < stage_need + own_spent:
                            if candidates.running:
                                position -= 1
                                await candidates.wait()
                                continue
                            verdicts = _deferred_budget_verdict(
                                candidate_resume, candidate_prior, closed=False,
                                candidate_id=candidate_id, fields=sqli_fields,
                                field_count=field_count, ceiling=round_wall_ceiling,
                                scan_wall_share=scan_wall_share,
                                execution_target=execution_target,
                                method=body_request.get("method", "GET"),
                            )
                            closed = any(item.get("closed") for item in verdicts)
                            observations.append({
                                "kind": "candidate_deferred",
                                "candidate_id": candidate_id,
                                "family": family,
                                "reason": "stage_wall_unfunded",
                                **({} if closed else {"resume_wall_seconds": stage_need}),
                                "available_wall_seconds": max(0, available - own_spent),
                                **({"verdict": "inconclusive"} if closed else {}),
                            })
                            observations.extend(verdicts)
                            exhausted.add("tool_wall_seconds")
                            continue
                        sub_budget["tool_wall_seconds"] = max(
                            int(sub_budget["tool_wall_seconds"]), stage_need + own_spent,
                        )
                    if not sub_budget.get("http_requests") or not sub_budget.get("tool_wall_seconds"):
                        if candidates.running:
                            position -= 1
                            await candidates.wait()
                            continue
                        exhausted |= {
                            name for name in ("http_requests", "tool_wall_seconds")
                            if not sub_budget.get(name)
                        }
                        break
                    if retry_round and int(sub_budget["tool_wall_seconds"]) <= empty_timeouts.get(
                        candidate_id, 0,
                    ):
                        # The residual would grant no more wall than the attempt that timed out
                        # empty: retrying it would fail the same way. It stays unexamined.
                        continue
                    if retry_round:
                        retry_walls[candidate_id] = int(sub_budget["tool_wall_seconds"])
                    endpoint_urls.setdefault(candidate_id, redact_url(execution_target))
                    parsed = urllib.parse.urlsplit(execution_target)
                    registered_target = urllib.parse.urlunsplit(
                        (parsed.scheme, parsed.netloc, "", "", "")
                    )
                    socket_factory = FrozenTargetSocketFactory(
                        hostname=str(parsed.hostname or self.target.canonical_host),
                        port=parsed.port or (443 if parsed.scheme == "https" else 80),
                        frozen_addresses=self.target.allowed_addresses,
                    )
                    scanner_options = {"_batch_attempt": True, **body_request}
                    args = dict(primary.capability_args())
                    args.update(body_request)
                    if tool == "nuclei":
                        scanner_options.update(worker_template_options)
                        args.update(args_template_options)
                    elif tool == "dalfox":
                        scanner_options["severity"] = "high"
                        args["severity"] = "high"
                    legacy_spec = CAPABILITY_REGISTRY.require(legacy_capability)

                    # A concurrent candidate runs after the loop has moved on, so everything the
                    # attempt needs from this iteration is bound now, not looked up when it runs.
                    async def execute_attempt(
                        budget: Mapping[str, int], extra_options: Mapping[str, Any], job_suffix: str,
                        execution_target: str = execution_target,
                        registered_target: str = registered_target,
                        scanner_options: Mapping[str, Any] = scanner_options,
                        args: Mapping[str, Any] = args,
                        socket_factory: FrozenTargetSocketFactory = socket_factory,
                        legacy_spec: Any = legacy_spec,
                    ) -> Any:
                        prepared = fit_prepared_scan_capability(
                            prepare_scan_external_capability(
                                specification=legacy_spec,
                                target=self.target,
                                args=dict(args),
                                policy=self.policy,
                            ),
                            ledger_limits=budget,
                        )
                        adapter = ScannerExecutionAdapter(
                            specification=legacy_spec,
                            process_payload={
                                "job_id": f"{self.job_id}:{action.action_id}:{job_suffix}",
                                "tool_name": tool,
                                "execution_target": execution_target,
                                "registered_target": registered_target,
                                "scanner_options": {**scanner_options, **extra_options},
                                "trusted_headers": primary.headers(),
                                "timeout_ms": int(budget["tool_wall_seconds"]) * 1_000,
                                "pinned_address": socket_factory.primary_address,
                                "authorized_addresses": list(self.target.allowed_addresses),
                                "address_policy": socket_factory.policy_receipt,
                                "oob_interactsh_server": None,
                                "oob_interactsh_token": None,
                                # In memory only: the pinned transport spaces every connection of
                                # this slice's concurrent candidates by it.
                                **({"_request_gate": request_gate} if request_gate is not None else {}),
                            },
                            process_runner=self.process_runner,
                            requested_budget=dict(budget),
                            redacted_execution=prepared.redacted_execution,
                        )
                        return await CapabilityExecutor().execute(
                            CapabilityExecutionContext(
                                specification=legacy_spec,
                                target=self.target,
                                requested_budget=dict(budget),
                                adapter_managed_cancellation=True,
                            ),
                            adapter,
                            heartbeat=heartbeat,
                            cancelled=self.cancelled,
                        )

                    if tool == "sqlmap":
                        # One candidate, verified technique by technique; every finished stage
                        # is checkpointed, so a later attempt continues instead of re-sending it.
                        async def run_stage(
                            technique: str, budget: Mapping[str, int], latency: float,
                            field_name: str | None = None,
                            _attempt_id: str = attempt_id,
                            _execute: Any = execute_attempt,
                        ) -> Any:
                            # One field per run when the body has several: ``-p`` names it.
                            field_suffix = (
                                ":" + hashlib.sha256(field_name.encode()).hexdigest()[:8]
                                if field_name is not None else ""
                            )
                            return await _execute(
                                budget,
                                {
                                    "technique": technique,
                                    **({"injection_fields": [field_name]} if field_name is not None else {}),
                                    **({"_measured_latency_seconds": round(latency, 3)} if latency else {}),
                                },
                                f"{_attempt_id[:16]}:{technique}{field_suffix}",
                            )

                        async def checkpoint_stage(stage: Mapping[str, Any]) -> None:
                            # sqli_stages builds the stage payload, always with a terminal status.
                            await checkpoint_attempt(action.action_id, dict(stage))

                        run_attempt = functools.partial(
                            run_staged_sqli_attempt,
                            candidate_attempt_id=attempt_id,
                            candidate_id=candidate_id,
                            budget=sub_budget,
                            prior=candidate_prior,
                            own_action_id=action.action_id,
                            run_stage=run_stage,
                            checkpoint=checkpoint_stage,
                            cancelled=self.cancelled,
                            measured=candidates.measured,
                            field_count=field_count,
                            fields=sqli_fields,
                            round_wall_ceiling=round_wall_ceiling,
                            scan_wall_share=scan_wall_share,
                        )
                    else:
                        run_attempt = functools.partial(
                            execute_attempt, sub_budget, {}, attempt_id[:16],
                        )
                    row = {
                        "sqli_fields": sqli_fields,
                        "attempt_id": attempt_id, "candidate_id": candidate_id,
                        "retry_round": retry_round, "execution_target": execution_target,
                        "body_request": body_request, "sub_budget": dict(sub_budget),
                    }
                    if concurrent:
                        # The candidate's records keep its place in the slice whenever it finishes.
                        sink: list[Any] = []
                        observations.append(sink)  # type: ignore[arg-type]

                        async def run_candidate(
                            _row: Mapping[str, Any] = row, _run: Any = run_attempt,
                            _sink: list[Any] = sink,
                        ) -> None:
                            try:
                                await settle_attempt(_row, await _run(), _sink)
                            except _BATCH_CANDIDATE_ERRORS as exc:
                                await fail_attempt(
                                    str(_row["attempt_id"]), str(_row["candidate_id"]),
                                    int(_row["retry_round"]), exc,
                                )

                        candidates.launch(attempt_id, sub_budget, consumed, run_candidate)
                        continue
                    await settle_attempt(row, await run_attempt(), observations)
                    if stopped_by_cancel:
                        break
                except _BATCH_CANDIDATE_ERRORS as exc:
                    await fail_attempt(attempt_id, candidate_id, retry_round, exc)
                    continue
            await candidates.finish()
        finally:
            # Cancelled or failed while candidates were running: stop every one of them.
            await candidates.abandon()
            charge_wall()
        # Each concurrent candidate's records were collected in its place in the slice.
        observations = [
            item for entry in observations
            for item in (entry if isinstance(entry, list) else (entry,))
        ]
        for candidate_id, held in deferred_errors.items():
            if candidate_id not in recovered:
                errors.extend(held)
        if recovered:
            # A first attempt a retry recovered no longer stands; every other attempt does.
            standing = [
                entry for entry in attempt_log
                if not (entry[1] == 0 and entry[0] in recovered)
            ]
            terminal_failure = any(not succeeded for _, _, succeeded, _ in standing)
            attempt_timed_out = any(timed_out for _, _, _, timed_out in standing)
        if (recovered or retried_with_output) and cut_off_attempts:
            # A retry re-sends the whole pack with more wall than the cut-off first attempt had.
            # A match it reproduced is kept once; a match only the first attempt reported is
            # kept too, marked as not reproduced (see merge_retried_template_records).
            observations = merge_retried_template_records(observations, {
                item: cut_off_attempts[item] for item in recovered | retried_with_output
                if item in cut_off_attempts
            })
        slow_endpoints = sorted(still_empty) if retry_partial_timeouts else []
        for candidate_id in slow_endpoints:
            # Named per endpoint, so coverage can say which endpoints were too slow for the
            # pack inside this batch's wall instead of a generic timeout.
            observations.append({
                "kind": "template_slow_endpoint",
                "candidate_id": candidate_id,
                "url": endpoint_urls.get(candidate_id, ""),
                "first_attempt_wall_seconds": int(empty_timeouts.get(candidate_id, 0)),
                "retry_wall_seconds": int(retry_walls.get(candidate_id, 0)),
            })
        unattempted = max(0, len(rows) - attempted - inapplicable)
        partial = unattempted > 0 or terminal_failure
        # Say why, ahead of any per-attempt tool errors, so the durable reason is
        # the real one. A tool's own "timeout" string is not a reason code, so
        # without this the result fell back to "output_truncated" and put a false
        # reason on a required action -- which alone made the grade unreliable.
        batch_errors = list(errors[:20])
        if partial or stopped_by_cancel:
            # A batch that attempted every candidate it had did not run out of plan
            # budget, whatever went wrong inside those attempts. Claiming otherwise put a
            # false reason on a required action -- `verify.xss` reported
            # "insufficient_plan_budget" while holding 650 unused requests, its attempts
            # having been wall-killed (exit -9) -- and that alone made the grade
            # unreliable while pointing every reader at the wrong cause. The same holds
            # for the dimension: a request ceiling is not a timeout.
            stated = batch_stop_reason(
                batch_errors, unattempted=unattempted,
                ceiling_stops=ceiling_stops, exhausted=exhausted,
                cancelled=stopped_by_cancel, unexamined=len(still_empty),
            )
            if stated == CapabilityResultReason.TIMED_OUT.value and unattempted:
                # The action's own wall ran out with candidates left: a real timeout.
                attempt_timed_out = attempt_timed_out or "tool_wall_seconds" in exhausted
            elif (
                stated == CapabilityResultReason.TIMED_OUT.value and slow_endpoints
                and {entry[0] for entry in attempt_log if entry[2]}
                and {entry[0] for entry in attempt_log}
                <= {entry[0] for entry in attempt_log if entry[2]} | set(slow_endpoints)
            ):
                # Every endpoint was attempted, every other endpoint finished, and every stop
                # was the wall cutting off an endpoint that could not finish the pack even on
                # its retry: name those endpoints instead of a timeout of the whole batch. When
                # no endpoint finished, the host or the whole target was slow -- a timeout.
                stated = CapabilityResultReason.SLOW_ENDPOINTS.value
            batch_errors.insert(0, stated)
        return self._receipt(
            action,
            status="cancelled" if stopped_by_cancel else "partial" if partial else "success",
            parser_version=CAPABILITY_REGISTRY.require(action.capability_name).output_schema,
            started_at=started_at,
            observations=tuple(observations),
            errors=tuple(batch_errors[:21]),
            consumed=consumed,
            partial=partial,
            # Never overwrite a real timeout with False: the batch inherits it from its
            # attempts, so a wall-killed run stays visible as one.
            timed_out=attempt_timed_out,
            redacted_execution={
                "action_id": action.action_id,
                "profile": action.capability_args.get("profile"),
                "proof_policy": action.capability_args.get("proof_policy"),
                "manifest_digest": manifest_digest,
                "slice": {"start": start, "count": count},
                "candidate_count": len(rows),
                "attempted_count": attempted,
                "resumed_count": resumed,
                "inapplicable_count": inapplicable,
                "unattempted_count": unattempted,
                "retried_count": retried,
                "recovered_count": len(recovered),
                "unexamined_count": len(still_empty),
                "unexamined_candidate_ids": sorted(still_empty)[:50],
                **({"slow_endpoint_count": len(slow_endpoints)} if slow_endpoints else {}),
                "checkpoint_mode": "after_each_candidate",
                **({"extends": extends} if extends else {}),
                **({"technique_stages": staged_summary} if tool == "sqlmap" else {}),
                **({"candidate_concurrency": {
                    "bound": candidates.bound,
                    "peak": candidates.holds.peak,
                    "rate_ceiling_per_second": round(rate_ceiling, 3),
                    "gated_connections": request_gate.admitted,
                }} if request_gate is not None else {}),
                **({"carried_from_admission": admission_source} if admission_source else {}),
                **({"carried_count": carried_count} if extends or admission_source else {}),
            },
        )

    @staticmethod
    def _settle_template_attempt(
        candidate_id: str,
        retry_round: int,
        empty: bool,
        *,
        succeeded: bool,
        granted_wall: int,
        attempt_errors: list[str],
        errors: list[str],
        empty_timeouts: dict[str, int],
        deferred_errors: dict[str, list[str]],
        still_empty: set[str],
        recovered: set[str],
    ) -> None:
        """Record one template attempt: hold back an empty first timeout, settle a retry."""
        if retry_round == 0 and empty:
            empty_timeouts[candidate_id] = granted_wall
            deferred_errors[candidate_id] = attempt_errors
            still_empty.add(candidate_id)
            return
        errors.extend(attempt_errors)
        if retry_round:
            if not empty:
                still_empty.discard(candidate_id)
            if succeeded:
                recovered.add(candidate_id)

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
        origin_evidence = observations.get("origin.select", ())
        if not origin_evidence and "origin.select" in results:
            load_receipt = getattr(self.backend, "load_action_receipt", None)
            if load_receipt is not None:
                receipt = await load_receipt("origin.select")
                origin_evidence = tuple(
                    row for row in receipt.get("observations", ())
                    if isinstance(row, Mapping)
                )
        execution_plan = self.options.get("scan_execution_plan")
        report = finalize_scan_report(
            plan=self.plan,
            plan_revision=self.plan_revision,
            target_url=self.target_url,
            action_results=results,
            observations=observations,
            origin_evidence=origin_evidence,
            # The worker verified this plan against the job (job_runtime) before running it.
            resolved_families=(
                tuple(execution_plan.get("resolved_families") or ())
                if isinstance(execution_plan, Mapping)
                and isinstance(execution_plan.get("resolved_families"), (list, tuple))
                else None
            ),
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
        if action.capability_name == "scan.origin_select":
            return await self._origin_select(action, heartbeat)
        if self.target.inferred_origins and action.capability_name in SCAN_BASE_ORIGIN_CAPABILITIES:
            if not await self._restore_selected_origin():
                return self._skip(action, "origin_unreachable")
        if action.capability_name == "browser.login_check":
            if self._browser_login_adapter_factory is None:
                raise ScanActionAdapterError("browser login requires the local credential-enabled worker")
            adapter = self._browser_login_adapter_factory(action, self)
            return await self._execute_adapter(action, adapter, heartbeat, managed_cancellation=True)
        if action.action_id == "finalize.report":
            await self._restore_selected_origin()
            return await self._finalize(action)
        if action.action_id in {"inputs.auth_primary", "inputs.auth_secondary"}:
            return await self._auth_session(action, heartbeat)
        if action.action_id.startswith("inputs.collection_"):
            return await self._collection_replay(action, heartbeat)
        if action.capability_name == "http.request":
            return await self._http(action, heartbeat)
        if action.capability_name == "dns.inspect":
            return await self._dns(action, heartbeat)
        if action.capability_name == "infrastructure.inspect":
            return await self._infrastructure(action, heartbeat)
        if action.capability_name == "tls.inspect":
            return await self._tls(action, heartbeat)
        if action.capability_name == "web.spec_ingest":
            return await self._spec_ingest(action, heartbeat)
        if action.capability_name in {
            "ports.discover", "service.fingerprint", "subdomains.discover",
        }:
            return await self._network(action, heartbeat)
        if action.capability_name in {
            "web.probe", "web.crawl", "web.browser_crawl",
            "web.content_discover", "templates.scan",
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
        if action.capability_name == "authz_surface.verify_batch":
            return await self._authz_surface_batch(action, heartbeat)
        if action.capability_name == "authz.verify":
            return await self._authz(action, heartbeat)
        raise ScanActionAdapterError(
            f"no database-neutral adapter exists for {action.action_id}"
        )


__all__ = ["DatabaseNeutralScanActionDispatcher", "ScanActionAdapterError"]

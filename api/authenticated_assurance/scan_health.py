"""Scan health observations execute as canonical http.request actions and receipts."""
import asyncio
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from capabilities.inline import HttpRequestExecutionAdapter
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.credential_resolver import WorkerCredentialResolver, validate_worker_credential_authority
from runtime.credentials import IMMEDIATE_HTTP_HEADER_KINDS

from .health_probe import observe_identity
from .models import ProfileConfiguration, ValidationRecord
from .snapshots import bound_snapshot, snapshot_authority_current
from .store import AssuranceStore, ProfileConflict

PROCESS_GENERATION = uuid4()


def scan_health_status(records, options, action):
    """A sample is bounded confidence, and cannot authorize work after its horizon."""
    if ("authentication_profile_ref" in action.capability_args or
            CAPABILITY_REGISTRY.require(action.capability_name).credential_transport == "not_used"):
        return None
    reviewed = False
    for ref in options.get("credential_profile_refs") or ():
        pinned = bound_snapshot(ref)
        if pinned is None:
            continue
        reviewed = True
        try:
            record = ValidationRecord.model_validate(records.get(str(pinned.profile_id)))
        except (ValueError, TypeError):
            return "authentication_uncertain"
        now = datetime.now(timezone.utc)
        if (record.state != "valid" or record.process_generation != PROCESS_GENERATION or
                record.revision != pinned.revision or record.configuration_digest != pinned.configuration_digest or
                record.credential_version != pinned.credential_version or
                record.credential_record_version != pinned.credential_record_version or
                record.checked_at > now or not record.valid_until or record.valid_until <= now):
            return "authentication_uncertain"
    if reviewed:
        from runtime.scan_credentials import resolve_scan_http_principal, ScanCredentialError
        try:
            resolve_scan_http_principal(options, lane="primary", capability_name=action.capability_name)
        except ScanCredentialError:
            return "authentication_uncertain"
    return None


class ScanHealthAdapter(HttpRequestExecutionAdapter):
    """Use the shared HTTP stop/budget contract while retaining only identity match bits."""

    def __init__(self, *, pinned, observe, requested_budget):
        self.pinned = pinned
        self.observation = None
        self.attempt = {"started": False, "elapsed": 0}

        async def operation():
            try:
                async with asyncio.timeout(max(0, int(requested_budget.get("tool_wall_seconds", 0)))):
                    self.observation = await observe(self.attempt)
            except Exception as exc:
                # Resolver and transport exceptions can contain secrets. Never render them.
                reason = str(exc) if isinstance(exc, ProfileConflict) else "validation_timeout" if isinstance(exc, TimeoutError) else "validation_unavailable"
                self.observation = ValidationRecord(validation_id=uuid4(), profile_id=pinned.profile_id,
                    revision=pinned.revision, credential_version=pinned.credential_version,
                    credential_record_version=pinned.credential_record_version,
                    configuration_digest=pinned.configuration_digest, state="unknown", reason_code=reason,
                    checked_at=datetime.now(timezone.utc), process_generation=PROCESS_GENERATION)
            value = {"ok": self.observation.state == "valid", "error": "" if self.observation.state == "valid" else "authentication_uncertain"}
            if self.attempt["started"]:
                value["request"] = {"method": "GET"}
            return value

        super().__init__(specification=CAPABILITY_REGISTRY.require("http.request"), operation=operation,
            requested_budget=requested_budget, redacted_execution={"purpose": "authentication_health",
                "profile_id": str(pinned.profile_id), "profile_revision": pinned.revision,
                "response_content_retained": False, "continuous_authentication_proven": False})

    async def execute(self, *, heartbeat, cancelled):
        result = await super().execute(heartbeat=heartbeat, cancelled=cancelled)
        # Explicit cancellation stays cancellation. No synthetic positive event is emitted.
        if result.status == "cancelled" or self.observation is None:
            return replace(result, observations=())
        if self.observation.reason_code == "validation_timeout":
            result = replace(result, status="partial", partial=True, timed_out=True)
        return replace(result, observations=({"kind": "authentication_health",
            "record": self.observation.model_dump(mode="json")},))


def build_scan_health_adapter(pool, *, action, dispatcher):
    requested = dict(action.capability_args.get("authentication_profile_ref") or {})
    refs = dispatcher.options.get("credential_profile_refs") or []
    matching = [ref for ref in refs if str(ref.get("profile_id")) == requested.get("profile_id")]
    if len(matching) != 1:
        raise ProfileConflict("invalid_profile_selection")
    pinned = bound_snapshot(matching[0])
    if pinned is None or requested != {"profile_id": str(pinned.profile_id), "revision": pinned.revision,
                                     "configuration_digest": pinned.configuration_digest}:
        raise ProfileConflict("profile_changed")
    spec = CAPABILITY_REGISTRY.require("http.request")
    if spec.credential_transport != "exact_origin" or spec.credential_interruption != "cooperative":
        raise ProfileConflict("validation_not_supported")
    target = replace(dispatcher.target, allowed_origins=pinned.credential_destinations)
    if (str(target.target_id) != str(pinned.target_id) or
            not set(pinned.credential_destinations).issubset(dispatcher.target.allowed_origins)):
        raise ProfileConflict("destination_rejected")

    async def observe(attempt):
        async with pool.acquire() as conn:
            profile = await AssuranceStore().get(conn, pinned.profile_id)
            if not snapshot_authority_current(pinned, profile, target.target_id):
                raise ProfileConflict("profile_changed")
            config = ProfileConfiguration.model_validate(profile["configuration"])
            if (int(action.requested_budget.get("http_requests", 0)) < 1 or
                    int(action.requested_budget.get("tool_wall_seconds", 0)) < config.validation_policy.timeout_seconds + 1):
                raise ProfileConflict("validation_unavailable")
            # HTTP consent is an explicit reviewed Scan input; setup consent is not reused.
            if target.allowed_origins[0].startswith("http://") and dispatcher.options.get("authentication_allow_insecure_transport") is not True:
                raise ProfileConflict("insecure_transport_not_approved")
            authority = await validate_worker_credential_authority(conn, owner_kind="scan", owner_id=dispatcher.scan_id,
                target=target, approval_receipt_id=dispatcher.policy.approval_receipt_id,
                scope_receipt_id=target.scope_receipt_id, action_name="scan.submit")
            async with WorkerCredentialResolver().resolve(conn, profile_id=pinned.profile_id, target=target,
                    capability="http.request", authority=authority, expected_version=pinned.credential_version,
                    expected_record_version=pinned.credential_record_version) as credential:
                if credential.profile.auth_kind not in IMMEDIATE_HTTP_HEADER_KINDS:
                    raise ProfileConflict("validation_not_supported")
                record = await observe_identity(config, target=target, headers=credential.http_headers().as_dict(),
                    principal_slot=credential.profile.principal_slot, revision=pinned.revision,
                    credential_version=pinned.credential_version, credential_record_version=pinned.credential_record_version,
                    generation=PROCESS_GENERATION, attempt=attempt)
                if record.state == "valid":
                    current = await AssuranceStore().get(conn, pinned.profile_id)
                    if not snapshot_authority_current(pinned, current, target.target_id):
                        raise ProfileConflict("profile_changed")
                    await validate_worker_credential_authority(conn, owner_kind="scan", owner_id=dispatcher.scan_id,
                        target=target, approval_receipt_id=dispatcher.policy.approval_receipt_id,
                        scope_receipt_id=target.scope_receipt_id, action_name="scan.submit")
                return record

    return ScanHealthAdapter(pinned=pinned, observe=observe, requested_budget=action.requested_budget)

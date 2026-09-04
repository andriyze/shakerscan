"""Durable Hunt run reads and terminal lifecycle transitions."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib
import json
from typing import Any, Mapping
import uuid

from fastapi import HTTPException

from .skills import (
    MAX_CONTEXT_SKILL_SUGGESTIONS,
    MAX_SKILLS_PER_HUNT,
    HuntSkillError,
    HuntSkillSpec,
    skill_library,
)

try:
    from redaction import redact_sensitive
except ModuleNotFoundError:  # package import layout
    from scanner.redaction import redact_sensitive

try:
    from runtime.http_archive_reader import (
        MAX_EXPORT_ROWS,
        count_transactions,
        export_document,
        read_archive_stats,
        read_transactions,
    )
except ModuleNotFoundError:  # package import layout
    from ..runtime.http_archive_reader import (
        MAX_EXPORT_ROWS,
        count_transactions,
        export_document,
        read_archive_stats,
        read_transactions,
    )

agent_tools = importlib.import_module(
    "agent_tools" if __package__ == "hunt" else "api.agent_tools"
)

try:
    from hunt.cancellation import signal_cancelled_jobs
except ModuleNotFoundError:  # package import in host-side tests
    from .cancellation import signal_cancelled_jobs


HUNT_TARGET_KINDS = frozenset({"web", "api", "device", "network"})
HUNT_BUDGET_PROFILE_NAMES = frozenset({"fast", "balanced", "thorough"})
# Sortable columns, mapped explicitly so a client cannot name an arbitrary expression.
HUNT_SORT_COLUMNS = {
    "created_at": "h.created_at",
    "updated_at": "h.updated_at",
    "completed_at": "h.completed_at",
    "status": "h.status",
    "objective": "h.objective",
    "target_url": "COALESCE(t.url, d.primary_locator)",
}
HUNT_RUN_STATUSES = frozenset({
    "created",
    "active",
    "awaiting_planner",
    "completed",
    "cancelled",
    "failed",
    "budget_exhausted",
})
ACTIVE_HUNT_STATUSES = frozenset({"active", "awaiting_planner"})
HUNT_SKILL_USAGE_STATES = frozenset({"used", "completed", "deferred"})
_SKILL_SIGNAL_KEYS = frozenset({
    "auth", "authentication", "content_type", "endpoint", "endpoints", "framework",
    "frameworks", "protocol", "protocols", "route", "routes", "service", "services",
    "stack", "tags", "technologies", "technology",
})

_ACTION_REFERENCE_FIELDS = {
    "scan_id": "scan_ids",
    "scan_ids": "scan_ids",
    "queued_scan_id": "scan_ids",
    "finding_id": "finding_ids",
    "finding_ids": "finding_ids",
    "candidate_id": "candidate_ids",
    "candidate_ids": "candidate_ids",
    "evidence_id": "evidence_ids",
    "evidence_ids": "evidence_ids",
    "evidence_ref": "evidence_ids",
    "evidence_instance_id": "evidence_ids",
    "evidence_instance_ids": "evidence_ids",
}


def _uuid_or_400(value: str, label: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid {label}") from exc


def _decode_json(value: Any, default: Any) -> Any:
    decoded = value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = value
    return decoded if isinstance(decoded, type(default)) else default


def _row_dict(row: Any) -> dict[str, Any]:
    item = dict(row or {})
    for key, value in tuple(item.items()):
        if isinstance(value, uuid.UUID):
            item[key] = str(value)
        elif isinstance(value, datetime):
            item[key] = value.isoformat()
    return item


def _bounded_text(value: Any, *, maximum: int) -> str:
    return str(value or "").strip()[:maximum]


def _json_object_copy(value: Any) -> dict[str, Any]:
    return json.loads(json.dumps(_decode_json(value, {})))


def _skill_signal_values(context: Mapping[str, Any]) -> tuple[str, ...]:
    """Extract a small technology/surface vocabulary without copying context into prompts."""
    values: list[str] = []

    def visit(node: Any, *, key: str = "", depth: int = 0) -> None:
        if depth > 5 or len(values) >= 40:
            return
        if isinstance(node, Mapping):
            for raw_key, child in node.items():
                name = str(raw_key).strip().lower()
                if name in _SKILL_SIGNAL_KEYS:
                    visit(child, key=name, depth=depth + 1)
                elif isinstance(child, (Mapping, list, tuple)):
                    visit(child, key=name, depth=depth + 1)
        elif isinstance(node, (list, tuple)):
            for child in node[:20]:
                visit(child, key=key, depth=depth + 1)
        elif key in _SKILL_SIGNAL_KEYS:
            text = _bounded_text(node, maximum=160)
            if text and text not in values:
                values.append(text)

    visit(context)
    return tuple(values)


def _bound_skill_projection(
    specs: tuple[HuntSkillSpec, ...], requested: set[str],
) -> list[dict[str, Any]]:
    return [
        {
            "skill_id": spec.skill_id,
            "title": spec.title,
            "version": spec.version,
            "body_sha256": spec.body_sha256,
            "phase": spec.phase,
            "requested": spec.skill_id in requested,
            "methodology_url": f"/hunts/{{hunt_id}}/skills/{spec.skill_id}/read",
        }
        for spec in specs
    ]


def public_hunt_skill_event(row: Any) -> dict[str, Any]:
    item = _row_dict(row)
    return {
        "event_id": str(item.get("id")) if item.get("id") else None,
        "skill_id": item.get("skill_id"),
        "event_type": item.get("event_type"),
        "skill_version": item.get("skill_version"),
        "body_sha256": item.get("body_sha256"),
        "reason": item.get("reason"),
        "evidence_refs": _decode_json(item.get("evidence_refs"), []),
        "action_id": str(item.get("action_id")) if item.get("action_id") else None,
        "created_at": item.get("created_at"),
    }


def _requested_skill_ids(context: Mapping[str, Any]) -> list[str]:
    skills = context.get("skills") if isinstance(context.get("skills"), Mapping) else {}
    selection = (
        skills.get("selection") if isinstance(skills.get("selection"), Mapping) else {}
    )
    values = selection.get("requested_skill_ids")
    if not isinstance(values, list):
        values = [
            item.get("skill_id")
            for item in skills.get("bound") or []
            if isinstance(item, Mapping) and item.get("requested") is True
        ]
    return list(dict.fromkeys(
        str(item).strip() for item in values if str(item or "").strip()
    ))


def _resolve_skill_url_templates(context: dict[str, Any], hunt_id: str) -> dict[str, Any]:
    skills = context.get("skills")
    if not isinstance(skills, Mapping):
        return context
    copied = json.loads(json.dumps(context))

    def visit(node: Any) -> Any:
        if isinstance(node, dict):
            return {key: visit(value) for key, value in node.items()}
        if isinstance(node, list):
            return [visit(value) for value in node]
        if isinstance(node, str):
            return node.replace("{hunt_id}", hunt_id)
        return node

    copied["skills"] = visit(copied["skills"])
    return copied


def _refresh_skill_context(
    context: dict[str, Any], *, objective: str, target_kind: str,
    allowed_capabilities: list[str], requested: list[str], signals: tuple[str, ...] = (),
) -> tuple[dict[str, Any], tuple[HuntSkillSpec, ...]]:
    library = skill_library()
    specs = library.resolve_for_hunt(requested, target_kind=target_kind)
    available = set(allowed_capabilities)
    unavailable = sorted({
        capability
        for spec in specs
        for capability in spec.capabilities
        if capability not in available
    })
    if unavailable:
        raise HuntSkillError(
            "methodology requires capabilities outside this Hunt authority: "
            + ", ".join(unavailable)
        )
    context["skills"] = {
        "schema_version": "hunt-skill/v2",
        "catalog": {
            "url": "/hunt/skills",
            "suggestions_url": "/hunts/{hunt_id}/skills/suggestions",
            "status": library.catalog_status,
            "loaded_count": len(library),
            "bindable_for_policy_count": len(library.available_for_hunt(
                target_kind=target_kind,
                allowed_capabilities=allowed_capabilities,
            )),
        },
        "selection": {
            "requested_skill_ids": list(requested),
            "selection_optional": True,
            "binding_is_explicit": True,
            "auto_bound": False,
            "maximum": MAX_SKILLS_PER_HUNT,
            "instruction": (
                "Do not read the whole catalog. Fetch one suggested methodology only when "
                "its evidence trigger is relevant, then bind it explicitly if used."
            ),
        },
        "suggested": [
            {
                **item,
                "methodology_url": (
                    f"/hunts/{{hunt_id}}/skills/{item['skill_id']}/read"
                ),
            }
            for item in library.suggest(
                goal=objective,
                signals=signals,
                target_kind=target_kind,
                allowed_capabilities=allowed_capabilities,
                exclude=(spec.skill_id for spec in specs),
                limit=MAX_CONTEXT_SKILL_SUGGESTIONS,
            )
        ],
        "bound": _bound_skill_projection(specs, set(requested)),
    }
    return context, specs


def _uuid_reference(value: Any) -> str | None:
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError):
        return None


def _action_reference_ids(value: Any) -> dict[str, list[str]]:
    """Extract only typed UUID references from a redacted action result."""

    references: dict[str, list[str]] = {
        "scan_ids": [],
        "finding_ids": [],
        "candidate_ids": [],
        "evidence_ids": [],
    }

    def visit(node: Any, *, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(node, Mapping):
            for raw_key, raw_value in node.items():
                key = str(raw_key)
                reference_kind = _ACTION_REFERENCE_FIELDS.get(key)
                if reference_kind:
                    values = raw_value if isinstance(raw_value, (list, tuple)) else [raw_value]
                    for candidate in values:
                        reference = _uuid_reference(candidate)
                        if reference and reference not in references[reference_kind]:
                            references[reference_kind].append(reference)
                if isinstance(raw_value, (Mapping, list, tuple)):
                    visit(raw_value, depth=depth + 1)
        elif isinstance(node, (list, tuple)):
            for child in node:
                visit(child, depth=depth + 1)

    visit(value)
    return references


def public_hunt_action(row: Any) -> dict[str, Any]:
    """Return a content-safe projection of one canonical capability action."""

    item = _row_dict(row)
    input_summary = _decode_json(item.get("input_summary"), {})
    result_summary = _decode_json(item.get("result_summary"), {})
    def numeric_budget(value: Any) -> dict[str, int | float]:
        if not isinstance(value, Mapping):
            return {}
        return {
            str(key): amount
            for key, amount in value.items()
            if isinstance(amount, (int, float)) and not isinstance(amount, bool)
        }

    budget_consumed = numeric_budget(result_summary.get("budget_consumed"))
    raw_accounting = result_summary.get("budget_accounting")
    has_accounting = isinstance(raw_accounting, Mapping)
    accounting = dict(raw_accounting) if has_accounting else {}
    reservation_id = str(accounting.get("reservation_id") or "") or None
    settlement_status = str(accounting.get("settlement_status") or "legacy")
    has_measured_actual = isinstance(accounting.get("actual"), Mapping)
    has_exact_accounting = bool(
        reservation_id and settlement_status == "succeeded" and has_measured_actual
    )
    budget_actual = numeric_budget(accounting.get("actual"))
    accounting_basis = (
        "exact_settlement" if has_exact_accounting
        else "settlement_failed" if settlement_status == "failed"
        else "no_reservation" if has_accounting and not reservation_id
        else "legacy_reported_charge"
    )
    observations = result_summary.get("observations")
    if isinstance(observations, list):
        observation_count = len(observations)
    else:
        # Worker-owned network/scanner actions intentionally persist only a
        # content-safe count, not their complete observation bodies. Older
        # rows used ``record_count`` while current rows use the canonical
        # ``observation_count`` name. Preserve both so the UI does not turn a
        # successful probe or crawl into a misleading "0 observations" card.
        raw_observation_count = result_summary.get(
            "observation_count", result_summary.get("record_count", 0)
        )
        observation_count = (
            int(raw_observation_count)
            if isinstance(raw_observation_count, int)
            and not isinstance(raw_observation_count, bool)
            and raw_observation_count >= 0
            else 0
        )
    return {
        "action_id": str(item.get("id")) if item.get("id") else None,
        "capability_name": item.get("capability_name"),
        "status": item.get("status"),
        "input_digest": input_summary.get("input_digest"),
        "idempotency_key_sha256": input_summary.get("idempotency_key_sha256"),
        "receipt_id": str(item.get("receipt_id")) if item.get("receipt_id") else None,
        "started_at": item.get("started_at"),
        "completed_at": item.get("completed_at"),
        "result": {
            # Missing is unknown, not failure. Several worker adapters historically stored an
            # execution status but no semantic `ok` field; coercing that absence to False made
            # the public record contradict its own completed status.
            "ok": (
                result_summary.get("ok")
                if isinstance(result_summary.get("ok"), bool)
                else None
            ),
            "partial": result_summary.get("partial") is True,
            "timed_out": result_summary.get("timed_out") is True,
            "observation_count": observation_count,
            # Compatibility field. New clients should use budget_accounting so a
            # reservation ceiling can never be presented as measured consumption.
            "budget_consumed": budget_actual if has_exact_accounting else budget_consumed,
            "budget_accounting": {
                "schema_version": "hunt-budget-settlement/v1",
                "basis": accounting_basis,
                "settlement_status": settlement_status,
                "reservation_id": reservation_id,
                "charge_basis": (
                    str(accounting.get("charge_basis") or "capability_reported_settlement")
                    if has_exact_accounting else "legacy_unknown"
                ),
                "reserved": numeric_budget(accounting.get("reserved")),
                "actual": budget_actual,
                "released": numeric_budget(accounting.get("released")),
                "overspent": numeric_budget(accounting.get("overspent")),
                "used_after_reconciliation": numeric_budget(
                    accounting.get("used_after_reconciliation")
                ),
            },
            "reference_ids": _action_reference_ids(result_summary),
        },
    }


def hunt_action_outcome_summary(actions: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive a factual Hunt outcome from the immutable action ledger."""
    statuses: dict[str, int] = {}
    references = {
        "finding_ids": set(), "candidate_ids": set(), "evidence_ids": set(),
    }
    observations = 0
    successful_calls = 0
    executed_calls = 0
    unsuccessful_calls = 0
    indeterminate_calls = 0
    partial_calls = 0
    for action in actions:
        status = str(action.get("status") or "unknown")
        statuses[status] = statuses.get(status, 0) + 1
        if status not in {"completed", "failed", "partial"}:
            continue
        executed_calls += 1
        result = action.get("result") if isinstance(action.get("result"), Mapping) else {}
        semantic_ok = result.get("ok") if isinstance(result.get("ok"), bool) else None
        if status == "partial":
            partial_calls += 1
        elif status == "failed" or semantic_ok is False:
            unsuccessful_calls += 1
        elif status == "completed" and semantic_ok is True:
            successful_calls += 1
        else:
            indeterminate_calls += 1
        observations += max(0, int(result.get("observation_count") or 0))
        typed = result.get("reference_ids") if isinstance(result.get("reference_ids"), Mapping) else {}
        for key in references:
            for reference in typed.get(key) or []:
                if _uuid_reference(reference):
                    references[key].add(str(reference))
    return {
        "schema_version": "hunt-outcome-summary/v3",
        # Compatibility field retained for existing clients. Unlike v2 it now means what its
        # UI label always claimed: semantically successful calls, not merely completed dispatch.
        "capability_calls": successful_calls,
        "total_capability_calls": len(actions),
        "attempted_calls": len(actions),
        "executed_calls": executed_calls,
        "successful_calls": successful_calls,
        "unsuccessful_calls": unsuccessful_calls,
        "indeterminate_calls": indeterminate_calls,
        "partial_calls": partial_calls,
        "action_statuses": statuses,
        "observation_count": observations,
        "finding_ids": sorted(references["finding_ids"]),
        "candidate_ids": sorted(references["candidate_ids"]),
        "evidence_ids": sorted(references["evidence_ids"]),
    }


def public_hunt_action_trace(row: Any) -> dict[str, Any]:
    """One explicit, redacted planner decision and its persisted outcome.

    This is deliberately not hidden model chain-of-thought. It contains the operator-visible
    capability choice, planner-supplied input, durable receipt references and outcome that
    ShakerScan actually used to authorize and settle the action.
    """
    item = _row_dict(row)
    input_summary = _decode_json(item.get("input_summary"), {})
    result_summary = _decode_json(item.get("result_summary"), {})
    decision_input = input_summary.get("input")
    if not isinstance(decision_input, Mapping):
        decision_input = {}
    return {
        **public_hunt_action(row),
        "decision": {
            "kind": "explicit_capability_selection",
            "input": redact_sensitive(
                dict(decision_input), redact_strings=True, scrub_text=True,
            ),
            "input_digest": input_summary.get("input_digest"),
            "idempotency_key_sha256": input_summary.get("idempotency_key_sha256"),
        },
        "outcome": redact_sensitive(
            result_summary, redact_strings=True, scrub_text=True,
        ),
    }


def public_hunt_run(
    row: Any,
    *,
    include_context: bool = True,
    include_capabilities: bool = True,
) -> dict[str, Any]:
    """Return the content-safe Hunt projection shared by every client."""

    item = _row_dict(row)
    policy = _decode_json(item.get("policy_json"), {})
    allowed = policy.get("allowed_capabilities")
    capabilities: list[dict[str, Any]] = []
    if isinstance(allowed, list):
        for raw_name in allowed:
            try:
                capabilities.append(
                    agent_tools.CAPABILITY_REGISTRY.require(
                        str(raw_name)
                    ).planner_contract()
                )
            except KeyError:
                continue
    result = {
        "hunt_id": str(item.get("id")) if item.get("id") else None,
        "target_kind": item.get("target_kind"),
        "target_id": str(
            item.get("target_id") or item.get("device_target_id") or ""
        ) or None,
        "objective": item.get("objective"),
        "status": item.get("status"),
        "budget_profile": item.get("budget_profile"),
        "policy": policy,
        "budget": _decode_json(item.get("budget_json"), {}),
        "budget_used": _decode_json(item.get("budget_used_json"), {}),
        "final_debrief": _decode_json(item.get("final_debrief"), {}),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        # Present in the table but never projected, so a client could not show how long a
        # hunt took or sort by when it finished.
        "completed_at": item.get("completed_at"),
        "stop_reason": item.get("stop_reason"),
        # Resolved by the list query's join. Absent on a single-run read, where the caller
        # already knows the target it asked about.
        "target_url": item.get("target_url"),
        "target_name": item.get("target_name"),
        "root_domain": item.get("root_domain"),
        "next_action": (
            f"POST /hunts/{item.get('id')}/query"
            if item.get("status") in {"active", "awaiting_planner"}
            else None
        ),
    }
    if include_capabilities:
        result["capabilities"] = capabilities
    context = _resolve_skill_url_templates(
        _decode_json(item.get("context_pack"), {}), str(item.get("id") or ""),
    )
    # Surfaced beside capabilities rather than only inside the pack: a client listing runs
    # needs to see which methodology a hunt was run under without parsing the whole pack.
    bound_skills = (context.get("skills") or {}).get("bound")
    result["skills"] = list(bound_skills) if isinstance(bound_skills, list) else []
    if include_context:
        result["context_pack"] = context
    return result


async def hunt_run_or_404(
    connection: Any,
    hunt_id: str,
    *,
    for_update: bool = False,
) -> Any:
    query = "SELECT * FROM hunt_runs WHERE id=$1"
    if for_update:
        query += " FOR UPDATE"
    row = await connection.fetchrow(query, _uuid_or_400(hunt_id, "hunt id"))
    if not row:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return row


class HuntRunService:
    """Own read/list/finish/cancel/resume persistence for canonical Hunts."""

    def __init__(self, pool_provider, redis_provider=None):
        self._pool_provider = pool_provider
        # Optional so existing construction and tests are unchanged; without it a cancellation
        # still stops the Hunt and its scans, it simply cannot reach worker-placed capability jobs.
        self._redis_provider = redis_provider

    def _pool(self):
        pool = self._pool_provider()
        if pool is None:
            raise HTTPException(status_code=503, detail="Database is not ready")
        return pool

    async def get(self, hunt_id: str) -> dict[str, Any]:
        hunt_uuid = _uuid_or_400(hunt_id, "hunt id")
        async with self._pool().acquire() as connection:
            row = await hunt_run_or_404(connection, hunt_id)
            actions = await connection.fetch(
                """SELECT id, capability_name, status, input_summary,
                          result_summary, receipt_id, started_at, completed_at
                   FROM hunt_actions WHERE hunt_run_id=$1
                   ORDER BY started_at ASC, id ASC""",
                hunt_uuid,
            )
            skill_events = await connection.fetch(
                """SELECT id, skill_id, event_type, skill_version, body_sha256,
                          reason, evidence_refs, action_id, created_at
                   FROM hunt_skill_events WHERE hunt_run_id=$1
                   ORDER BY created_at ASC, id ASC""",
                hunt_uuid,
            )
        result = public_hunt_run(row)
        result["actions"] = [public_hunt_action(action) for action in actions]
        result["outcome_summary"] = hunt_action_outcome_summary(result["actions"])
        result["skill_activity"] = [
            public_hunt_skill_event(event) for event in skill_events
        ]
        return result

    async def skill_suggestions(
        self, hunt_id: str, *, signals: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return at most three compact suggestions; methodology bodies stay server-side."""
        async with self._pool().acquire() as connection:
            row = await hunt_run_or_404(connection, hunt_id)
        item = _row_dict(row)
        context = _decode_json(item.get("context_pack"), {})
        policy = _decode_json(item.get("policy_json"), {})
        allowed = [str(name) for name in policy.get("allowed_capabilities") or []]
        bounded_signals = list(_skill_signal_values(context))
        for signal in signals or []:
            text = _bounded_text(signal, maximum=160)
            if text and text not in bounded_signals and len(bounded_signals) < 40:
                bounded_signals.append(text)
        requested = _requested_skill_ids(context)
        specs = skill_library().resolve_for_hunt(
            requested, target_kind=str(item.get("target_kind") or "web"),
        )
        suggestions = skill_library().suggest(
            goal=str(item.get("objective") or ""),
            signals=bounded_signals,
            target_kind=str(item.get("target_kind") or "web"),
            allowed_capabilities=allowed,
            exclude=(spec.skill_id for spec in specs),
            limit=MAX_CONTEXT_SKILL_SUGGESTIONS,
        )
        return {
            "hunt_id": str(item.get("id")),
            "catalog_url": "/hunt/skills",
            "suggestions": [
                {
                    **item,
                    "methodology_url": (
                        f"/hunts/{hunt_id}/skills/{item['skill_id']}/read"
                    ),
                    "bind_url": f"/hunts/{hunt_id}/skills/{item['skill_id']}/bind",
                }
                for item in suggestions
            ],
            "count": len(suggestions),
            "signals_considered": len(bounded_signals),
            "methodology_bodies_loaded": 0,
            "advisory_only": True,
        }

    async def read_skill(self, hunt_id: str, skill_id: str) -> dict[str, Any]:
        """Fetch one methodology on demand and record that explicit context spend."""
        library = skill_library()
        try:
            spec = library.require(skill_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        try:
            payload = spec.public(include_body=True)
        except (HuntSkillError, OSError, UnicodeError) as exc:
            raise HTTPException(status_code=503, detail="Methodology revision is unavailable") from exc
        hunt_uuid = _uuid_or_400(hunt_id, "hunt id")
        async with self._pool().acquire() as connection:
            async with connection.transaction():
                row = await hunt_run_or_404(connection, hunt_id, for_update=True)
                if str(row["target_kind"]) not in spec.target_kinds:
                    raise HTTPException(
                        status_code=422,
                        detail="Methodology does not support this Hunt target kind",
                    )
                if row["status"] in ACTIVE_HUNT_STATUSES:
                    await connection.execute(
                        """INSERT INTO hunt_skill_events (
                               hunt_run_id, skill_id, event_type, skill_version,
                               body_sha256, reason, evidence_refs
                           )
                           SELECT $1,$2,'read',$3,$4,$5,'[]'::jsonb
                           WHERE NOT EXISTS (
                               SELECT 1 FROM hunt_skill_events
                               WHERE hunt_run_id=$1 AND skill_id=$2
                                 AND event_type='read' AND body_sha256=$4
                           )""",
                        hunt_uuid, spec.skill_id, spec.version, spec.body_sha256,
                        "Methodology fetched on demand",
                    )
        payload["hunt_id"] = hunt_id
        payload["context_policy"] = "on_demand_single_methodology"
        return payload

    async def bind_skill(
        self, hunt_id: str, skill_id: str, *, reason: str = "",
        evidence_refs: list[str] | None = None,
    ) -> dict[str, Any]:
        hunt_uuid = _uuid_or_400(hunt_id, "hunt id")
        async with self._pool().acquire() as connection:
            async with connection.transaction():
                row = await hunt_run_or_404(connection, hunt_id, for_update=True)
                if row["status"] not in ACTIVE_HUNT_STATUSES:
                    raise HTTPException(
                        status_code=409, detail=f"Hunt is {row['status']}",
                    )
                context = _json_object_copy(row["context_pack"])
                requested = _requested_skill_ids(context)
                if skill_id not in requested:
                    requested.append(skill_id)
                if len(requested) > MAX_SKILLS_PER_HUNT:
                    raise HTTPException(
                        status_code=422,
                        detail=f"A Hunt may bind at most {MAX_SKILLS_PER_HUNT} methodologies",
                    )
                policy = _decode_json(row["policy_json"], {})
                allowed = [str(name) for name in policy.get("allowed_capabilities") or []]
                try:
                    context, specs = _refresh_skill_context(
                        context,
                        objective=str(row["objective"] or ""),
                        target_kind=str(row["target_kind"]),
                        allowed_capabilities=allowed,
                        requested=requested,
                        signals=_skill_signal_values(context),
                    )
                except HuntSkillError as exc:
                    raise HTTPException(status_code=422, detail=str(exc)) from exc
                explicit = next(spec for spec in specs if spec.skill_id == skill_id)
                changed = skill_id not in _requested_skill_ids(
                    _decode_json(row["context_pack"], {})
                )
                previous_revisions = {
                    item.get("skill_id"): item.get("body_sha256")
                    for item in (_decode_json(row["context_pack"], {}).get("skills") or {}).get("bound") or []
                    if isinstance(item, Mapping)
                }
                changed = changed or previous_revisions.get(skill_id) != explicit.body_sha256
                if changed:
                    was_read = await connection.fetchval(
                        """SELECT EXISTS(
                               SELECT 1 FROM hunt_skill_events
                               WHERE hunt_run_id=$1 AND skill_id=$2
                                 AND event_type='read' AND body_sha256=$3
                           )""",
                        hunt_uuid, explicit.skill_id, explicit.body_sha256,
                    )
                    if not was_read:
                        raise HTTPException(
                            status_code=409,
                            detail=(
                                "Read this methodology through the Hunt-specific read endpoint "
                                "before binding it"
                            ),
                        )
                    for spec in specs:
                        if previous_revisions.get(spec.skill_id) == spec.body_sha256:
                            continue
                        await connection.execute(
                            """INSERT INTO hunt_skill_events (
                                   hunt_run_id, skill_id, event_type, skill_version,
                                   body_sha256, reason, evidence_refs
                               ) VALUES ($1,$2,'bound',$3,$4,$5,$6)""",
                            hunt_uuid, spec.skill_id, spec.version,
                            spec.body_sha256,
                            (
                                _bounded_text(reason, maximum=500)
                                or "Selected after review"
                                if spec.skill_id == explicit.skill_id
                                else f"Required by {explicit.skill_id}"
                            ),
                            json.dumps(
                                list(dict.fromkeys(evidence_refs or []))[:20]
                                if spec.skill_id == explicit.skill_id else []
                            ),
                        )
                    await connection.execute(
                        "UPDATE hunt_runs SET context_pack=$2, updated_at=NOW() WHERE id=$1",
                        hunt_uuid, json.dumps(context),
                    )
        return await self.get(hunt_id)

    async def unbind_skill(
        self, hunt_id: str, skill_id: str, *, reason: str = "",
    ) -> dict[str, Any]:
        hunt_uuid = _uuid_or_400(hunt_id, "hunt id")
        async with self._pool().acquire() as connection:
            async with connection.transaction():
                row = await hunt_run_or_404(connection, hunt_id, for_update=True)
                if row["status"] not in ACTIVE_HUNT_STATUSES:
                    raise HTTPException(
                        status_code=409, detail=f"Hunt is {row['status']}",
                    )
                context = _json_object_copy(row["context_pack"])
                previous_bound_ids = {
                    str(item.get("skill_id"))
                    for item in (context.get("skills") or {}).get("bound") or []
                    if isinstance(item, Mapping)
                }
                requested = _requested_skill_ids(context)
                if skill_id not in requested:
                    raise HTTPException(
                        status_code=409, detail="Methodology is not explicitly bound",
                    )
                requested = [item for item in requested if item != skill_id]
                policy = _decode_json(row["policy_json"], {})
                allowed = [str(name) for name in policy.get("allowed_capabilities") or []]
                try:
                    context, specs = _refresh_skill_context(
                        context,
                        objective=str(row["objective"] or ""),
                        target_kind=str(row["target_kind"]),
                        allowed_capabilities=allowed,
                        requested=requested,
                        signals=_skill_signal_values(context),
                    )
                    spec = skill_library().require(skill_id)
                except (HuntSkillError, KeyError) as exc:
                    raise HTTPException(status_code=422, detail=str(exc)) from exc
                remaining_ids = {item.skill_id for item in specs}
                removed_ids = previous_bound_ids - remaining_ids
                event_ids = sorted(removed_ids | ({skill_id} if skill_id in remaining_ids else set()))
                for event_skill_id in event_ids:
                    event_spec = skill_library().require(event_skill_id)
                    selection_only = event_skill_id == skill_id and event_skill_id in remaining_ids
                    await connection.execute(
                        """INSERT INTO hunt_skill_events (
                               hunt_run_id, skill_id, event_type, skill_version,
                               body_sha256, reason, evidence_refs
                           ) VALUES ($1,$2,$3,$4,$5,$6,'[]'::jsonb)""",
                        hunt_uuid, event_spec.skill_id,
                        "selection_removed" if selection_only else "unbound",
                        event_spec.version, event_spec.body_sha256,
                        (
                            _bounded_text(reason, maximum=500)
                            or "Methodology selection removed"
                            if event_skill_id == skill_id
                            else f"No longer required after removing {skill_id}"
                        ),
                    )
                await connection.execute(
                    "UPDATE hunt_runs SET context_pack=$2, updated_at=NOW() WHERE id=$1",
                    hunt_uuid, json.dumps(context),
                )
        return await self.get(hunt_id)

    async def record_skill_usage(
        self, hunt_id: str, skill_id: str, *, state: str,
        action_id: str | None = None, evidence_refs: list[str] | None = None,
        reason: str = "",
    ) -> dict[str, Any]:
        if state not in HUNT_SKILL_USAGE_STATES:
            raise HTTPException(status_code=422, detail="Invalid methodology usage state")
        hunt_uuid = _uuid_or_400(hunt_id, "hunt id")
        action_uuid = _uuid_or_400(action_id, "action id") if action_id else None
        refs = list(dict.fromkeys(evidence_refs or []))[:20]
        if state in {"used", "completed"} and action_uuid is None:
            raise HTTPException(
                status_code=422,
                detail="Used or completed methodology requires a same-Hunt action_id; evidence references alone do not establish usage",
            )
        async with self._pool().acquire() as connection:
            async with connection.transaction():
                row = await hunt_run_or_404(connection, hunt_id, for_update=True)
                if row["status"] not in ACTIVE_HUNT_STATUSES:
                    raise HTTPException(status_code=409, detail=f"Hunt is {row['status']}")
                context = _decode_json(row["context_pack"], {})
                bound_ids = {
                    str(item.get("skill_id"))
                    for item in (context.get("skills") or {}).get("bound") or []
                    if isinstance(item, Mapping)
                }
                if skill_id not in bound_ids:
                    raise HTTPException(status_code=409, detail="Methodology is not bound")
                try:
                    spec = skill_library().require(skill_id)
                except KeyError as exc:
                    raise HTTPException(status_code=404, detail=str(exc)) from exc
                bound = next(item for item in context["skills"]["bound"] if item.get("skill_id") == skill_id)
                if bound.get("body_sha256") != spec.body_sha256:
                    raise HTTPException(status_code=409, detail="Bound methodology revision changed; read and rebind it before use")
                if state in {"used", "completed"}:
                    was_read = await connection.fetchval(
                        """SELECT EXISTS(SELECT 1 FROM hunt_skill_events
                           WHERE hunt_run_id=$1 AND skill_id=$2 AND event_type='read' AND body_sha256=$3)""",
                        hunt_uuid, spec.skill_id, spec.body_sha256,
                    )
                    if not was_read:
                        raise HTTPException(status_code=409, detail="Read this methodology before reporting usage")
                if action_uuid is not None:
                    action = await connection.fetchrow(
                        """SELECT capability_name, status FROM hunt_actions
                           WHERE id=$1 AND hunt_run_id=$2""",
                        action_uuid, hunt_uuid,
                    )
                    if not action:
                        raise HTTPException(
                            status_code=422, detail="Action does not belong to this Hunt",
                        )
                    allowed_statuses = {"completed"} if state == "completed" else {"running", "completed", "partial"}
                    if state in {"used", "completed"} and str(action["status"]) not in allowed_statuses:
                        raise HTTPException(status_code=422, detail="Action has not reached the reported methodology usage state")
                    if str(action["capability_name"]) not in {
                        *spec.capabilities, *spec.optional_capabilities,
                    }:
                        raise HTTPException(
                            status_code=422,
                            detail="Action capability is not declared by this methodology",
                        )
                await connection.execute(
                    """INSERT INTO hunt_skill_events (
                           hunt_run_id, skill_id, event_type, skill_version,
                           body_sha256, reason, evidence_refs, action_id
                       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)""",
                    hunt_uuid, spec.skill_id, state, spec.version, spec.body_sha256,
                    _bounded_text(reason, maximum=500) or None,
                    json.dumps(refs), action_uuid,
                )
        return await self.get(hunt_id)

    async def export_record(self, hunt_id: str) -> dict[str, Any]:
        """Return the complete redacted, explicit Hunt record and its HTTP archive."""
        hunt_uuid = _uuid_or_400(hunt_id, "hunt id")
        async with self._pool().acquire() as connection:
            row = await hunt_run_or_404(connection, hunt_id)
            actions = await connection.fetch(
                """SELECT id, capability_name, status, input_summary,
                          result_summary, receipt_id, started_at, completed_at
                   FROM hunt_actions WHERE hunt_run_id=$1
                   ORDER BY started_at ASC, id ASC""",
                hunt_uuid,
            )
            skill_events = await connection.fetch(
                """SELECT id, skill_id, event_type, skill_version, body_sha256,
                          reason, evidence_refs, action_id, created_at
                   FROM hunt_skill_events WHERE hunt_run_id=$1
                   ORDER BY created_at ASC, id ASC""",
                hunt_uuid,
            )
            total = await count_transactions(
                connection, scan_id=None, hunt_run_id=hunt_id,
            )
            stats = await read_archive_stats(
                connection, scan_id=None, hunt_run_id=hunt_id,
            )
            transactions = await read_transactions(
                connection, scan_id=None, hunt_run_id=hunt_id,
                limit=MAX_EXPORT_ROWS, offset=0,
            )
        run = redact_sensitive(
            public_hunt_run(row, include_context=False),
            redact_strings=True,
            scrub_text=True,
        )
        notes = _decode_json(_row_dict(row).get("notes"), [])
        return {
            "schema_version": "hunt-record/v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "trace_policy": {
                "kind": "explicit_decision_trace",
                "includes": [
                    "objective", "bound_skills", "policy", "budgets",
                    "planner_capability_inputs", "action_outcomes", "receipt_references",
                    "persisted_notes", "final_debrief", "http_transactions",
                ],
                "excludes": ["hidden_model_chain_of_thought", "context_pack"],
                "detail": (
                    "This export preserves explicit choices and durable outcomes; it does "
                    "not expose private model chain-of-thought or the worker context pack. "
                    "Known secret shapes are masked, but planner and target-controlled free "
                    "text must still be handled as potentially sensitive."
                ),
                "residual_secret_risk": True,
            },
            "hunt": run,
            "decision_trace": [public_hunt_action_trace(action) for action in actions],
            "methodology_trace": [
                public_hunt_skill_event(event) for event in skill_events
            ],
            "notes": redact_sensitive(notes, redact_strings=True, scrub_text=True),
            "http_archive": export_document(
                transactions, export_format="transactions", redaction="redacted",
                owner={"hunt_id": hunt_id}, total=total, archive_total=total, stats=stats,
            ),
        }

    async def list(
        self,
        *,
        target_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        target_kind: str | None = None,
        budget_profile: str | None = None,
        root_domain: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        """List hunts across targets, with the target's identity resolved.

        The projection carried only a target UUID, so any cross-target view rendered
        unreadable identifiers or had to fetch every target and join in the browser. The
        join happens here, and `total` is the count before paging so a client can say
        "51-100 of 240" rather than "50 shown".
        """
        clauses: list[str] = []
        params: list[Any] = []
        if target_id:
            params.append(_uuid_or_400(target_id, "target id"))
            clauses.append(
                f"(h.target_id=${len(params)} OR h.device_target_id=${len(params)})"
            )
        if status:
            if status not in HUNT_RUN_STATUSES:
                raise HTTPException(status_code=400, detail="invalid Hunt status")
            params.append(status)
            clauses.append(f"h.status=${len(params)}")
        if target_kind:
            if target_kind not in HUNT_TARGET_KINDS:
                raise HTTPException(status_code=400, detail="invalid Hunt target kind")
            params.append(target_kind)
            clauses.append(f"h.target_kind=${len(params)}")
        if budget_profile:
            if budget_profile not in HUNT_BUDGET_PROFILE_NAMES:
                raise HTTPException(status_code=400, detail="invalid Hunt budget profile")
            params.append(budget_profile)
            clauses.append(f"h.budget_profile=${len(params)}")
        if root_domain:
            params.append(str(root_domain).strip().lower())
            clauses.append(f"t.root_domain=${len(params)}")
        if search:
            # Objective and target identity together: an operator looking for a past hunt
            # remembers one or the other, rarely both.
            params.append(f"%{str(search).strip()}%")
            clauses.append(
                f"(h.objective ILIKE ${len(params)} OR t.url ILIKE ${len(params)}"
                f" OR t.name ILIKE ${len(params)} OR d.name ILIKE ${len(params)}"
                f" OR d.primary_locator ILIKE ${len(params)})"
            )
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        order_column = HUNT_SORT_COLUMNS.get(str(sort_by))
        if order_column is None:
            raise HTTPException(status_code=400, detail="invalid Hunt sort field")
        direction = "ASC" if str(sort_order).lower() == "asc" else "DESC"
        joins = (
            " FROM hunt_runs h"
            " LEFT JOIN targets t ON t.id = h.target_id"
            " LEFT JOIN device_targets d ON d.id = h.device_target_id"
        )
        async with self._pool().acquire() as connection:
            total = await connection.fetchval(
                f"SELECT COUNT(*){joins}{where}", *params,
            )
            params.extend([int(limit), max(0, int(offset))])
            rows = await connection.fetch(
                f"SELECT h.*, COALESCE(t.url, d.primary_locator) AS target_url,"
                f" COALESCE(t.name, d.name) AS target_name, t.root_domain"
                f"{joins}{where}"
                f" ORDER BY {order_column} {direction} NULLS LAST, h.id"
                f" LIMIT ${len(params) - 1} OFFSET ${len(params)}",
                *params,
            )
        return {
            "hunts": [
                public_hunt_run(
                    row, include_context=False, include_capabilities=False
                )
                for row in rows
            ],
            "count": len(rows),
            "total": int(total or 0),
            "limit": int(limit),
            "offset": max(0, int(offset)),
        }

    async def finish(
        self, hunt_id: str, *, summary: str, next_actions: list[str]
    ) -> dict[str, Any]:
        async with self._pool().acquire() as connection:
            async with connection.transaction():
                run_uuid = _uuid_or_400(hunt_id, "hunt id")
                row = await hunt_run_or_404(connection, hunt_id, for_update=True)
                if row["status"] == "completed":
                    return public_hunt_run(row)
                if row["status"] not in {
                    "active", "awaiting_planner", "budget_exhausted",
                }:
                    raise HTTPException(
                        status_code=409, detail=f"Hunt is {row['status']}"
                    )
                in_flight = await connection.fetchrow(
                    """SELECT
                           EXISTS(SELECT 1 FROM hunt_actions
                                  WHERE hunt_run_id=$1
                                    AND status IN ('reserved','running')) AS actions,
                           EXISTS(SELECT 1 FROM budget_reservations
                                     WHERE owner_kind='hunt' AND owner_id=$1::text
                                       AND status IN ('reserved','running')) AS reservations""",
                    run_uuid,
                )
                if in_flight["actions"] or in_flight["reservations"]:
                    raise HTTPException(
                        status_code=409,
                        detail="Hunt has reserved or running actions",
                    )
                row = await connection.fetchrow(
                    """UPDATE hunt_runs
                       SET status = CASE
                               WHEN status='budget_exhausted' THEN status ELSE 'completed' END,
                           stop_reason = CASE
                               WHEN status='budget_exhausted'
                               THEN COALESCE(stop_reason, 'budget_exhausted') ELSE 'completed' END,
                           final_debrief=$2, completed_at=COALESCE(completed_at, NOW()),
                           updated_at=NOW()
                       WHERE id=$1
                         AND status IN ('active','awaiting_planner','budget_exhausted')
                       RETURNING *""",
                    run_uuid,
                    json.dumps({"summary": summary, "next_actions": next_actions}),
                )
        return public_hunt_run(row)

    async def cancel(self, hunt_id: str) -> dict[str, Any]:
        """Cancel a Hunt and the downstream work it queued.

        Flipping ``hunt_runs.status`` alone stopped the Hunt from admitting new actions but left
        every scan it had already queued running against the target. Actions still in flight learn
        of the cancellation through ``HuntCancellationWatch``; scans are already queued jobs and
        have to be cancelled where they live.

        The status rules mirror ``cancel_scan``: device traffic goes to ``cancelling`` and stays
        there until its worker acknowledges a terminal state after reaping the process group, so a
        cancel never invents a terminal row while a device is still being probed. Reservations are
        deliberately left to settle through their own path -- releasing a hold whose action is still
        running would let the next action spend budget that is already committed.
        """
        run_uuid = _uuid_or_400(hunt_id, "hunt id")
        cancelled_ids: list[str] = []
        durable_job_ids: list[str] = []
        async with self._pool().acquire() as connection:
            row = await connection.fetchrow(
                """UPDATE hunt_runs SET status='cancelled', stop_reason='cancelled',
                          completed_at=NOW(), updated_at=NOW()
                   WHERE id=$1 AND status IN ('created','active','awaiting_planner')
                   RETURNING *""",
                run_uuid,
            )
            if not row:
                row = await hunt_run_or_404(connection, run_uuid)
                if row["status"] != "cancelled":
                    return public_hunt_run(row)
            else:
                cancelled = await connection.fetch(
                    """UPDATE scans
                   SET status = CASE
                           WHEN run_kind IN ('device_posture','device_probe') AND status='running'
                           THEN 'cancelling' ELSE 'cancelled' END,
                       error_message = 'Cancelled by owning Hunt',
                       completed_at = CASE
                           WHEN run_kind IN ('device_posture','device_probe') AND status='running'
                           THEN NULL ELSE NOW() END,
                       progress = CASE
                           WHEN run_kind IN ('device_posture','device_probe') AND status='running'
                           THEN progress ELSE 100 END,
                       current_phase = CASE
                           WHEN run_kind IN ('device_posture','device_probe') AND status='running'
                           THEN 'cancelling' ELSE 'cancelled' END
                   WHERE options->'hunt_dispatch'->>'hunt_id' = $1::text
                     AND status IN ('pending','queued','running')
                   RETURNING id""",
                    str(run_uuid),
                )
                cancelled_ids = [str(item["id"]) for item in cancelled]
                if cancelled_ids:
                    # Shards of a cancelled parent must not be left to finish on their own.
                    await connection.execute(
                        """UPDATE scans
                       SET status='cancelled', error_message='Cancelled by parent scan',
                           completed_at=NOW(), progress=100, current_phase='cancelled'
                       WHERE parent_scan_id = ANY($1::uuid[])
                         AND status IN ('pending','queued','running')""",
                        [uuid.UUID(item) for item in cancelled_ids],
                    )
            durable_jobs = await connection.fetch(
                """UPDATE hunt_cancellable_jobs
                   SET cancel_requested_at=COALESCE(cancel_requested_at, NOW()),
                       updated_at=NOW()
                   WHERE hunt_id=$1 AND signal_state != 'terminal'
                   RETURNING job_id""",
                run_uuid,
            )
            durable_job_ids = sorted(str(item["job_id"]) for item in durable_jobs)
        # A worker-placed capability polls `agent_tool_cancel:{job_id}` for a job id minted at
        # queue time, so cancelling the Hunt and its scans still left that traffic running. Signal
        # every job this Hunt queued. Idempotent: an already-set flag is harmless and a finished
        # job never reads it.
        signalled: list[str] = []
        if self._redis_provider is not None:
            try:
                signalled = signal_cancelled_jobs(
                    self._redis_provider(), run_uuid, job_ids=durable_job_ids,
                )
            except (AttributeError, NameError, TypeError):
                # A programming error must never look like an unreachable Redis. The
                # blanket handler that used to sit here swallowed a missing import, so
                # this call raised NameError on every cancellation, wrote no cancel keys,
                # and still returned an empty list as though there had been nothing to
                # signal.
                raise
            except Exception:  # noqa: BLE001 - Redis is unreachable; the Hunt is cancelled either way
                signalled = []
        durable_signalled = sorted(set(signalled).intersection(durable_job_ids))
        if durable_signalled:
            async with self._pool().acquire() as connection:
                await connection.execute(
                    """UPDATE hunt_cancellable_jobs
                       SET signal_state='signalled', signalled_at=NOW(), updated_at=NOW()
                       WHERE hunt_id=$1 AND job_id = ANY($2::uuid[])""",
                    run_uuid,
                    [uuid.UUID(item) for item in durable_signalled],
                )
        pending_job_ids = sorted(set(durable_job_ids).difference(signalled))
        payload = public_hunt_run(row)
        payload["cancelled_scan_ids"] = cancelled_ids
        payload["cancelled_job_ids"] = signalled
        payload["pending_cancel_job_ids"] = pending_job_ids
        payload["cancellation_degraded"] = bool(pending_job_ids)
        return payload

    async def resume(self, hunt_id: str) -> dict[str, Any]:
        async with self._pool().acquire() as connection:
            row = await connection.fetchrow(
                """UPDATE hunt_runs SET status='active', stop_reason=NULL,
                          updated_at=NOW()
                   WHERE id=$1 AND status='awaiting_planner' RETURNING *""",
                _uuid_or_400(hunt_id, "hunt id"),
            )
            if not row:
                row = await hunt_run_or_404(connection, hunt_id)
                if row["status"] != "active":
                    raise HTTPException(
                        status_code=409,
                        detail=f"Hunt is {row['status']} and cannot resume",
                    )
        return public_hunt_run(row)


__all__ = [
    "HUNT_RUN_STATUSES",
    "HuntRunService",
    "hunt_run_or_404",
    "public_hunt_action",
    "public_hunt_run",
]

"""Runtime settings routes.

Extracted verbatim from the api.py monolith. Owns the runtime settings surface —
AI provider configuration and its connectivity probe, scan execution policy, and
automation defaults (auto-sharding, Continuous ASM defaults, and the approval
receipt policy).

Collaborators that are still hubs inside api.py are injected by the composition
root as lazily-resolved callables.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import urllib.error
import urllib.parse
import urllib.request
import json
import os
from typing import Any, Callable, Literal, Mapping, Optional
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from api_utils import _clean_string_list, _int_or_none, _optional_uuid, _uuid_or_400, utc_now_iso
    import asm_inventory
    import parallel_scan
    from ai_targets.router import _validate_demo_base_url
    from exposure.intel_sources import SETTING_KEYS as INTEL_SOURCE_KEYS, load_intel_sources
    from redaction import mask_secret
    from retest_contract import AUTO_FP_MIN_CONFIDENCE_FLOOR
    from serialization import _decode_json_value, _json_object, _str_list, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import _clean_string_list, _int_or_none, _optional_uuid, _uuid_or_400, utc_now_iso
    from .. import asm_inventory, parallel_scan
    from ..ai_targets.router import _validate_demo_base_url
    from ..exposure.intel_sources import SETTING_KEYS as INTEL_SOURCE_KEYS, load_intel_sources
    from ..retest_contract import AUTO_FP_MIN_CONFIDENCE_FLOOR
    from ..serialization import _decode_json_value, _json_object, _str_list, row_to_dict
    from scanner.redaction import mask_secret


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


APPROVAL_POLICY_SETTING_KEY = "approval_receipts_required_for_state_changing_actions"


def configure_settings_router(
    pool_provider: Callable[[], Any], **collaborators: Callable[..., Any]
) -> None:
    """Bind the pool and the collaborators this domain needs."""
    global _pool_provider
    _pool_provider = pool_provider
    _deps.update(collaborators)


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool


def _dep(name: str) -> Callable[..., Any]:
    call = _deps.get(name)
    if call is None:
        raise HTTPException(status_code=503, detail=f"{name} is not ready")
    return call

# Hub collaborators that still live in api.py, injected and resolved lazily.
def get_redis(*a: Any, **k: Any) -> Any:
    return _dep("get_redis")(*a, **k)


def _is_truthy(*a: Any, **k: Any) -> Any:
    return _dep("is_truthy")(*a, **k)


def _normalize_severity(*a: Any, **k: Any) -> Any:
    return _dep("normalize_severity")(*a, **k)


def _load_effective_ai_settings(*a: Any, **k: Any) -> Any:
    return _dep("load_effective_ai_settings")(*a, **k)


def _load_effective_automation_settings(*a: Any, **k: Any) -> Any:
    return _dep("load_effective_automation_settings")(*a, **k)


def _is_local_scan_worker_container(*a: Any, **k: Any) -> Any:
    return _dep("is_local_scan_worker_container")(*a, **k)


def _local_compose_project_best_effort(*a: Any, **k: Any) -> Any:
    return _dep("local_compose_project_best_effort")(*a, **k)


def docker_socket_request(*a: Any, **k: Any) -> Any:
    return _dep("docker_socket_request")(*a, **k)


import logging

logger = logging.getLogger("shakerscan.api.settings")

@router.get("/settings/ai")
async def get_ai_settings():
    """Get effective AI settings (secrets masked)."""
    settings = _load_effective_ai_settings()
    return _sanitize_ai_settings_response(settings)


@router.get("/settings/scan-execution")
async def get_scan_execution_settings():
    """Get effective scan execution settings."""
    settings = _load_effective_scan_execution_settings()
    return _sanitize_scan_execution_settings_response(settings)


@router.put("/settings/scan-execution")
async def update_scan_execution_settings(request: ScanExecutionSettingsUpdate):
    """Update runtime scan execution settings."""
    try:
        r = get_redis()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {e}")

    updates = _scan_execution_update_mapping(request)
    if updates:
        r.hset(SCAN_SETTINGS_KEY, mapping=updates)

    settings = _load_effective_scan_execution_settings()
    return {
        "status": "updated",
        "settings": _sanitize_scan_execution_settings_response(settings),
    }


@router.get("/settings/automation")
async def get_automation_settings():
    """Get compact safe automation defaults for Settings, API, and AI agents."""
    automation = await _automation_settings_with_durable_flags()
    return _sanitize_automation_settings_response(automation)


@router.put("/settings/automation")
async def update_automation_settings(request: AutomationSettingsUpdate):
    """Update compact safe automation defaults.

    This intentionally allows only safe default ASM policy. Lab/deep active depth
    remains an explicit per-target or per-operation decision.
    """
    try:
        r = get_redis()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {e}")

    current_automation = _load_effective_automation_settings()

    scan_updates = _scan_execution_update_mapping(request)
    if scan_updates:
        r.hset(SCAN_SETTINGS_KEY, mapping=scan_updates)

    automation_updates: dict[str, str] = {}
    if request.default_asm_enabled is not None:
        automation_updates["default_asm_enabled"] = "true" if request.default_asm_enabled else "false"
    if request.default_asm_config is not None:
        automation_updates["default_asm_config"] = json.dumps(
            _merge_safe_default_asm_config(
                current_automation.get("default_asm_config"),
                request.default_asm_config,
            )
        )
    if request.approval_receipts_required_for_state_changing_actions is not None:
        automation_updates[APPROVAL_POLICY_SETTING_KEY] = (
            "true" if request.approval_receipts_required_for_state_changing_actions else "false"
        )
    if automation_updates:
        r.hset(AUTOMATION_SETTINGS_KEY, mapping=automation_updates)

    # Optional advisory intelligence sources are an operator opt-in read from Postgres only.
    intel_updates = {
        INTEL_SOURCE_KEYS[name]: "true" if value else "false"
        for name, value in (("curated_briefings", request.intel_curated_briefings),
                            ("vendor_declared_ranges", request.intel_vendor_declared_ranges))
        if value is not None
    }
    if intel_updates:
        async with _pool().acquire() as conn:
            for key, value in intel_updates.items():
                await _write_durable_setting(conn, key, value)

    # The approval-receipt requirement is a security gate, so persist it durably
    # to Postgres (Redis stays a cache). This is what enforcement reads, so the
    # policy survives a Redis flush instead of silently failing open.
    if request.approval_receipts_required_for_state_changing_actions is not None:
        async with _pool().acquire() as conn:
            await _write_durable_setting(
                conn,
                APPROVAL_POLICY_SETTING_KEY,
                "true" if request.approval_receipts_required_for_state_changing_actions else "false",
            )

    return {
        "status": "updated",
        "settings": _sanitize_automation_settings_response(
            await _automation_settings_with_durable_flags()
        ),
    }


@router.put("/settings/ai")
async def update_ai_settings(request: AISettingsUpdate):
    """Update runtime AI settings (Redis persists them across restarts)."""
    _validate_effective_ai_threshold_update(request, _load_effective_ai_settings())
    try:
        r = get_redis()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {e}")

    string_fields = (
        "ai_url",
        "ai_api_key",
        "ai_model",
        "ai_model_fallback",
        "ai_mask_host",
    )

    updates: dict[str, str] = {}
    deletes: list[str] = []

    for field in string_fields:
        value = getattr(request, field)
        if value is None:
            continue
        normalized = str(value).strip()
        if normalized == "":
            deletes.append(field)
        else:
            updates[field] = normalized

    # Always remove legacy per-verify provider keys from runtime settings.
    deletes.extend([
        "ai_verify_url",
        "ai_verify_api_key",
        "ai_verify_model",
        "ai_verify_model_fallback",
    ])

    if request.ai_verify_enabled is not None:
        updates["ai_verify_enabled"] = "true" if request.ai_verify_enabled else "false"

    if request.ai_verify_min_severity is not None:
        updates["ai_verify_min_severity"] = _normalize_severity(request.ai_verify_min_severity, default="high")

    if request.ai_scan_classification_enabled is not None:
        updates["ai_scan_classification_enabled"] = "true" if request.ai_scan_classification_enabled else "false"

    if request.ai_classify_min_severity is not None:
        updates["ai_classify_min_severity"] = _normalize_severity(
            request.ai_classify_min_severity,
            default=_normalize_severity(request.ai_verify_min_severity, default="high")
            if request.ai_verify_min_severity is not None
            else "high",
        )

    if request.auto_retest_on_scan_complete is not None:
        updates["auto_retest_on_scan_complete"] = "true" if request.auto_retest_on_scan_complete else "false"

    if request.auto_retest_min_severity is not None:
        updates["auto_retest_min_severity"] = _normalize_severity(request.auto_retest_min_severity, default="medium")

    if request.auto_retest_max_per_scan is not None:
        updates["auto_retest_max_per_scan"] = str(max(0, int(request.auto_retest_max_per_scan)))

    # Unified verification policy fields (bidirectional sync with legacy names)
    if request.verification_min_severity is not None:
        updates["verification_min_severity"] = _normalize_severity(request.verification_min_severity, default="medium")
        updates["auto_retest_min_severity"] = updates["verification_min_severity"]
    if request.ai_escalation_min_severity is not None:
        updates["ai_escalation_min_severity"] = _normalize_severity(request.ai_escalation_min_severity, default="high")
        updates["ai_verify_min_severity"] = updates["ai_escalation_min_severity"]
    if request.proof_required_for_smart is not None:
        updates["proof_required_for_smart"] = "true" if request.proof_required_for_smart else "false"
    if request.auto_fp_on_retest is not None:
        updates["auto_fp_on_retest"] = "true" if request.auto_fp_on_retest else "false"
    if request.auto_fp_min_confidence is not None:
        updates["auto_fp_min_confidence"] = str(_normalize_confidence(request.auto_fp_min_confidence, default=0.9))
    if request.demo_mode_enabled is not None:
        updates["demo_mode_enabled"] = "true" if request.demo_mode_enabled else "false"
    if request.demo_honey_public_url is not None:
        normalized = _validate_demo_base_url(request.demo_honey_public_url)
        if normalized:
            updates["demo_honey_public_url"] = normalized
        else:
            deletes.append("demo_honey_public_url")
    if request.demo_honey_scanner_url is not None:
        normalized = _validate_demo_base_url(request.demo_honey_scanner_url)
        if normalized:
            updates["demo_honey_scanner_url"] = normalized
        else:
            deletes.append("demo_honey_scanner_url")

    if updates:
        from runtime.ai_settings_secrets import protect_settings, SecretStoreUnavailable
        try:
            r.hset(AI_SETTINGS_KEY, mapping=protect_settings(updates))
        except SecretStoreUnavailable:
            raise HTTPException(503, "Credential encryption is unavailable; provider key cannot be saved") from None
    if deletes:
        r.hdel(AI_SETTINGS_KEY, *deletes)
    if "ai_api_key" in updates or "ai_api_key" in deletes:
        from runtime.ai_settings_secrets import compact_history
        compact_history(r)

    return {
        "status": "updated",
        "settings": _sanitize_ai_settings_response(_load_effective_ai_settings()),
    }


@router.post("/settings/ai/test")
async def test_ai_settings(request: AISettingsProbeRequest):
    """Test AI provider connectivity and parsing."""
    effective = _load_effective_ai_settings()
    scope = request.scope

    if scope == "verify":
        stored_url = (effective.get("ai_verify_url") or effective.get("ai_url") or "").strip()
        ai_api_key = (request.ai_api_key or effective.get("ai_verify_api_key") or effective.get("ai_api_key") or "").strip()
        ai_model = (request.ai_model or effective.get("ai_verify_model") or effective.get("ai_model") or "").strip()
        fallback_models = request.ai_fallback_model
        if fallback_models is None:
            fallback_models = effective.get("ai_verify_model_fallback") or effective.get("ai_model_fallback") or ""
    else:
        stored_url = (effective.get("ai_url") or "").strip()
        ai_api_key = (request.ai_api_key or effective.get("ai_api_key") or "").strip()
        ai_model = (request.ai_model or effective.get("ai_model") or "").strip()
        fallback_models = request.ai_fallback_model
        if fallback_models is None:
            fallback_models = effective.get("ai_model_fallback") or ""

    # The stored provider key is only ever sent to the stored provider URL. A probe of any other
    # URL must bring its own key, or the probe would hand the saved key to a caller-chosen host.
    requested_url = (request.ai_url or "").strip()
    ai_url = requested_url or stored_url
    if requested_url and requested_url != stored_url and not (request.ai_api_key or "").strip():
        raise HTTPException(
            status_code=400,
            detail="AI API key is required to probe a URL other than the saved AI URL",
        )
    if not ai_url:
        raise HTTPException(status_code=400, detail="AI URL is required for probe")
    if not ai_api_key:
        raise HTTPException(status_code=400, detail="AI API key is required for probe")
    if not ai_model:
        raise HTTPException(status_code=400, detail="AI model is required for probe")

    probe = await _probe_ai_provider(
        ai_url=ai_url,
        ai_api_key=ai_api_key,
        model=ai_model,
        fallback_models=(fallback_models or "").strip() or None,
    )
    return {
        "status": "ok" if probe.get("ok") else "failed",
        "scope": scope,
        "probe": probe,
    }
AI_SETTINGS_KEY = os.environ.get("AI_SETTINGS_KEY", "settings:ai")


SCAN_SETTINGS_KEY = os.environ.get("SCAN_SETTINGS_KEY", "settings:scan")


AUTOMATION_SETTINGS_KEY = os.environ.get("AUTOMATION_SETTINGS_KEY", "settings:automation")




def _normalize_confidence(value: Any, default: float) -> float:
    """Clamp a confidence value into [0, 1], falling back to default on error."""
    try:
        return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return default


def _sanitize_ai_settings_response(settings: dict[str, Any]) -> dict[str, Any]:
    shared_key = str(settings.get("ai_api_key") or "")
    return {
        "ai_url": settings.get("ai_url") or "",
        "ai_model": settings.get("ai_model") or "",
        "ai_model_fallback": settings.get("ai_model_fallback") or "",
        "ai_mask_host": settings.get("ai_mask_host") or "",
        "ai_scan_classification_enabled": bool(settings.get("ai_scan_classification_enabled")),
        "ai_classify_min_severity": settings.get("ai_classify_min_severity") or settings.get("ai_verify_min_severity") or "high",
        "ai_api_key_configured": bool(shared_key),
        "ai_api_key_masked": _mask_secret(shared_key),
        "ai_verify_enabled": bool(settings.get("ai_verify_enabled")),
        "ai_verify_min_severity": settings.get("ai_verify_min_severity") or "high",
        "auto_retest_on_scan_complete": bool(settings.get("auto_retest_on_scan_complete")),
        "auto_retest_min_severity": settings.get("auto_retest_min_severity") or "medium",
        "auto_retest_max_per_scan": _normalize_non_negative_int(
            settings.get("auto_retest_max_per_scan"),
            default=0,
        ),
        # Unified verification policy fields
        "verification_min_severity": settings.get("verification_min_severity") or settings.get("auto_retest_min_severity") or "medium",
        "ai_escalation_min_severity": settings.get("ai_escalation_min_severity") or settings.get("ai_verify_min_severity") or "high",
        "proof_required_for_smart": bool(settings.get("proof_required_for_smart", False)),
        "auto_fp_on_retest": bool(settings.get("auto_fp_on_retest", False)),
        "auto_fp_min_confidence": _normalize_confidence(settings.get("auto_fp_min_confidence"), default=0.9),
        "demo_mode_enabled": bool(settings.get("demo_mode_enabled", False)),
        "demo_honey_public_url": settings.get("demo_honey_public_url") or "",
        "demo_honey_scanner_url": settings.get("demo_honey_scanner_url") or "",
    }


def _load_effective_scan_execution_settings() -> dict[str, Any]:
    settings = _default_scan_execution_settings()
    try:
        r = get_redis()
        overrides = r.hgetall(SCAN_SETTINGS_KEY) or {}
    except Exception:
        overrides = {}

    if "auto_sharding_enabled" in overrides:
        settings["auto_sharding_enabled"] = _is_truthy(
            overrides.get("auto_sharding_enabled"),
            default=settings["auto_sharding_enabled"],
        )
    if "auto_sharding_strategy" in overrides:
        settings["auto_sharding_strategy"] = _normalize_parallel_strategy(
            overrides.get("auto_sharding_strategy"),
            default=settings["auto_sharding_strategy"],
        )
    if "auto_sharding_max_shards" in overrides:
        settings["auto_sharding_max_shards"] = _normalize_auto_shard_count(
            overrides.get("auto_sharding_max_shards"),
            default=int(settings["auto_sharding_max_shards"]),
        )
    if "auto_sharding_min_workers" in overrides:
        settings["auto_sharding_min_workers"] = max(
            1,
            _normalize_non_negative_int(
                overrides.get("auto_sharding_min_workers"),
                default=int(settings["auto_sharding_min_workers"]),
            ),
        )
    return settings


def _merge_safe_default_asm_config(base: Any, update: Any) -> dict[str, Any]:
    """Apply a partial automation default update without resetting unrelated knobs."""
    merged = dict(_safe_default_asm_config(base))
    if isinstance(update, dict):
        merged.update(update)
    return _safe_default_asm_config(merged)


async def _write_durable_setting(conn, key: str, value: str) -> None:
    await conn.execute(
        """
        INSERT INTO app_settings (key, value, updated_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        """,
        key,
        value,
    )


def _sanitize_scan_execution_settings_response(settings: dict[str, Any]) -> dict[str, Any]:
    worker_count = _running_scan_worker_count_best_effort()
    return {
        "auto_sharding_enabled": bool(settings.get("auto_sharding_enabled")),
        "auto_sharding_strategy": _normalize_parallel_strategy(
            settings.get("auto_sharding_strategy"),
            default="auto",
        ),
        "auto_sharding_max_shards": _normalize_auto_shard_count(
            settings.get("auto_sharding_max_shards"),
            default=4,
        ),
        "auto_sharding_min_workers": max(
            1,
            _normalize_non_negative_int(settings.get("auto_sharding_min_workers"), default=2),
        ),
        "eligibility": "active_testing_or_two_explicit_endpoints",
        "running_workers": worker_count,
    }


def _sanitize_automation_settings_response(
    automation: dict[str, Any] | None = None,
    scan_execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    automation = automation or _load_effective_automation_settings()
    scan_execution = scan_execution or _load_effective_scan_execution_settings()
    default_asm_config = _safe_default_asm_config(automation.get("default_asm_config"))
    return {
        "scan_execution": _sanitize_scan_execution_settings_response(scan_execution),
        "default_continuous_asm": {
            "enabled_for_new_web_targets": bool(automation.get("default_asm_enabled")),
            "config": default_asm_config,
            "active_depth_confirmation_required": True,
            "high_risk_families_require_explicit_request": True,
            "applies_to": "new web targets",
        },
        "safety_boundaries": {
            "global_exploit_depth": False,
            "lab_depth_requires_explicit_action": True,
            "planned_high_risk_families_fail_closed": True,
            "approval_receipts_required_for_state_changing_actions": bool(
                automation.get("approval_receipts_required_for_state_changing_actions")
            ),
        },
        # Optional advisory data already in the verified snapshot. Off until an operator enables it;
        # enabling fetches nothing, grants no authority and changes no score.
        "intelligence_sources": {
            name: bool((automation.get("intelligence_sources") or {}).get(name)) for name in INTEL_SOURCE_KEYS
        },
    }


async def _probe_ai_provider(
    ai_url: str,
    ai_api_key: str,
    model: str,
    fallback_models: str | None = None,
) -> dict[str, Any]:
    probe_fn, probe_import_error = _load_probe_ai_provider()
    if probe_fn is None:
        return {
            "ok": False,
            "error": f"AI probe unavailable ({probe_import_error})",
            "latency_ms": None,
            "provider_meta": {},
            "response": None,
        }
    try:
        return await probe_fn(
            ai_url=ai_url,
            ai_api_key=ai_api_key,
            model=model,
            fallback_models=fallback_models,
        )
    except Exception as exc:
        return {
            "ok": False,
            "error": f"AI probe failed: {type(exc).__name__}: {str(exc)[:160]}",
            "latency_ms": None,
            "provider_meta": {},
            "response": None,
        }


def _scan_execution_update_mapping(request: ScanExecutionSettingsUpdate) -> dict[str, str]:
    updates: dict[str, str] = {}
    if request.auto_sharding_enabled is not None:
        updates["auto_sharding_enabled"] = "true" if request.auto_sharding_enabled else "false"
    if request.auto_sharding_strategy is not None:
        updates["auto_sharding_strategy"] = _normalize_parallel_strategy(
            request.auto_sharding_strategy,
            default="auto",
        )
    if request.auto_sharding_max_shards is not None:
        updates["auto_sharding_max_shards"] = str(
            _normalize_auto_shard_count(request.auto_sharding_max_shards, default=4)
        )
    if request.auto_sharding_min_workers is not None:
        updates["auto_sharding_min_workers"] = str(max(1, int(request.auto_sharding_min_workers)))
    return updates


async def _automation_settings_with_durable_flags() -> dict[str, Any]:
    """Load automation settings with the durable (Postgres) approval flag applied.

    Postgres is the source of truth for the security gate; Redis/env is only a
    fallback when no durable value has been written yet.
    """
    automation = _load_effective_automation_settings()
    try:
        async with _pool().acquire() as conn:
            durable = await _read_durable_setting(conn, APPROVAL_POLICY_SETTING_KEY)
    except Exception:
        durable = None
    if durable is not None:
        automation[APPROVAL_POLICY_SETTING_KEY] = _is_truthy(durable, default=False)
    try:
        async with _pool().acquire() as conn:
            automation["intelligence_sources"] = await load_intel_sources(conn)
    except Exception:
        automation["intelligence_sources"] = {}
    return automation










def _normalize_non_negative_int(value: Any, default: int) -> int:
    try:
        return max(0, int(str(value)))
    except (TypeError, ValueError):
        return default


_mask_secret = mask_secret


def _normalize_parallel_strategy(value: Any, default: str = "auto") -> str:
    candidate = str(value or "").strip().lower()
    if candidate in parallel_scan.VALID_STRATEGIES:
        return candidate
    return default


def _normalize_auto_shard_count(value: Any, default: int = 4) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        parsed = default
    return max(2, min(AUTO_SHARD_MAX_SHARDS, parsed))


def _default_scan_execution_settings() -> dict[str, Any]:
    return {
        "auto_sharding_enabled": _is_truthy(
            os.environ.get("AUTO_SHARDING_ENABLED", "false"),
            default=False,
        ),
        "auto_sharding_strategy": _normalize_parallel_strategy(
            os.environ.get("AUTO_SHARDING_STRATEGY", "auto"),
            default="auto",
        ),
        "auto_sharding_max_shards": _normalize_auto_shard_count(
            os.environ.get("AUTO_SHARDING_MAX_SHARDS", "4"),
            default=4,
        ),
        "auto_sharding_min_workers": max(
            1,
            _normalize_non_negative_int(
                os.environ.get("AUTO_SHARDING_MIN_WORKERS", "2"),
                default=2,
            ),
        ),
    }


def _safe_default_asm_config(config: Any = None) -> dict[str, Any]:
    cfg = asm_inventory.merge_asm_config(config or {})
    # Global automation defaults must stay safe. Lab/deep active depth is still
    # explicit per target/action, not a broad default.
    cfg["exploit_depth"] = False
    return cfg




async def _read_durable_setting(conn, key: str) -> str | None:
    """Read one durable app_settings value, or None if unset/unavailable."""
    try:
        return await conn.fetchval("SELECT value FROM app_settings WHERE key = $1", key)
    except Exception:
        return None


def _load_probe_ai_provider():
    import importlib

    import_errors: list[str] = []
    for module_name in ("scanner_tools.ai_classifier", "scanner.scanner_tools.ai_classifier"):
        try:
            module = importlib.import_module(module_name)
            fn = getattr(module, "probe_ai_provider", None)
            if callable(fn):
                return fn, None
        except Exception as exc:
            import_errors.append(f"{module_name}: {type(exc).__name__}")
    return None, "; ".join(import_errors) if import_errors else "probe function not found"






_EXPERIMENT_WORKFLOW_TEMPLATES: dict[str, dict[str, Any]] = {
    "bola": {
        "proof_family": "bola",
        "objective": "User2 reads a User1-owned object referenced by User1's managed login context",
        "expected_signal": "the attacker principal receives the owner's object while anonymous is denied",
        "falsifier": "the owner reference is absent, the attacker is denied or receives different data, or anonymous is allowed",
        "principal_variables": [
            {"name": "owner_object_id", "principal": "user1", "ref": "object_id"},
            {"name": "attacker_object_id", "principal": "user2", "ref": "object_id"},
        ],
        "steps": [
            {"label": "owner_read", "kind": "http", "principal": "user1", "checkpoint": "action", "method": "GET", "path": "/api/<objects>/${owner_object_id}"},
            {"label": "attacker_own_read", "kind": "http", "principal": "user2", "checkpoint": "before", "method": "GET", "path": "/api/<objects>/${attacker_object_id}"},
            {"label": "attacker_read", "kind": "http", "principal": "user2", "checkpoint": "action", "method": "GET", "path": "/api/<objects>/${owner_object_id}", "compare_to": "owner_read"},
            {"label": "anon_denied", "kind": "http", "principal": "anonymous", "checkpoint": "action", "method": "GET", "path": "/api/<objects>/${owner_object_id}"},
        ],
        "assertions": [
            {"type": "distinct_principals", "steps": ["owner_read", "attacker_read"], "predicate": "distinct_identity"},
            {"type": "comparison_equivalent", "control": "owner_read", "candidate": "attacker_read", "predicate": "ownership_established"},
            {"type": "comparison_equivalent", "control": "owner_read", "candidate": "attacker_read", "predicate": "cross_principal_access"},
            {"type": "status_not_in", "step": "anon_denied", "values": [200, 201, 202, 203, 204], "predicate": "denial_control"},
        ],
    },
    "data_exposure": {
        "proof_family": "data_exposure",
        "objective": "A sensitive value is exposed to an unauthorized principal",
        "expected_signal": "an unauthorized read returns a sensitive value",
        "falsifier": "no sensitive value is present",
        "steps": [
            {"label": "owner", "kind": "http", "principal": "user1", "checkpoint": "before", "method": "GET", "path": "/api/<resource>"},
            {"label": "exposed", "kind": "http", "principal": "anonymous", "checkpoint": "action", "method": "GET", "path": "/api/<resource>"},
        ],
        "assertions": [
            {"type": "status_in", "step": "exposed", "values": [200], "predicate": "sensitive_value_present"},
        ],
    },
    "auth_bypass": {
        "proof_family": "auth_bypass",
        "objective": "An anonymous request reaches a protected resource",
        "expected_signal": "the anonymous request succeeds where auth is required",
        "falsifier": "the anonymous request is denied",
        "steps": [
            {"label": "authed", "kind": "http", "principal": "user1", "checkpoint": "action", "method": "GET", "path": "/api/<protected>"},
            {"label": "anon", "kind": "http", "principal": "anonymous", "checkpoint": "action", "method": "GET", "path": "/api/<protected>", "compare_to": "authed"},
        ],
        "assertions": [
            {"type": "status_in", "step": "authed", "values": [200], "predicate": "protected_resource_accessed"},
            {"type": "status_not_in", "step": "anon", "values": [401, 403], "predicate": "unauthenticated_control"},
        ],
    },
    "access_control": {
        "proof_family": "access_control",
        "objective": "Test an approved deny/requires-role invariant with an authorized control and a distinct forbidden principal",
        "expected_signal": "the forbidden principal succeeds on the exact approved method and route",
        "falsifier": "the authorized control fails or the forbidden principal is denied",
        "steps": [
            {"label": "authorized", "kind": "http", "principal": "admin", "checkpoint": "action", "method": "GET", "path": "/api/<approved-route>"},
            {"label": "forbidden", "kind": "http", "principal": "user1", "checkpoint": "action", "method": "GET", "path": "/api/<approved-route>"},
        ],
        "assertions": [
            {"type": "status_in", "step": "authorized", "values": [200, 201, 202, 204], "predicate": "authorized_role_control"},
            {"type": "status_in", "step": "forbidden", "values": [200, 201, 202, 204], "predicate": "forbidden_role_access"},
            {"type": "distinct_principals", "steps": ["authorized", "forbidden"], "predicate": "distinct_identity"},
        ],
    },
    "field_constraint": {
        "proof_family": "field_constraint",
        "objective": "Test an approved field constraint with a bounded violating value and restore the original state",
        "expected_signal": "the out-of-policy value is accepted and persists in a live state read",
        "falsifier": "the mutation is rejected or the violating value does not persist",
        "steps": [
            {"label": "before", "kind": "http", "principal": "user1", "checkpoint": "before", "method": "GET", "path": "/api/<approved-route>", "select_json": ["$.<field>"]},
            {"label": "mutate", "kind": "http", "principal": "user1", "checkpoint": "mutation", "method": "PATCH", "path": "/api/<approved-route>", "json_body": {"<field>": "<violating-value>"}},
            {"label": "verify", "kind": "http", "principal": "user1", "checkpoint": "action", "method": "GET", "path": "/api/<approved-route>", "select_json": ["$.<field>"], "compare_to": "before"},
            {"label": "cleanup", "kind": "http", "principal": "user1", "checkpoint": "cleanup", "method": "PATCH", "path": "/api/<approved-route>", "json_body": {"<field>": "<original-value>"}},
            {"label": "after", "kind": "http", "principal": "user1", "checkpoint": "after", "method": "GET", "path": "/api/<approved-route>", "select_json": ["$.<field>"], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "status_in", "step": "before", "values": [200], "predicate": "constraint_baseline_observed"},
            {"type": "comparison_changed", "control": "before", "candidate": "verify", "predicate": "constraint_violation_persisted"},
            {"type": "restored", "control": "before", "candidate": "after", "predicate": "before_after_state"},
        ],
    },
    "workflow": {
        "proof_family": "workflow",
        "objective": "Test an approved state-transition invariant and restore the original state",
        "expected_signal": "the forbidden transition succeeds and the state changes outside the approved transition",
        "falsifier": "the transition is rejected or only the approved state change occurs",
        "steps": [
            {"label": "before", "kind": "http", "principal": "user1", "checkpoint": "before", "method": "GET", "path": "/api/<approved-route>", "select_json": ["$.status"]},
            {"label": "transition", "kind": "http", "principal": "user1", "checkpoint": "mutation", "method": "PATCH", "path": "/api/<approved-route>", "json_body": {"status": "<forbidden-state>"}},
            {"label": "verify", "kind": "http", "principal": "user1", "checkpoint": "action", "method": "GET", "path": "/api/<approved-route>", "select_json": ["$.status"], "compare_to": "before"},
            {"label": "cleanup", "kind": "http", "principal": "user1", "checkpoint": "cleanup", "method": "PATCH", "path": "/api/<approved-route>", "json_body": {"status": "<original-state>"}},
            {"label": "after", "kind": "http", "principal": "user1", "checkpoint": "after", "method": "GET", "path": "/api/<approved-route>", "select_json": ["$.status"], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "comparison_changed", "control": "before", "candidate": "verify", "predicate": "transition_invariant_broken"},
            {"type": "restored", "control": "before", "candidate": "after", "predicate": "before_after_state"},
        ],
    },
    "mass_assignment": {
        "proof_family": "mass_assignment",
        "objective": "A security-sensitive field is overposted and its exact value persists",
        "expected_signal": "the benign write succeeds and the added forbidden field persists with the submitted value",
        "falsifier": "the benign write fails, the forbidden field is rejected, or its exact value does not persist",
        # GENERIC privilege markers (never app-specific): the proof only fires when a persisted PRIVILEGE
        # elevation is accepted, so substitute <forbidden_field>/<forbidden_value> with one of these
        # instead of a benign field. Try the resource's own response field names first, then these.
        "forbidden_field_candidates": [
            {"field": "role", "value": "admin"},
            {"field": "roles", "value": ["admin"]},
            {"field": "isAdmin", "value": True},
            {"field": "is_admin", "value": True},
            {"field": "admin", "value": True},
            {"field": "verified", "value": True},
            {"field": "is_verified", "value": True},
            {"field": "permissions", "value": ["admin"]},
        ],
        "steps": [
            {"label": "before", "kind": "http", "principal": "user1", "checkpoint": "before", "method": "GET", "path": "/api/<resource>", "select_json": ["$.<forbidden_field>", "$.<allowed_field>"]},
            {"label": "control", "kind": "http", "principal": "user1", "checkpoint": "mutation", "method": "PATCH", "path": "/api/<resource>", "json_body": {"<allowed_field>": "<benign_value>"}},
            {"label": "mutate", "kind": "http", "principal": "user1", "checkpoint": "mutation", "method": "PATCH", "path": "/api/<resource>", "json_body": {"<allowed_field>": "<benign_value>", "<forbidden_field>": "<forbidden_value>"}},
            {"label": "verify", "kind": "http", "principal": "user1", "checkpoint": "action", "method": "GET", "path": "/api/<resource>", "select_json": ["$.<forbidden_field>"], "compare_to": "before"},
            {"label": "cleanup", "kind": "http", "principal": "user1", "checkpoint": "cleanup", "method": "PATCH", "path": "/api/<resource>", "json_body": {"<allowed_field>": "<original_allowed_value>", "<forbidden_field>": "<original_forbidden_value>"}},
            {"label": "after", "kind": "http", "principal": "user1", "checkpoint": "after", "method": "GET", "path": "/api/<resource>", "select_json": ["$.<forbidden_field>", "$.<allowed_field>"], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "status_in", "step": "control", "values": [200, 201, 202, 204], "predicate": "benign_control_accepted"},
            {"type": "status_in", "step": "mutate", "values": [200, 201, 202, 204], "predicate": "forbidden_field_accepted"},
            {"type": "comparison_changed", "control": "before", "candidate": "verify", "predicate": "observable_state_change"},
            {"type": "restored", "control": "before", "candidate": "after", "predicate": "before_after_state"},
        ],
    },
}






def _running_scan_worker_count_best_effort() -> int | None:
    """Return running scanner worker count, or None when Docker is unavailable.

    Auto-sharding should use real fleet capacity when the standard Docker
    deployment exposes it, but should not fail API requests in environments
    without a mounted Docker socket.
    """
    worker_ids = _running_scan_worker_container_ids_best_effort()
    return len(worker_ids) if worker_ids is not None else None
AUTO_SHARD_MAX_SHARDS = parallel_scan.MAX_SHARDS






def _running_scan_worker_container_ids_best_effort() -> list[str] | None:
    """Return live local worker container IDs, or None without Docker authority."""
    try:
        filters = urllib.parse.quote('{"name":["worker"]}')
        status_code, containers = docker_socket_request(
            "GET",
            f"/containers/json?all=true&filters={filters}",
        )
        if status_code != 200 or not isinstance(containers, list):
            return None
        compose_project = _local_compose_project_best_effort()
        worker_ids: list[str] = []
        for container in containers:
            if _is_local_scan_worker_container(
                container, compose_project=compose_project
            ) and container.get("State") == "running":
                container_id = str(container.get("Id") or "").lower()
                if container_id:
                    worker_ids.append(container_id)
        return worker_ids
    except Exception:
        return None
class AISettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ai_url: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_model: Optional[str] = None
    ai_model_fallback: Optional[str] = None
    ai_mask_host: Optional[str] = None
    ai_scan_classification_enabled: Optional[bool] = None
    ai_classify_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    ai_verify_enabled: Optional[bool] = None
    ai_verify_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    auto_retest_on_scan_complete: Optional[bool] = None
    auto_retest_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    auto_retest_max_per_scan: Optional[int] = Field(default=None, ge=0, le=500)
    # Unified verification policy fields
    verification_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    ai_escalation_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    proof_required_for_smart: Optional[bool] = None
    auto_fp_on_retest: Optional[bool] = None
    auto_fp_min_confidence: Optional[float] = Field(default=None, ge=AUTO_FP_MIN_CONFIDENCE_FLOOR, le=1.0)
    demo_mode_enabled: Optional[bool] = None
    demo_honey_public_url: Optional[str] = None
    demo_honey_scanner_url: Optional[str] = None

    @model_validator(mode="after")
    def validate_verification_threshold_hierarchy(self):
        aliases = (
            ("verification_min_severity", self.verification_min_severity,
             "auto_retest_min_severity", self.auto_retest_min_severity),
            ("ai_escalation_min_severity", self.ai_escalation_min_severity,
             "ai_verify_min_severity", self.ai_verify_min_severity),
        )
        for canonical_name, canonical, legacy_name, legacy in aliases:
            if canonical is not None and legacy is not None and canonical != legacy:
                raise ValueError(f"{legacy_name} must match canonical {canonical_name}")
        verification = self.verification_min_severity or self.auto_retest_min_severity
        ai_escalation = self.ai_escalation_min_severity or self.ai_verify_min_severity
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if verification and ai_escalation and severity_order[ai_escalation] < severity_order[verification]:
            raise ValueError(
                "ai_escalation_min_severity cannot be broader than verification_min_severity"
            )
        return self


def _validate_effective_ai_threshold_update(
    request: AISettingsUpdate,
    current: Mapping[str, Any],
) -> None:
    """Validate a partial update against the policy it will actually produce."""
    verification = (
        request.verification_min_severity
        or request.auto_retest_min_severity
        or current.get("verification_min_severity")
        or current.get("auto_retest_min_severity")
        or "medium"
    )
    escalation = (
        request.ai_escalation_min_severity
        or request.ai_verify_min_severity
        or current.get("ai_escalation_min_severity")
        or current.get("ai_verify_min_severity")
        or "high"
    )
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    verification = str(verification or "medium").strip().lower()
    escalation = str(escalation or "high").strip().lower()
    if verification not in severity_order:
        verification = "medium"
    if escalation not in severity_order:
        escalation = "high"
    if severity_order[escalation] < severity_order[verification]:
        raise HTTPException(
            status_code=422,
            detail=(
                "ai_escalation_min_severity cannot be broader than the effective "
                "verification_min_severity"
            ),
        )


class ScanExecutionSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auto_sharding_enabled: Optional[bool] = None
    auto_sharding_strategy: Optional[str] = Field(default=None, pattern="^(auto|scope|family|coverage|coverage_family)$")
    auto_sharding_max_shards: Optional[int] = Field(default=None, ge=2, le=AUTO_SHARD_MAX_SHARDS)
    auto_sharding_min_workers: Optional[int] = Field(default=None, ge=1, le=20)


class AutomationSettingsUpdate(ScanExecutionSettingsUpdate):
    default_asm_enabled: Optional[bool] = None
    default_asm_config: Optional[dict[str, Any]] = None
    approval_receipts_required_for_state_changing_actions: Optional[bool] = None
    intel_curated_briefings: Optional[bool] = None
    intel_vendor_declared_ranges: Optional[bool] = None


class AISettingsProbeRequest(BaseModel):
    scope: str = Field(default="scan", pattern="^(scan|verify)$")
    ai_url: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_model: Optional[str] = None
    ai_fallback_model: Optional[str] = None

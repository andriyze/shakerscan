"""Content-free authority and bounded saved configuration for browser login QA.

A planner selects a managed principal; only the operator who saves/rotates its
profile authors the login and QA workflow. No script, arbitrary click sequence,
request body, or credential is accepted by the action contract.
"""
from __future__ import annotations

from dataclasses import asdict, fields
from typing import Any, Mapping
import uuid

BROWSER_LOGIN_CAPABILITY = "browser.login_check"
BROWSER_LOGIN_PROFILE_SCHEMA = "browser-login-profile/v1"
BROWSER_LOGIN_BUDGET = {
    "http_requests": 128, "state_changing_requests": 1,
    "browser_actions": 32, "tool_wall_seconds": 210,
}
PRINCIPAL_SLOTS = ("primary", "secondary", "service")
PROFILE_REF_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "profile_id": {"type": "string", "format": "uuid"},
        "profile_version": {"type": "integer", "minimum": 1},
        "principal_slot": {"type": "string", "enum": list(PRINCIPAL_SLOTS)},
    },
    "required": ["profile_id", "profile_version", "principal_slot"],
}
BROWSER_LOGIN_INPUT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "as_principal": {"type": "string", "enum": list(PRINCIPAL_SLOTS)},
        "profile_ref": PROFILE_REF_SCHEMA,
    },
    "required": ["as_principal"],
}
BROWSER_LOGIN_PLANNER_SCHEMA = {
    **BROWSER_LOGIN_INPUT_SCHEMA,
    "properties": {"as_principal": BROWSER_LOGIN_INPUT_SCHEMA["properties"]["as_principal"]},
}


def normalize_browser_login_reference(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(PROFILE_REF_SCHEMA["properties"]):
        raise ValueError("browser login profile reference is invalid")
    version, slot = value["profile_version"], value["principal_slot"]
    if type(version) is not int or version < 1 or slot not in PRINCIPAL_SLOTS:
        raise ValueError("browser login profile reference is invalid")
    try:
        profile_id = str(uuid.UUID(value["profile_id"]))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("browser login profile reference is invalid") from None
    return {"profile_id": profile_id, "profile_version": version, "principal_slot": slot}


def normalize_browser_login_profile(value: Any) -> dict[str, Any]:
    # Import lazily: registry/credential metadata must never load Chromium.
    try:
        from capabilities.browser_login import (
            BrowserLoginWorkflow, BrowserLoginValues, BrowserReadOnlyCheck,
            _validate, _validate_selector, _url,
        )
    except ModuleNotFoundError:
        from ..capabilities.browser_login import (
            BrowserLoginWorkflow, BrowserLoginValues, BrowserReadOnlyCheck,
            _validate, _validate_selector, _url,
        )
    try:
        if (not isinstance(value, Mapping)
                or set(value) != {"schema_version", "workflow", "checks"}
                or value["schema_version"] != BROWSER_LOGIN_PROFILE_SCHEMA):
            raise ValueError
        raw, checks = value["workflow"], value["checks"]
        if not isinstance(raw, Mapping) or not isinstance(checks, list) or len(checks) > 20:
            raise ValueError
        if set(raw) - {item.name for item in fields(BrowserLoginWorkflow)}:
            raise ValueError
        workflow = BrowserLoginWorkflow(**raw)
        origin = _validate(workflow, BrowserLoginValues("validation-only", "validation-only"))
        if (workflow.max_requests > BROWSER_LOGIN_BUDGET["http_requests"]
                or workflow.timeout_ms + workflow.qa_timeout_ms > 180_000
                or workflow.max_response_bytes > 2 * 1024 * 1024):
            raise ValueError
        normalized_checks = []
        for check in checks:
            if not isinstance(check, Mapping) or set(check) != {"url", "visible_selector"}:
                raise ValueError
            item = BrowserReadOnlyCheck(**check)
            if _url(item.url, origin) != item.url:
                raise ValueError
            _validate_selector(item.visible_selector)
            normalized_checks.append(asdict(item))
        return {"schema_version": BROWSER_LOGIN_PROFILE_SCHEMA,
                "workflow": asdict(workflow), "checks": normalized_checks}
    except (TypeError, ValueError, UnicodeError, RecursionError):
        # URLs, selectors and configuration can contain private application data.
        raise ValueError("browser login profile configuration is invalid") from None


def require_browser_login_policy(policy: Any) -> None:
    def flag(name: str) -> Any:
        return policy.get(name) if isinstance(policy, Mapping) else getattr(policy, name, None)
    if not (flag("active_testing") is True and flag("allow_state_changing_http") is True):
        raise ValueError("browser login requires active_testing and allow_state_changing_http")
    if not flag("approval_receipt_id") or not flag("scope_receipt_id"):
        raise ValueError("browser login requires target-bound credential approval")


def browser_login_action_arguments(references, *, policy, max_workers, scope, continuation_round):
    """Compile exactly once, preserving the profile version in the action digest."""
    if not references:
        return ()
    require_browser_login_policy(policy)
    if max_workers != 1 or scope != "full" or continuation_round != 0:
        raise ValueError("browser login QA cannot be duplicated into shards or continuation rounds")
    if not isinstance(references, (list, tuple)) or not 1 <= len(references) <= 2:
        raise ValueError("browser login profile references are invalid")
    refs = tuple(normalize_browser_login_reference(item) for item in references)
    if (len({item["profile_id"] for item in refs}) != len(refs)
            or len({item["principal_slot"] for item in refs}) != len(refs)):
        raise ValueError("browser login profile references are ambiguous")
    return tuple({"as_principal": item["principal_slot"], "profile_ref": item} for item in refs)

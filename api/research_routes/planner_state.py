"""Who advances a research episode, and why it is not advancing.

A research episode in ``awaiting_planner`` is advanced by exactly one of two drivers:

* the in-process server autopilot (``research_autopilot_runner`` in the API lifespan), which
  only claims rows with ``autopilot_enabled=true`` and only runs when the API is not in
  ``FLEET_EDGE_MODE``; it plans with the stored/configured AI provider (``configured_ai``);
* an external coding agent (``agent``/``local_codex``) that submits decisions itself.

Before this module, ``POST /research/episodes`` persisted ``autopilot_enabled`` only from the
``autopilot`` boolean, so an episode created with ``planner.mode=configured_ai`` (or created
from a client that assumed the configured model would drive it) was stored as an agent-driven
episode. The runner never claimed it and nothing said so: it sat at ``awaiting_planner`` until
the abandoned-episode reaper cancelled it. These helpers make the create request resolve one
consistent driver and make every episode read name what it is waiting for.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from typing import Any

PLANNER_MODES = frozenset({"configured_ai", "agent", "local_codex"})
PLANNER_KINDS = {
    "configured_ai": "configured_ai",
    "local_codex": "local_agent",
    "agent": "interactive_agent",
}
# Stored AI settings key -> the environment variable an operator sets for it.
CONFIGURED_PLANNER_SETTINGS = {
    "ai_url": "AI_URL",
    "ai_api_key": "AI_API_KEY",
    "ai_model": "AI_MODEL",
}
AUTOPILOT_MAX_CONSECUTIVE_FAILURES = 3


class PlannerModeConflict(ValueError):
    """The create request names a planner that cannot be combined with its autopilot flag."""


def configured_planner_missing_settings(settings: Mapping[str, Any]) -> list[str]:
    """The AI settings the configured-provider planner needs but does not have."""
    return [
        key for key in CONFIGURED_PLANNER_SETTINGS if not str(settings.get(key) or "").strip()
    ]


def autopilot_runner_active(environ: Mapping[str, str] = os.environ) -> bool:
    """Mirror of the API lifespan rule: fleet-edge API processes start no background controllers."""
    return str(environ.get("FLEET_EDGE_MODE", "")).strip().lower() not in {"1", "true", "yes", "on"}


def resolve_create_planner(
    planner: Mapping[str, Any],
    *,
    autopilot: bool,
    autopilot_explicit: bool,
) -> tuple[str | None, bool]:
    """Resolve (planner mode, autopilot_enabled) for a new episode.

    ``planner.mode`` (or ``planner.kind=configured_ai``) naming the configured provider means the
    server drives the episode unless the caller explicitly created it paused (``autopilot: false``).
    ``autopilot: true`` without a mode means ``configured_ai``. An agent planner cannot be combined
    with server autopilot. Returns ``(None, False)`` for the unchanged legacy agent default.
    """
    raw_mode = str(planner.get("mode") or "").strip().lower()
    raw_kind = str(planner.get("kind") or "").strip().lower()
    if raw_mode and raw_mode not in PLANNER_MODES:
        raise PlannerModeConflict(
            f"Unsupported planner.mode {raw_mode!r}; use one of {', '.join(sorted(PLANNER_MODES))}"
        )
    mode = raw_mode or ("configured_ai" if raw_kind == "configured_ai" else "")
    if autopilot and mode and mode != "configured_ai":
        raise PlannerModeConflict(
            "Only planner.mode=configured_ai uses server autopilot; agent planners submit "
            "decisions through POST /research/episodes/{id}/decisions"
        )
    if autopilot:
        return "configured_ai", True
    if mode == "configured_ai":
        return "configured_ai", not autopilot_explicit
    return (mode or None), False


def _missing_env(missing_settings: Sequence[str]) -> list[str]:
    return [CONFIGURED_PLANNER_SETTINGS.get(key, key) for key in missing_settings]


def research_planner_state(
    episode: Mapping[str, Any],
    *,
    planner_mode: str,
    missing_settings: Sequence[str],
    runner_active: bool,
    active_work: Sequence[Any] = (),
) -> dict[str, Any]:
    """Explain who must act next on an episode and, when nothing will, exactly why."""
    status = str(episode.get("status") or "")
    autopilot = bool(episode.get("autopilot_enabled"))
    last_error = str(episode.get("autopilot_error") or "").strip()[:500] or None
    failures = int(episode.get("autopilot_consecutive_failures") or 0)
    episode_id = str(episode.get("id") or "{id}")
    resume = (
        f"PUT /research/episodes/{episode_id}/autopilot "
        '{"enabled": true, "planner_mode": "configured_ai"}'
    )
    state: dict[str, Any] = {
        "mode": planner_mode,
        "server_autopilot": autopilot,
        "autopilot_runner_active": runner_active,
        "engine_will_advance": False,
        "waiting_for": None,
        "blocked_reason": None,
        "missing_settings": [],
        "missing_env": [],
        "last_error": last_error,
        "consecutive_failures": failures,
        "next_action": None,
    }
    if bool(episode.get("terminal")):
        return state
    if status == "awaiting_observation" or (status == "awaiting_planner" and active_work):
        state["waiting_for"] = "linked_work"
        state["engine_will_advance"] = autopilot and runner_active
        state["next_action"] = "Wait for the linked scan or retest listed in waiting_on to settle"
        if autopilot and not runner_active:
            state["blocked_reason"] = "autopilot_runner_not_running"
        return state
    if status == "awaiting_input":
        state["waiting_for"] = "operator_input"
        state["next_action"] = "Answer the episode's requested_input"
        return state
    if status != "awaiting_planner":
        # created/planning/validating_decision/dispatching are transient engine-owned states.
        state["waiting_for"] = "engine"
        state["engine_will_advance"] = True
        return state

    if planner_mode != "configured_ai":
        state["waiting_for"] = "external_planner_decision"
        state["blocked_reason"] = "server_autopilot_not_enabled"
        state["next_action"] = (
            f"This {planner_mode} episode is advanced only by a coding agent submitting "
            f"POST /research/episodes/{episode_id}/decisions. To have the engine's configured "
            f"model drive it, {resume} (or create it with \"autopilot\": true)."
        )
        if missing_settings:
            state["missing_settings"] = list(missing_settings)
            state["missing_env"] = _missing_env(missing_settings)
        return state

    if missing_settings:
        state["waiting_for"] = "ai_provider_configuration"
        state["blocked_reason"] = "configured_ai_provider_not_configured"
        state["missing_settings"] = list(missing_settings)
        state["missing_env"] = _missing_env(missing_settings)
        state["next_action"] = (
            "Configure the engine's AI provider (" + ", ".join(state["missing_env"])
            + ") in the API environment or AI settings"
        )
        return state
    if not autopilot:
        state["waiting_for"] = "server_autopilot_resume"
        if last_error and failures >= AUTOPILOT_MAX_CONSECUTIVE_FAILURES:
            state["blocked_reason"] = "autopilot_paused_after_planner_failures"
            state["next_action"] = (
                "Fix the planner error in last_error (model, provider or structured-output "
                f"support), then {resume}"
            )
        else:
            state["blocked_reason"] = "autopilot_paused"
            state["next_action"] = resume
        return state
    if not runner_active:
        state["waiting_for"] = "server_autopilot"
        state["blocked_reason"] = "autopilot_runner_not_running"
        state["next_action"] = (
            "This API process runs with FLEET_EDGE_MODE and starts no research autopilot; run "
            "the control-plane API (FLEET_EDGE_MODE unset) against the same database"
        )
        return state
    state["waiting_for"] = "server_autopilot"
    state["engine_will_advance"] = True
    if last_error:
        state["next_action"] = "The server autopilot is retrying after a planner error (see last_error)"
    return state


__all__ = [
    "AUTOPILOT_MAX_CONSECUTIVE_FAILURES",
    "CONFIGURED_PLANNER_SETTINGS",
    "PLANNER_KINDS",
    "PLANNER_MODES",
    "PlannerModeConflict",
    "autopilot_runner_active",
    "configured_planner_missing_settings",
    "research_planner_state",
    "resolve_create_planner",
]

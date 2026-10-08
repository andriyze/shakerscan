"""Bind Hunt coverage claims to same-Hunt actions that actually ran.

Evidence rules (documented in docs/hunt-architecture.md and skills/hunt/SKILL.md):

* Every cited action must belong to this exact Hunt and be settled
  (``completed``, ``partial`` or ``blocked``).
* A queue handoff is never evidence. An action whose result only says that
  downstream work was ``queued`` (device posture queue, confirmed SSH plan) has
  not examined anything yet, whatever its action status says.
* An action *executed* when it is ``completed`` or ``partial`` and its settled
  budget records target traffic (requests, browser actions, ports, hosts or OOB
  interactions). Admission-only, refused and analysis-only actions sent none.
* ``negative`` needs every cited action completed and executed, and no
  contradictory evidence. ``partial`` needs at least one executed action.
  ``blocked`` may be recorded from its blocker text alone; when it cites actions,
  at least one must have executed. A pure policy refusal is a blocker sentence,
  not evidence. ``candidate`` may not cite a refused (``blocked``) action.
* Every action a ``negative`` or ``partial`` claim cites must be related to the angle
  (``action_relation``): where both name a route, the action addressed that route; where
  both name a service (host or port), the same service; and a family-specific capability
  (``xss.verify``, ``sqli.verify``, ``authz.verify``) only supports its own family, a
  network capability only a service-level angle. An action that addressed the whole
  target without a route (a crawl, a content discovery) is related at the target level.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import re
from typing import Any
import urllib.parse
from uuid import UUID

TERMINAL_ACTION_STATUSES = frozenset({"completed", "partial", "blocked"})
EXECUTED_ACTION_STATUSES = frozenset({"completed", "partial"})
# Settled budget dimensions that can only be spent by sending something to a target.
# tool_wall_seconds, agent_actions and active_actions are admission/runtime charges.
EXECUTED_TRAFFIC_DIMENSIONS = frozenset({
    "http_requests",
    "state_changing_requests",
    "browser_actions",
    "tcp_ports_attempted",
    "udp_ports_attempted",
    "hosts_attempted",
    "oob_interactions",
})


# Capabilities whose proof applies to one vulnerability family; the tokens a family name must
# contain for the capability to support it.
FAMILY_SPECIFIC_CAPABILITIES: dict[str, frozenset[str]] = {
    "xss.verify": frozenset({"xss", "scripting"}),
    "sqli.verify": frozenset({"sqli", "sql"}),
    "authz.verify": frozenset({
        "authz", "authorization", "access", "bola", "idor", "bfla", "privilege",
    }),
}
# Network and service capabilities examine ports and services, never an HTTP route.
NETWORK_CAPABILITIES = frozenset({
    "ports.discover", "service.fingerprint", "service.nse_check", "service.snmp.inspect",
    "device.service.verify", "ssh.connect", "ssh.exec", "ssh.close", "tls.inspect",
})
_ROUTE_LOCUS_KEYS = ("route", "path", "url")
_ACTION_PATH_KEYS = ("path", "endpoint_path")
_PLACEHOLDER = re.compile(r"^(?:\{[^/{}]*\}|<[^/<>]*>|:[A-Za-z_][\w-]*|\*)$")
_IDENTIFIER = re.compile(r"^(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{36})$")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class CoverageLedgerError(ValueError):
    """A coverage event is structurally invalid or overclaims its evidence."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 422,
        details: Mapping[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.details = dict(details or {})


def _decoded(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None
    return value


def is_queue_handoff(result_summary: Any) -> bool:
    """True when the action only handed work to a queue that has not reported back."""
    summary = _decoded(result_summary)
    if not isinstance(summary, Mapping):
        return False
    if str(summary.get("status") or "").strip().lower() == "queued":
        return True
    if isinstance(summary.get("queued"), Mapping) or summary.get("queued_scan"):
        return True
    observations = summary.get("receipt_observations")
    if isinstance(observations, Sequence) and not isinstance(observations, (str, bytes)):
        for item in observations:
            if isinstance(item, Mapping) and str(item.get("status") or "").lower() == "queued":
                return True
    return False


def measured_target_traffic(result_summary: Any) -> int:
    """Return settled target-traffic units; unknown or legacy accounting counts as none."""
    summary = _decoded(result_summary)
    if not isinstance(summary, Mapping):
        return 0
    accounting = summary.get("budget_accounting")
    actual = accounting.get("actual") if isinstance(accounting, Mapping) else None
    if not isinstance(actual, Mapping):
        actual = summary.get("budget_consumed")
    if not isinstance(actual, Mapping):
        return 0
    total = 0
    for name, amount in actual.items():
        if str(name) not in EXECUTED_TRAFFIC_DIMENSIONS or isinstance(amount, bool):
            continue
        if isinstance(amount, (int, float)) and amount > 0:
            total += int(amount)
    return total


def _path_of(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    path = urllib.parse.urlsplit(text).path if "://" in text else text.split("?", 1)[0].split("#", 1)[0]
    path = "/" + path.strip("/") if path.strip("/") else "/"
    return path


def _service_of(value: Any) -> tuple[str | None, int | None]:
    text = str(value or "").strip()
    if "://" not in text:
        return None, None
    parts = urllib.parse.urlsplit(text)
    try:
        port = parts.port or _DEFAULT_PORTS.get(parts.scheme.lower())
    except ValueError:
        port = None
    return (parts.hostname or "").lower() or None, port


def _port_ranges(value: Any) -> list[tuple[int, int]]:
    """Ports named by an action input (an integer, a list, "80,443" or "1-1024") as ranges."""
    items = value if isinstance(value, (list, tuple)) else str(value or "").replace(",", " ").split()
    ranges = []
    for item in items:
        low, _, high = str(item).strip().partition("-")
        if low.isdigit() and (not high or high.isdigit()):
            ranges.append((int(low), int(high or low)))
    return ranges


def action_locations(capability: str | None, input_summary: Any) -> dict[str, Any]:
    """What one recorded action addressed: routes, hosts and ports from its own input."""
    summary = _decoded(input_summary)
    values = summary.get("input") if isinstance(summary, Mapping) else None
    values = values if isinstance(values, Mapping) else {}
    paths = {path for key in _ACTION_PATH_KEYS if (path := _path_of(values.get(key)))}
    host, port = _service_of(values.get("origin"))
    ports = [(port, port)] if port else []
    for key in ("port", "ports", "port_range", "origin_port"):
        ports.extend(_port_ranges(values.get(key)))
    return {
        "capability": str(capability or "") or None,
        "paths": sorted(paths), "host": host, "ports": sorted(set(ports)),
    }


def _segments_match(route: str, path: str) -> bool:
    left, right = route.strip("/").split("/"), path.strip("/").split("/")
    if len(left) != len(right):
        return False
    for a, b in zip(left, right):
        if a == b or _PLACEHOLDER.match(a) or _PLACEHOLDER.match(b):
            continue
        if _IDENTIFIER.match(a) and _IDENTIFIER.match(b):
            continue
        return False
    return True


def _family_tokens(family: Any) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", str(family or "").lower()) if token}


def action_relation(angle: Mapping[str, Any], action: Mapping[str, Any]) -> str | None:
    """``None`` when the action is related to the angle, otherwise why it is not."""
    locus = angle.get("locus") if isinstance(angle.get("locus"), Mapping) else {}
    capability = action.get("capability")
    routes = {path for key in _ROUTE_LOCUS_KEYS if (path := _path_of(locus.get(key)))}
    host, port = None, None
    for key in ("origin", "url"):
        host, port = _service_of(locus.get(key))
        if host:
            break
    angle_ports = {int(locus["port"])} if str(locus.get("port") or "").isdigit() else (
        {port} if port else set())
    if capability in NETWORK_CAPABILITIES and routes:
        return f"{capability} examines services, not the route {sorted(routes)[0]}"
    allowed = FAMILY_SPECIFIC_CAPABILITIES.get(str(capability or ""))
    if allowed is not None and not allowed & _family_tokens(angle.get("family")):
        return f"{capability} does not test the {angle.get('family')} family"
    paths = action.get("paths") or []
    if routes and paths and not any(_segments_match(r, p) for r in routes for p in paths):
        return f"it addressed {', '.join(paths[:3])}, not {', '.join(sorted(routes))}"
    if host and action.get("host") and host != action["host"]:
        return f"it addressed host {action['host']}, not {host}"
    ranges = action.get("ports") or []
    if angle_ports and ranges and not any(
        low <= port <= high for port in angle_ports for low, high in ranges
    ):
        shown = ", ".join(str(low) if low == high else f"{low}-{high}" for low, high in ranges[:5])
        return f"it addressed port {shown}, not {', '.join(str(p) for p in sorted(angle_ports))}"
    return None


async def owned_action_evidence(
    conn: Any, *, hunt_run_id: str, action_ids: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """Load cited actions from this exact Hunt and classify what each one did."""
    if not action_ids:
        return {}
    rows = await conn.fetch(
        """SELECT id, status, result_summary, capability_name, input_summary
           FROM hunt_actions
           WHERE hunt_run_id=$1::uuid AND id = ANY($2::uuid[])""",
        hunt_run_id,
        [UUID(item) for item in action_ids],
    )
    evidence: dict[str, dict[str, Any]] = {}
    for row in rows:
        status = str(row["status"])
        summary = row.get("result_summary") if hasattr(row, "get") else row["result_summary"]
        item = dict(row) if hasattr(row, "keys") else {}
        evidence[str(row["id"])] = {
            **action_locations(item.get("capability_name"), item.get("input_summary")),
            "status": status,
            "queue_handoff": is_queue_handoff(summary),
            "executed": (
                status in EXECUTED_ACTION_STATUSES
                and not is_queue_handoff(summary)
                and measured_target_traffic(summary) > 0
            ),
        }
    if set(action_ids) - set(evidence):
        raise CoverageLedgerError(
            "coverage_evidence_not_owned",
            "Coverage evidence must be actions from this exact Hunt",
        )
    if any(item["status"] not in TERMINAL_ACTION_STATUSES for item in evidence.values()):
        raise CoverageLedgerError(
            "coverage_evidence_not_terminal",
            "Coverage evidence must be a completed, partial, or blocked Hunt action",
        )
    if any(item["queue_handoff"] for item in evidence.values()):
        raise CoverageLedgerError(
            "coverage_evidence_queued_handoff",
            "A queue handoff is not evidence: its downstream work has not reported a result",
        )
    return evidence


def validate_evidence_claim(
    angle: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]],
) -> None:
    status = str(angle["status"])
    cited = [evidence[item] for item in angle.get("evidence_action_ids") or [] if item in evidence]
    if status == "negative":
        if any(item["status"] != "completed" for item in cited):
            raise CoverageLedgerError(
                "coverage_negative_requires_completed_actions",
                "Negative coverage may cite only completed actions; partial/blocked work is a gap",
            )
        if any(not item["executed"] for item in cited):
            raise CoverageLedgerError(
                "coverage_negative_requires_executed_actions",
                "Negative coverage may cite only actions that sent target traffic",
            )
        if angle.get("contradictory_evidence_action_ids"):
            raise CoverageLedgerError(
                "coverage_negative_has_contradictory_evidence",
                "Negative coverage cannot close an angle while contradictory evidence remains",
            )
    if status in {"partial", "blocked"} and cited and not any(item["executed"] for item in cited):
        raise CoverageLedgerError(
            "coverage_evidence_not_executed",
            f"{status} coverage must cite at least one same-Hunt action that sent target traffic",
        )
    if status == "candidate" and any(item["status"] == "blocked" for item in cited):
        raise CoverageLedgerError(
            "coverage_candidate_requires_executed_evidence",
            "Candidate coverage cannot cite a blocked (refused) action",
        )
    if status in {"negative", "partial"}:
        unrelated = {
            action_id: reason
            for action_id in angle.get("evidence_action_ids") or []
            if action_id in evidence
            and (reason := action_relation(angle, evidence[action_id])) is not None
        }
        if unrelated:
            first_id, first_reason = next(iter(unrelated.items()))
            raise CoverageLedgerError(
                "coverage_evidence_unrelated",
                f"{status} coverage must cite actions that examined this angle; action "
                f"{first_id} is unrelated: {first_reason}",
                details={"unrelated_evidence": [
                    {"action_id": action_id, "reason": reason}
                    for action_id, reason in unrelated.items()
                ]},
            )


__all__ = [
    "EXECUTED_ACTION_STATUSES",
    "EXECUTED_TRAFFIC_DIMENSIONS",
    "FAMILY_SPECIFIC_CAPABILITIES",
    "NETWORK_CAPABILITIES",
    "TERMINAL_ACTION_STATUSES",
    "CoverageLedgerError",
    "action_locations",
    "action_relation",
    "is_queue_handoff",
    "measured_target_traffic",
    "owned_action_evidence",
    "validate_evidence_claim",
]

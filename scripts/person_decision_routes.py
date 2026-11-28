"""The engine routes that record a person's decision, and the command the person runs for each.

An AI agent never makes a person's decision: it asks, a person decides, and the agent reads the
outcome. ``shakerscan api`` (api_cli.py) reads this list. Inside an agent that ``shakerscan agent``
launched (SHAKERSCAN_AGENT_NAME is set, the signal hunt_approve.person_at_terminal uses), and
anywhere stdin and stdout are not both a terminal (an agent started without the launcher runs it
from a shell tool; a person's own script opts out with SHAKERSCAN_PERSON_SCRIPT=1), it refuses
every request listed here before anything is sent, and prints the one command the person runs in
their own terminal instead, and how the agent reads the outcome afterwards.

What this is and is not:

- On an open-source engine without authentication this is a guard rail for an agent that follows
  its kit, not a security boundary: any process on the host can call the API directly (curl, its
  own HTTP client), and an agent that unsets the variable or sets the script opt-out is not
  stopped here.
- ShakerScan Enterprise enforces person decisions on the server: its gateway refuses them from a
  service token unless the person proves the decision with their own security key.

The list is the engine's own person-only decisions: every route that records an approval, an
authorization, a grant, an acceptance of risk, a reveal of a secret value or an operator setting,
and every route that changes or withdraws one of those (a revocation, a changed trust anchor, a
deleted exception): what a person decided stays decided until a person decides otherwise.
tests/test_person_decision_routes.py reads every method the engine serves on these resources, so a
new verb on one is classified there or fails.
A route whose body decides whether it is one (a finding's status, a target registered together
with its authorization) names that test in ``when``; a body that is not a JSON object counts as
the decision (fail closed).
"""

from __future__ import annotations

import json
import re
import shlex
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

#: The statuses and triage verdicts that dismiss a finding: a person's decision.
DISMISSING_STATUSES = frozenset({"false_positive", "accepted_risk"})
DISMISSING_VERDICTS = frozenset({"false_positive", "accepted_risk", "duplicate"})
# A path value used as one word of the person's command: an id or a plain name, never an option.
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")


def _object(body: Any) -> Mapping[str, Any] | None:
    return body if isinstance(body, Mapping) else None


def _always(body: Any) -> bool:
    return True


def _dismisses_finding(body: Any) -> bool:
    payload = _object(body)
    if payload is None:
        return True
    return payload.get("status") in DISMISSING_STATUSES or payload.get("analyst_verdict") in DISMISSING_VERDICTS


def _dismisses_findings(body: Any) -> bool:
    payload = _object(body)
    return payload is None or payload.get("status") in DISMISSING_STATUSES


def _names(field: str) -> Callable[[Any], bool]:
    def asks(body: Any) -> bool:
        payload = _object(body)
        return payload is None or payload.get(field) is not None
    return asks


def _confirms(field: str) -> Callable[[Any], bool]:
    def asks(body: Any) -> bool:
        payload = _object(body)
        return payload is None or payload.get(field, False) is not False
    return asks


@dataclass(frozen=True)
class PersonRoute:
    """One route that records a person's decision.

    ``command``: the dedicated command the person runs, with ``{name}`` for the path's values;
    None, or a value that is not one plain word, names exactly the request through ``shakerscan
    api`` (person_decision.person_command), which the person runs in their own terminal.
    ``outcome``: how the agent reads the decision once the person made it."""

    method: str
    template: str
    summary: str
    outcome: str
    command: str | None = None
    when: Callable[[Any], bool] = _always

    @property
    def pattern(self) -> re.Pattern[str]:
        return re.compile("".join(
            f"(?P<{part[1:-1]}>[^/]+)" if part.startswith("{") else re.escape(part)
            for part in re.split(r"(\{[a-z_]+\})", self.template)
        ))


_READ_TARGET_AUTHORIZATION = "read GET /targets/{target_id}/authorization"
_READ_HUNT = "read the Hunt (shakerscan_hunt_get, or GET /hunts/{hunt_id})"
_READ_SECRETS = "read the secret's state with `shakerscan secrets list {target_id}` (never its value)"
_READ_PROPOSALS = "read GET /targets/{target_id}/instruction-proposals"
_READ_FINDING = "read GET /findings/{finding_id}"
_SETTINGS = "read GET {path}"

ROUTES: tuple[PersonRoute, ...] = (
    # Hunt permissions and budget.
    PersonRoute("POST", "/hunts/{hunt_id}/permission-requests/{request_id}/decision",
                "allowing or denying a Hunt permission request",
                "wait with shakerscan_hunt_permission_wait (or GET "
                "/hunts/{hunt_id}/permission-requests/{request_id}); on granted, repeat the refused call "
                "with the same idempotency_key",
                command="shakerscan {verb} {request_id}"),
    PersonRoute("POST", "/hunts/{hunt_id}/permission-grants/{grant_id}/revoke",
                "revoking a Hunt permission grant", "read GET /hunts/{hunt_id}/permission-grants"),
    PersonRoute("POST", "/hunts/{hunt_id}/budget-amendments", "raising a Hunt's budget",
                "read the Hunt's budget (shakerscan_hunt_get); a budget.raise permission request the "
                "Hunt raised itself is approved with `shakerscan approve <request-id>`"),
    PersonRoute("POST", "/hunts/{hunt_id}/shell-plans/{plan_id}/confirm",
                "confirming a device SSH plan's exact commands and their effects", _READ_HUNT),
    PersonRoute("POST", "/hunts/{hunt_id}/authorization-investigations/{proposal_id}/approve",
                "approving an authorization investigation",
                "read GET /hunts/{hunt_id}/authorization-investigations/{proposal_id}"),
    # A target's authorization and Hunt authority.
    PersonRoute("POST", "/targets/{target_id}/authorization", "authorizing a target for active testing",
                _READ_TARGET_AUTHORIZATION),
    PersonRoute("DELETE", "/targets/{target_id}/authorization",
                "withdrawing a target's authorization for active testing", _READ_TARGET_AUTHORIZATION,
                command="shakerscan targets unauthorize {target_id}"),
    PersonRoute("POST", "/targets", "registering a target together with its authorization for active testing",
                "find the target with GET /targets/lookup?url=<url>, then read its authorization",
                when=_names("authorized_by")),
    PersonRoute("POST", "/targets/hosts", "registering a host together with its authorization for active testing",
                "find the target with GET /targets?limit=200, then read its authorization",
                when=_names("approved_by")),
    PersonRoute("PUT", "/targets/{target_id}/hunt-authority", "setting a target's standing Hunt authority",
                "read GET /targets/{target_id}/hunt-authority"),
    PersonRoute("POST", "/devices/{device_id}/verify-service",
                "confirming you are authorized to probe a connected device's service",
                "read GET /devices/{device_id}", when=_confirms("confirm_authorized")),
    # Approval receipts and what they unlock.
    PersonRoute("POST", "/arsenal/approvals", "recording an approval receipt (scope, credential or dangerous tier)",
                "ask the person for the approval receipt id their command printed"),
    PersonRoute("POST", "/arsenal/approvals/{approval_receipt_id}/revoke", "revoking an approval receipt",
                "ask the person whether it was revoked"),
    PersonRoute("POST", "/data-deletion/execute", "permanently deleting records (a reviewed deletion preview)",
                "ask the person for the deletion receipt their command printed"),
    PersonRoute("POST", "/evidence/retention/sweep", "running an evidence retention sweep",
                "read GET /evidence/retention/executions"),
    # Credentials and discovered secrets.
    PersonRoute("POST", "/credential-profiles/{profile_id}/grants", "sharing a saved credential with another target",
                "read GET /credential-profiles/{profile_id}/grants"),
    PersonRoute("DELETE", "/credential-profiles/{profile_id}/grants/{target_id}",
                "ending a saved credential's sharing with another target",
                "read GET /credential-profiles/{profile_id}/grants"),
    PersonRoute("POST", "/targets/{target_id}/discovered-secrets/{secret_id}/reveal",
                "revealing a discovered secret's value (to the person, in their own terminal)", _READ_SECRETS,
                command="shakerscan secrets reveal {target_id} {secret_id}"),
    PersonRoute("POST", "/targets/{target_id}/discovered-secrets/{secret_id}/grants",
                "letting another target's Hunts use a discovered secret", _READ_SECRETS,
                command="shakerscan secrets grant {target_id} {secret_id} --to {body_target_id}"),
    PersonRoute("DELETE", "/targets/{target_id}/discovered-secrets/{secret_id}/grants/{grant_target_id}",
                "ending another target's use of a discovered secret", _READ_SECRETS),
    PersonRoute("POST", "/targets/{target_id}/discovered-secrets/{secret_id}/promote",
                "moving a discovered secret into a credential profile", _READ_SECRETS),
    # Findings: dismissal, accepted risk and exceptions.
    PersonRoute("PATCH", "/findings/{finding_id}", "dismissing a finding (false positive, accepted risk or duplicate)",
                _READ_FINDING, when=_dismisses_finding),
    PersonRoute("POST", "/findings/bulk", "dismissing findings (false positive or accepted risk)",
                "read the findings with shakerscan_findings", when=_dismisses_findings),
    PersonRoute("POST", "/targets/{target_id}/findings/{finding_id}/dismiss",
                "dismissing a finding (false positive, accepted risk or duplicate)", _READ_FINDING,
                command="shakerscan knowledge dismiss {target_id} {finding_id} --reason {body_reason} "
                        "--note {body_note}"),
    PersonRoute("POST", "/finding-exceptions", "accepting a finding's risk as an exception",
                "read GET /finding-exceptions"),
    PersonRoute("PATCH", "/finding-exceptions/{exception_id}", "changing a finding exception",
                "read GET /finding-exceptions"),
    PersonRoute("DELETE", "/finding-exceptions/{exception_id}", "deleting a finding exception",
                "read GET /finding-exceptions"),
    # Target instructions and access-control contracts.
    PersonRoute("POST", "/targets/{target_id}/instruction-proposals/{proposal_id}/accept",
                "accepting a proposed change to a target's instructions or saved actions", _READ_PROPOSALS,
                command="shakerscan knowledge review {target_id} --accept {proposal_id}"),
    PersonRoute("POST", "/targets/{target_id}/instruction-proposals/{proposal_id}/reject",
                "rejecting a proposed change to a target's instructions or saved actions", _READ_PROPOSALS,
                command="shakerscan knowledge review {target_id} --reject {proposal_id}"),
    PersonRoute("POST", "/targets/{target_id}/skill/confirm",
                "confirming agent-written instructions as the operator's own", "read GET /targets/{target_id}/skill",
                command="shakerscan knowledge review {target_id}"),
    PersonRoute("POST", "/targets/{target_id}/invariants/{contract_id}/approve",
                "approving an access-control contract", "read GET /targets/{target_id}/invariants"),
    # Model Intake approvals, promotion and trust.
    PersonRoute("POST", "/model-intake/submissions/{submission_id}/approvals",
                "approving a model submission (a reviewer's own approval)",
                "read GET /model-intake/submissions/{submission_id}"),
    PersonRoute("POST", "/model-intake/submissions/{submission_id}/promote", "promoting (signing) a model submission",
                "read GET /model-intake/submissions/{submission_id}"),
    PersonRoute("POST", "/model-intake/trust-anchors", "adding a Model Intake trust anchor",
                "read GET /model-intake/trust-anchors"),
    PersonRoute("PATCH", "/model-intake/trust-anchors/{anchor_id}",
                "changing a Model Intake trust anchor (its key, constraints or whether it is active)",
                "read GET /model-intake/trust-anchors?active_only=false"),
    PersonRoute("DELETE", "/model-intake/trust-anchors/{anchor_id}", "deactivating a Model Intake trust anchor",
                "read GET /model-intake/trust-anchors?active_only=false"),
    PersonRoute("POST", "/model-intake/admissions/{admission_id}/revoke", "revoking a model admission",
                "read GET /model-intake/admissions/{admission_id}"),
    # Fleet membership.
    PersonRoute("POST", "/fleet/join-tokens", "issuing a fleet join token", "read GET /fleet/nodes"),
    PersonRoute("DELETE", "/fleet/join-tokens/{token_id}", "revoking a fleet join token",
                "ask the person whether it was revoked"),
    PersonRoute("POST", "/fleet/nodes/{node_id}/revoke", "revoking a fleet node", "read GET /fleet/nodes"),
    # Operator settings.
    PersonRoute("PUT", "/settings/ai", "changing the AI settings", _SETTINGS),
    PersonRoute("PUT", "/settings/automation", "changing the automation settings", _SETTINGS),
    PersonRoute("PUT", "/settings/scan-execution", "changing the scan execution settings", _SETTINGS),
)


def route_path(path: str) -> str:
    """The route a request path names: its query dropped, percent-escapes decoded, repeated and
    trailing slashes removed, so ``/findings//x/`` or ``/findings/x%2F`` is not a way around."""
    # Split by hand: urlsplit would read a path that starts with "//" as a host.
    route = urllib.parse.unquote(path.split("#", 1)[0].split("?", 1)[0])
    route = "/" + "/".join(part for part in route.split("/") if part)
    return route


def _payload(body: bytes | str | None) -> Any:
    if body is None or body == b"" or body == "":
        return None
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None


def match(method: str, path: str, body: bytes | str | None) -> tuple[PersonRoute, dict[str, str]] | None:
    """The person's decision this request records, with the path's values, or None."""
    method, route, payload = method.upper(), route_path(path), _payload(body)
    for entry in ROUTES:
        if entry.method != method:
            continue
        found = entry.pattern.fullmatch(route)
        if found and entry.when(payload):
            return entry, found.groupdict()
    return None


def dedicated_command(entry: PersonRoute, values: Mapping[str, str], body: bytes | str | None) -> str | None:
    """The person's dedicated command for this request, or None when it has none or a value is
    not one plain word (the request is then named through ``shakerscan api``)."""
    if entry.command is None:
        return None
    payload = _object(_payload(body)) or {}
    words = dict(values)
    if "{verb}" in entry.command:
        words["verb"] = "deny" if payload.get("decision") == "deny" else "approve"
    if "{body_target_id}" in entry.command:
        words["body_target_id"] = str(payload.get("target_id") or "")
    if "{body_reason}" in entry.command:
        reason = payload.get("reason")
        words["body_reason"] = reason if reason in DISMISSING_VERDICTS else ""
    if not all(_WORD.fullmatch(value) for value in words.values()):
        return None
    if "{body_note}" in entry.command:
        note = payload.get("note")
        if not isinstance(note, str) or not note.strip() or note.startswith("-"):
            return None
        words["body_note"] = shlex.quote(note)
    return entry.command.format(**words)


def refusal(method: str, path: str, body: bytes | str | None, *, api_url: str | None = None,
            no_terminal: bool = False) -> str | None:
    """One line for an agent that sent a person's decision: what the decision is, that nothing was
    sent, how to read the outcome, and last the person's command (nothing after it, so a copy of
    the line's end takes no punctuation into the command). None for any other request.
    ``no_terminal``: the caller carries no agent signal but is not a person's terminal either; the
    line says so, and where a person's own script finds its opt-out."""
    found = match(method, path, body)
    if found is None:
        return None
    entry, values = found
    try:
        import person_decision
    except ModuleNotFoundError:
        from scripts import person_decision
    raw = body.encode("utf-8") if isinstance(body, str) else body
    command = dedicated_command(entry, values, body)
    command = (person_decision.with_gateway(command, api_url) if command
               else person_decision.person_command(method.upper(), path, raw or None, gateway=api_url))
    outcome = entry.outcome.format(path=route_path(path), **values) if "{" in entry.outcome else entry.outcome
    why = ("this is not a person's terminal (stdin and stdout are not both terminals), and an agent never "
           "makes this decision (a person's own script: docs/agent-mcp-setup.md, \"A person's own scripts\")"
           if no_terminal else "an agent never makes this decision")
    return (f"person decision required: {entry.summary}. Nothing was sent: {why}. Ask the person to run the command below in their own terminal (not this agent's "
            f"shell), or to decide it in the browser; once they say it is done, {outcome}. "
            f"The person's command: {command}")

"""Decisions only a person makes, from the person's own terminal.

``shakerscan targets authorize <url-or-id>`` records a target's standing authorization for active
testing ("I own or am authorized to test this target"); ``targets unauthorize`` withdraws it. A
target is named by its URL, by its id (a connected device's id too: a device is authorized the
same way), or as ``host://<address>`` for a host (network) target.
``shakerscan hunt budget raise <hunt> --limit NAME=N|+N`` raises a Hunt's budget.

They are ordinary API writes. On an Enterprise gateway whose administrator requires a
security-key touch for person decisions from terminals, the gateway refuses them with the
connection's token alone, and the product CLI's client completes them with one touch of the
person's key and sends them again (person_decision.py, vendored as ``_person_decision``). From an
agent's shell, which has no terminal, they never prompt: they print the command the person runs
and exit 3. On an open-source engine, or a gateway without the switch, they are sent as they are.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
from collections.abc import Mapping, Sequence
from typing import Any

from ._vendored import helper, load

UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
LIMIT_LABELS = {  # every limit the engine takes, safety ceilings first
    "max_state_changing_requests": "state-changing requests",
    "max_oob_interactions": "out-of-band interactions",
    "max_tcp_ports": "TCP ports",
    "max_udp_ports": "UDP ports",
    "max_hosts": "hosts",
    "max_device_fragility_points": "device fragility points",
    "max_active_actions": "approval-gated actions",
    "max_http_requests": "HTTP requests",
    "max_browser_actions": "browser actions",
    "max_capability_calls": "capability calls",
    "max_candidates": "candidate and finding records",
    "max_verifications": "verifications",
    "max_duration_seconds": "duration in seconds",
}
# Limits that bound what a Hunt may do to a target or send off it, not how long it works.
SAFETY_CEILINGS = frozenset({
    "max_state_changing_requests", "max_oob_interactions", "max_tcp_ports", "max_udp_ports",
    "max_hosts", "max_device_fragility_points",
})
TARGET_PAGE = 500
MAX_TARGET_PAGES = 10


class DecisionError(Exception):
    """A problem the person can act on; printed without a traceback."""


def add_parser(commands: Any, connection: Any) -> None:
    targets = commands.add_parser(
        "targets",
        help="authorize a target for active testing in your own terminal, or withdraw it: "
             "targets authorize|unauthorize <url-or-id>",
    )
    connection(targets)
    targets.add_argument("action", choices=("authorize", "unauthorize"))
    targets.add_argument("target", help="the target's URL (https://app.example.com), its id (a device's id too), "
                                        "or host://<address> for a host target")
    targets.add_argument("--reason", help="unauthorize: why it is withdrawn (recorded)")
    targets.add_argument("--json", action="store_true", help="print the instance's answer as JSON")


def _client(url: str, timeout: float | None):
    v2 = load("_v2_cli")
    import os

    token = os.environ.get("SHAKERSCAN_API_TOKEN", "").strip() or None
    return v2, v2.ApiClient(url, api_token=token, timeout=timeout or v2.DEFAULT_TIMEOUT_SECONDS)


def _exit(v2: Any, exc: Exception) -> int:
    """The product CLI's error JSON; for a person's decision the one line it is (exit 3 when this
    shell cannot ask for it, 130 for Ctrl-C at the touch, 1 when the touch failed, as
    ``shakerscan api`` and ``scan`` exit)."""
    if isinstance(exc, v2.CliError):
        return v2.person_decision_exit(exc)
    print(f"shakerscan: {exc}", file=sys.stderr)
    return 2


def _same_target(left: str, right: str) -> bool:
    def key(value: str) -> tuple[str, str, int | None, str]:
        parts = urllib.parse.urlsplit(value if "://" in value else "https://" + value)
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
        return parts.scheme.lower(), (parts.hostname or "").lower().rstrip("."), port, parts.path.rstrip("/")

    return key(left) == key(right)


def target_url(value: str) -> str:
    text = str(value or "").strip()
    if not text or any(ch.isspace() for ch in text):
        raise DecisionError("name the target by its URL (https://app.example.com) or its id")
    return text if "://" in text else "https://" + text


def find_target(client: Any, value: str, *, create: bool) -> dict[str, Any]:
    """The target for a URL, an id or ``host://<address>``: registered on the instance
    (``create``: registered now, as adding it does; never an authorization) or found among the
    registered ones. An id the targets do not hold may be a connected device's, which is
    authorized under the same route."""
    if UUID.fullmatch(value.strip()):
        identifier = value.strip().lower()
        try:
            found = client.request("GET", f"/targets/{identifier}")
        except Exception as exc:
            if getattr(exc, "http_status", None) != 404:
                raise
            device = client.request("GET", f"/devices/{identifier}")
            if not isinstance(device, Mapping):
                raise
            return {"id": identifier, "url": str(device.get("primary_locator") or ""),
                    "name": str(device.get("name") or ""), "device": True}
        return dict(found) if isinstance(found, Mapping) else {"id": identifier}
    text = value.strip()
    if text.lower().startswith("host://"):
        locator = text[len("host://"):].strip()
        if not locator or any(ch.isspace() for ch in locator):
            raise DecisionError("name a host target as host://<address>")
        if create:
            created = client.request("POST", "/targets/hosts", payload={"locator": locator})
            if not isinstance(created, Mapping) or not created.get("id"):
                raise DecisionError("the instance registered no host target for that address")
            return dict(created)
        url = "host://" + locator
    else:
        url = target_url(value)
    if create:
        created = client.request("POST", "/targets", payload={"url": url})
        if not isinstance(created, Mapping) or not created.get("id"):
            raise DecisionError("the instance registered no target for that URL")
        return dict(created)
    for page in range(MAX_TARGET_PAGES):
        listed = client.request("GET", f"/targets?limit={TARGET_PAGE}&offset={page * TARGET_PAGE}")
        rows = listed if isinstance(listed, list) else (listed or {}).get("targets") or []
        for row in rows:
            if isinstance(row, Mapping) and _same_target(str(row.get("url") or ""), url):
                return dict(row)
        if len(rows) < TARGET_PAGE:
            break
    raise DecisionError(f"no target is registered for {url}; name it by its id")


def _os_user() -> str:
    import getpass

    try:
        return getpass.getuser()[:60] or "the local user"
    except Exception:  # no user name in the environment or the password database
        return "the local user"


def _named(target: Mapping[str, Any]) -> str:
    url = str(target.get("url") or "")
    name = str(target.get("name") or "")
    return f"{name} ({url})" if name and url and name not in url else url or name or str(target.get("id") or "")


def cmd_targets(args: argparse.Namespace) -> int:
    from .cli import apply_connection

    url = apply_connection(args)
    v2, client = _client(url, args.timeout)
    target: dict[str, Any] = {}
    try:
        target = find_target(client, args.target, create=args.action == "authorize")
        identifier = str(target.get("id") or "")
        if not UUID.fullmatch(identifier):
            raise DecisionError("the instance answered without a target id")
        if args.action == "authorize":
            # Active testing only; an intrusive authorization is made in the browser.
            # An Enterprise gateway writes who decided itself; an open-source engine records
            # this computer's user.
            answer = client.request(
                "POST", f"/targets/{identifier}/authorization",
                payload={"approved_by": f"{_os_user()} via shakerscan targets authorize", "risk_tier": "active"},
            )
            recorded = (answer or {}).get("authorization") if isinstance(answer, Mapping) else None
            who = (recorded or {}).get("approved_by") if isinstance(recorded, Mapping) else None
            line = f"authorized {_named(target)} for active testing" + (f", recorded as {who}" if who else "")
        else:
            answer = client.request(
                "DELETE", f"/targets/{identifier}/authorization",
                payload={"revoked_by": f"{_os_user()} via shakerscan targets unauthorize",
                         "reason": (args.reason or "withdrawn from the terminal")[:2000]},
            )
            revoked = bool((answer or {}).get("revoked")) if isinstance(answer, Mapping) else False
            line = (f"withdrew the authorization of {_named(target)}" if revoked
                    else f"{_named(target)} had no standing authorization")
    except (v2.CliError, DecisionError) as exc:
        code = _exit(v2, exc)
        if args.action == "authorize" and target.get("status") == "created":
            # Registered just now (an ordinary add, before any decision): "nothing was changed"
            # above is about the authorization, which was not recorded.
            print(f"note: {_named(target)} was registered as a target just now and stays registered, "
                  "not authorized", file=sys.stderr)
        return code
    print(json.dumps(answer, indent=2, sort_keys=True) if args.json else line)
    return 0


def _limits(values: Sequence[str], current: Mapping[str, Any]) -> dict[str, int]:
    """``NAME=N`` (a new total) or ``NAME=+N`` (that much more than now), each named once."""
    totals: dict[str, int] = {}
    for raw in values:
        name, separator, amount = str(raw).partition("=")
        name, amount = name.strip(), amount.strip()
        if not separator or not name or not re.fullmatch(r"\+?[0-9]{1,16}", amount):
            raise DecisionError(f"--limit takes NAME=N or NAME=+N, not {raw!r}")
        if name in totals:
            raise DecisionError(f"--limit names {name} twice")
        now = current.get(name)
        if type(now) is not int:
            known = ", ".join(sorted(key for key, value in current.items() if type(value) is int))
            raise DecisionError(f"this Hunt has no budget limit {name}; its limits are: {known}")
        totals[name] = now + int(amount[1:]) if amount.startswith("+") else int(amount)
        if totals[name] <= now:
            raise DecisionError(f"{name} is {now}; a raise names a larger total (or +N)")
    if not totals:
        raise DecisionError("name what to raise: --limit NAME=N or NAME=+N")
    return totals


def hunt_budget_raise(argv: Sequence[str], url: str, timeout: float | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shakerscan hunt budget raise",
        description="Raise a Hunt's budget limits: a person's decision, made in your own terminal.",
    )
    parser.add_argument("hunt_id")
    parser.add_argument("--limit", action="append", default=[], metavar="NAME=N|NAME=+N", required=True,
                        help="a new total, or +N more than now (repeatable), e.g. max_http_requests=+200")
    parser.add_argument("--resume", action="store_true", help="resume the Hunt if its budget had run out")
    parser.add_argument("--reason", help="why (recorded; an Enterprise gateway that asked for your touch writes its own)")
    parser.add_argument("--json", action="store_true", help="print the instance's answer as JSON")
    args = parser.parse_args(list(argv))
    v2, client = _client(url, timeout)
    hunt = str(args.hunt_id).strip().lower()
    try:
        if not UUID.fullmatch(hunt):
            raise DecisionError("name the Hunt by its id")
        current = client.request("GET", f"/hunts/{hunt}")
        budget = current.get("budget") if isinstance(current, Mapping) and isinstance(current.get("budget"), Mapping) else {}
        revision = current.get("budget_revision") if isinstance(current, Mapping) else None
        if type(revision) is not int:
            raise DecisionError("this instance reports no budget revision for the Hunt; raise it on the Hunt page")
        totals = _limits(args.limit, budget)
        key = "cli-raise-" + hashlib.sha256(json.dumps([hunt, revision, totals], sort_keys=True).encode()).hexdigest()[:40]
        answer = client.request("POST", f"/hunts/{hunt}/budget-amendments", payload={
            "schema_version": "hunt-budget-amendment/v1", "limits": totals, "expected_revision": revision,
            "idempotency_key": key, "operator_confirmed": True, "resume": bool(args.resume),
            "reason": (args.reason or "Raised from the terminal (shakerscan hunt budget raise)")[:500],
        })
    except (v2.CliError, DecisionError) as exc:
        return _exit(v2, exc)
    if args.json:
        print(json.dumps(answer, indent=2, sort_keys=True))
        return 0
    order = list(LIMIT_LABELS)
    raised = "; ".join(
        f"{LIMIT_LABELS.get(name, name)} {budget.get(name)} -> {value}"
        + (" (safety ceiling)" if name in SAFETY_CEILINGS else "")
        for name, value in sorted(totals.items(), key=lambda item: (
            item[0] not in SAFETY_CEILINGS, order.index(item[0]) if item[0] in order else len(order), item[0]))
    )
    status = (answer or {}).get("status") if isinstance(answer, Mapping) else None
    print(f"raised {raised} for Hunt {hunt}" + (f"; the Hunt is {status}" if status else ""))
    return 0


def touch_lines(client: Any) -> list[str]:
    """`shakerscan doctor` on an Enterprise connection: whether the gateway requires a
    security-key touch for person decisions from terminals, and whether a touch could happen
    here (python-fido2, a key plugged in). Opening no key: nothing blinks."""
    approve = helper("_hunt_approve")
    try:
        me = client.request_json("GET", approve.ME_PATH)
    except Exception:  # an engine, or no answer
        me = None
    if isinstance(me, Mapping) and "person_decision_proof" in me:
        state = ("required for person decisions from terminals" if me.get("person_decision_proof") is True
                 else "not required (the administrator's switch is off)")
    elif isinstance(me, Mapping):
        state = "not offered by this gateway (an older Enterprise gateway)"
    else:
        state = "unknown (this instance does not say)"
    unready = approve.security_key_readiness()
    if unready:
        key = unready
    else:
        from importlib.metadata import PackageNotFoundError, version

        try:
            fido2 = f"python-fido2 {version('fido2')}"
        except PackageNotFoundError:
            fido2 = "python-fido2"
        key = f"{fido2}, a security key is plugged in (register it once under My account)"
    return [f"touch:    {state}", f"key:      {key}"]


__all__ = [
    "DecisionError", "add_parser", "cmd_targets", "find_target", "hunt_budget_raise", "target_url", "touch_lines",
]

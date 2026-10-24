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
import shlex
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


# What a copy from a sentence carries after a command: an id or URL ending in one of these was
# not meant (`... authorize <id>.` registered and authorized `https://<id>.`).
TRAILING = ".,;:!?)]}'\"`"
# Placeholders this client and an Enterprise gateway print where a target could not be named.
PLACEHOLDERS = frozenset({"TARGET-ID", "TARGET-URL", "TARGET", "<TARGET>", "<TARGET-ID>"})


def checked_target(value: str) -> str:
    """The target as named, or DecisionError for what cannot be one: a placeholder this client
    or a gateway printed (TARGET-ID), and a value with punctuation copied after it (an id is
    named with what it was meant to be)."""
    text = str(value or "").strip()
    if text.upper() in PLACEHOLDERS:
        raise DecisionError(f"{text} stands for the target: name it by its URL (https://app.example.com) or its id")
    if text and text[-1] in TRAILING:
        bare = text.rstrip(TRAILING)
        meant = f": did you mean {bare.lower()}?" if UUID.fullmatch(bare) else ""
        raise DecisionError(f"{text!r} ends in punctuation, which is no part of a target{meant}")
    return text


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


def _me(client: Any) -> Mapping[str, Any] | None:
    """The gateway's description of itself to this connection (GET /_enterprise/me), or None on
    an open-source engine (no such route) or without an answer."""
    approve = helper("_hunt_approve")
    try:
        me = client.get(approve.ME_PATH)
    except Exception:  # an open-source engine, or no answer
        return None
    return me if isinstance(me, Mapping) and isinstance(me.get("user"), Mapping) else None


# What the engine is told of a decision a connection's token sent without a person's touch (the
# gateway's own audit says the same: made with a token, not proven by a person). It says what
# happened, not that nobody was there: the person who ran the command reads it too, and so does
# everyone who opens the target in the scanner, so it is short.
NO_TOUCH = "no security-key touch"


def _token_words(me: Mapping[str, Any]) -> str:
    """The connection, token first: "<person>'s token <label>" (the person the token acts for, as
    the gateway names them), else the service token and its service account's name."""
    user = me.get("user") if isinstance(me.get("user"), Mapping) else {}
    label = str(user.get("token_label") or "")[:60]
    person = me.get("acts_for_name")
    if isinstance(person, str) and person.strip():
        return f"{person.strip()[:100]}'s token {label}" if label else f"{person.strip()[:100]}'s service token"
    token = f"service token {label}" if label else "a service token"
    account = str(user.get("display") or user.get("subject") or "")[:100]
    return f"{token} ({account})" if account else token


def touch_required(me: Mapping[str, Any] | None) -> bool:
    """Whether this gateway's administrator requires a security-key touch for person decisions
    from terminals (it then writes who decided itself)."""
    return isinstance(me, Mapping) and me.get("person_decision_proof") is True


def _decider(client: Any, verb: str, me: Mapping[str, Any] | None | object = ...) -> str:
    """Who the engine records as having decided, as this command names them (at most the
    engine's 200 characters). Where the gateway requires a touch it writes the person who touched
    over this, so this names the person the token acts for. Elsewhere on an Enterprise connection
    the engine keeps what is sent, which no person proved: the token first, the person it acts
    for, and that no person proved it. On an open-source engine (no accounts): this computer's
    user."""
    if me is ...:
        me = _me(client)
    if not isinstance(me, Mapping):
        return f"{_os_user()} via shakerscan targets {verb}"
    through = f"shakerscan targets {verb}"
    if touch_required(me):
        user = me["user"]
        label = str(user.get("token_label") or "")[:60]
        person = me.get("acts_for_name")
        who = person if isinstance(person, str) and person.strip() else (user.get("display") or user.get("subject"))
        tail = f", service token {label}" if label else ""
        return f"{str(who or 'a service token')[:100]} via {through}{tail}"[:200]
    return f"{_token_words(me)}, {NO_TOUCH} ({through})"[:200]


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
        args.target = checked_target(args.target)
    except DecisionError as exc:
        return _exit(v2, exc)
    me = _me(client)
    if args.action == "authorize" and touch_required(me) and not helper("_person_decision").interactive():
        # Where the gateway requires a touch, an agent's shell cannot authorize: said before the
        # target is registered, so nothing at all changes (unauthorize needs no touch).
        decision = helper("_person_decision")
        command = "shakerscan targets authorize " + shlex.quote(args.target.strip())
        line = decision.refusal_line({"decision": "target.authorize",
                                      "summary": f"Authorize {args.target.strip()} for active testing"}, command)
        print(f"shakerscan: {line}", file=sys.stderr)
        return decision.EXIT_REFUSED
    try:
        target = find_target(client, args.target, create=args.action == "authorize")
        identifier = str(target.get("id") or "")
        if not UUID.fullmatch(identifier):
            raise DecisionError("the instance answered without a target id")
        if args.action == "authorize":
            # Active testing only; an intrusive authorization is made in the browser. Who decided
            # is the person the connection acts for (_decider); a gateway that requires a touch
            # writes the person who touched over it.
            answer = client.request(
                "POST", f"/targets/{identifier}/authorization",
                payload={"approved_by": _decider(client, "authorize", me), "risk_tier": "active"},
            )
            recorded = (answer or {}).get("authorization") if isinstance(answer, Mapping) else None
            who = (recorded or {}).get("approved_by") if isinstance(recorded, Mapping) else None
            line = f"authorized {_named(target)} for active testing" + (f", recorded as {who}" if who else "")
            if isinstance(me, Mapping) and not touch_required(me):
                # The person who ran it reads the record too: why it names the token.
                line += ("\n(this gateway requires no security-key touch for it, so the record names the "
                         "connection's token, which anyone holding it could have used)")
        else:
            answer = client.request(
                "DELETE", f"/targets/{identifier}/authorization",
                payload={"revoked_by": _decider(client, "unauthorize", me),
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


def _raise_reason(given: str | None, me: Mapping[str, Any] | None) -> str:
    """The amendment's reason, which the engine keeps as the person's. Where the gateway requires
    a touch it writes its own. Elsewhere on an Enterprise connection no person proved it: the
    connection (token first) and that, after the reason given. On an open-source engine: the
    reason given, else that it came from the terminal."""
    if isinstance(me, Mapping) and not touch_required(me):
        made = f"with {_token_words(me)}, {NO_TOUCH}"
        if given:
            return f"{given.strip()[:400]} ({made})"[:500]
        return f"Raised {made} (shakerscan hunt budget raise)"[:500]
    return (given or "Raised from the terminal (shakerscan hunt budget raise)")[:500]


def hunt_budget_raise(argv: Sequence[str], url: str, timeout: float | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shakerscan hunt budget raise",
        description="Raise a Hunt's budget limits: a person's decision, made in your own terminal.",
    )
    parser.add_argument("hunt_id")
    parser.add_argument("--limit", action="append", default=[], metavar="NAME=N|NAME=+N", required=True,
                        help="a new total, or +N more than now (repeatable), e.g. max_http_requests=+200")
    parser.add_argument("--resume", action="store_true", help="resume the Hunt if its budget had run out")
    parser.add_argument("--reason", help="why (recorded with the raise; where your administrator requires a "
                                         "security-key touch, the gateway records 'Raised by <you> (terminal "
                                         "security-key touch)' instead of this text)")
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
            "reason": _raise_reason(args.reason, _me(client)),
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
    here (python-fido2, a key plugged in). Opening no key: nothing blinks. No lines for an
    instance that is not an Enterprise gateway."""
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
        # Not an Enterprise gateway (an open-source engine answers no /_enterprise/me): the
        # touch is no question there, so doctor says nothing of it.
        return []
    required = me.get("person_decision_proof") is True
    unready = approve.security_key_readiness()
    if unready and approve.key_out_of_reach():
        key = unready
    elif unready.startswith("no USB security key found"):
        # No failure where no touch is required: approvals then use the person's other step-up.
        key = ("none plugged in: plug in the security key registered to you before you decide from this "
               "terminal" if required else "none plugged in (not needed here: approvals then use your other "
               "step-up)")
    elif unready:
        key = unready
    else:
        from importlib.metadata import PackageNotFoundError, version

        try:
            fido2 = f"python-fido2 {version('fido2')}"
        except PackageNotFoundError:
            fido2 = "python-fido2"
        # Which key is registered is not asked here (that needs a challenge of the gateway's):
        # approve checks it silently, without making a key blink.
        key = (f"{fido2}, a security key is plugged in (test it: shakerscan approve --test, one touch, "
               "nothing decided)")
    return [f"touch:    {state}", f"key:      {key}"]


__all__ = [
    "DecisionError", "add_parser", "cmd_targets", "find_target", "hunt_budget_raise", "target_url", "touch_lines",
]

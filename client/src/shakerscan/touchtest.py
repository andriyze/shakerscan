"""``shakerscan approve --test``: one touch of your security key, deciding nothing.

On an Enterprise gateway, before an administrator requires a security-key touch for person
decisions from terminals (or at any time), a person checks that the key registered to their
account answers from this computer: the gateway begins a touch test (approval purpose
``key_check``) over a document that says it decides nothing, the person touches the key (user
presence, no PIN), and the gateway verifies the assertion against that person's registered keys
exactly as it verifies every touch. Nothing is approved, decided or changed, and it works whether
the administrator's switch is on or off.

It asks only at an interactive terminal (stdin and stdout terminals, outside ``shakerscan agent``),
as every command that asks the person does; anywhere else it exits 3 and never opens a key.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from typing import Any

from ._vendored import load

PROMPT = "Touch your security key to test it; this decides nothing (Ctrl-C to cancel)..."
OLDER_GATEWAY = (
    "this Enterprise gateway has no touch test (an earlier release of it); `shakerscan approve "
    "<request-id>` with a pending request asks the same key"
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shakerscan approve --test",
        description="One touch of your security key, checked by your Enterprise gateway as every "
                    "touch is; nothing is decided.",
    )
    parser.add_argument("--test", action="store_true", required=True,
                        help="test a touch of your security key; nothing is decided")
    parser.add_argument("--account", help="your sign-in name (sso:<subject> for single sign-on), when "
                                          "this connection's token acts for nobody")
    return parser


def approve_test(argv: Sequence[str], url: str, timeout: float | None = None, *,
                 terminal: Any = None, environ: Mapping[str, str] | None = None) -> int:
    """Run the touch test against the connected instance; the exit status (0 the key answered, 1
    it did not, 2 no Enterprise connection, 3 not at a terminal, 130 Ctrl-C)."""
    args = _parser().parse_args(list(argv))
    environ = os.environ if environ is None else environ
    v2 = load("_v2_cli")
    approval = v2._approval()
    token = str(environ.get("SHAKERSCAN_API_TOKEN") or "").strip() or None
    if not token:
        print("shakerscan: a touch test asks an Enterprise gateway; this connection has no token "
              "(an open-source engine has no accounts and asks no key): run shakerscan connect "
              "first", file=sys.stderr)
        return 2
    terminal = terminal or approval.Terminal(sys.stdin, sys.stdout)
    try:
        terminal.require("a touch test of your security key")
    except approval.NotAtTerminal as exc:
        print(f"shakerscan: {exc}", file=sys.stderr)
        return approval.EXIT_NOT_AT_TERMINAL
    client = v2.ApiClient(url, api_token=token, timeout=float(timeout or v2.DEFAULT_TIMEOUT_SECONDS))
    send = v2._approval_send(client)
    if not approval.gateway_features(send)["names_approver"]:
        # Before any name is asked or key opened: a gateway that predates the test refuses it.
        print(f"shakerscan: {OLDER_GATEWAY}", file=sys.stderr)
        return 1
    unready = approval.security_key_readiness(waiting=True)
    if unready:
        print(f"shakerscan: {unready}; nothing was tested", file=sys.stderr)
        return 1
    stepup = approval.StepUp(send, url, terminal, account=args.account, method="security_key")
    stepup.prompt = PROMPT
    try:
        challenge, _ = stepup.begin("key_check", {"key_check": dict(approval.KEY_CHECK)})
        result = stepup.finish(challenge, stepup.prove(challenge))
    except KeyboardInterrupt:
        terminal.say("")
        print("shakerscan: cancelled; nothing was tested or decided", file=sys.stderr)
        return 130
    except approval.GatewayRefused as exc:
        if exc.status == 422 and exc.code == "request_invalid":
            print(f"shakerscan: {OLDER_GATEWAY}", file=sys.stderr)
            return 1
        print(f"shakerscan: {exc}; nothing was decided", file=sys.stderr)
        return 1
    except approval.ApprovalError as exc:
        print(f"shakerscan: {exc}", file=sys.stderr)
        return 1
    answer = result.get("key_check") if isinstance(result, Mapping) else None
    if not (isinstance(answer, Mapping) and answer.get("answered") is True
            and answer.get("decides") == "nothing"):
        print("shakerscan: the gateway's answer is not a touch test's; nothing was decided", file=sys.stderr)
        return 1
    who = approval._inert(str(result.get("decided_by") or "you"))[:120]
    terminal.say(f"Your security key answered for {who}: a touch from this terminal works. Nothing was decided.")
    if answer.get("touch_required") is True:
        terminal.say("Your administrator requires this touch for person decisions from terminals.")
    else:
        terminal.say("The touch switch is off on this installation; with it on, each person decision "
                     "from a terminal is this same touch.")
    return 0


__all__ = ["approve_test"]

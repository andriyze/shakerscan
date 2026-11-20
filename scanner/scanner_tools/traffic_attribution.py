"""Declared identification on every request a Scan, retest or Hunt sends.

A target's security team must be able to tell ShakerScan traffic from an attacker's: when AI
tooling makes reconnaissance cheap, an operator's own authorized testing would otherwise look
like one more anonymous scanner in the logs. Every request carries:

- the header ``X-ShakerScan-Run: <kind>:<id>`` naming the run (``scan:<uuid>`` for a Scan or a
  retest, ``hunt:<uuid>`` for a Hunt). The id is the engine's own record id: it identifies the
  run to whoever operates the engine and reveals nothing else (never a token, a credential or a
  target value);
- a ``ShakerScan`` token appended to the User-Agent of the engine's own HTTP clients (the
  external tools keep their own User-Agent and carry the header).

``SHAKERSCAN_TRAFFIC_ATTRIBUTION=off`` turns the header off for the whole install, and a Scan
whose options set ``traffic_attribution: false`` sends none (an authorized engagement that must
not announce itself). ``SHAKERSCAN_TRAFFIC_USER_AGENT_TOKEN`` replaces the User-Agent token
(empty: no token).

The run is bound per task with :func:`bound_run` (a context variable, so concurrent actions of
different runs in one worker never mix); a subprocess that cannot see the variable reads
``SHAKERSCAN_TRAFFIC_RUN`` from its environment (:func:`subprocess_environment`).
"""
from __future__ import annotations

import contextlib
import contextvars
import os
import re
from typing import Iterator, Mapping

HEADER = "X-ShakerScan-Run"
ENABLED_ENV = "SHAKERSCAN_TRAFFIC_ATTRIBUTION"
USER_AGENT_ENV = "SHAKERSCAN_TRAFFIC_USER_AGENT_TOKEN"
RUN_ENV = "SHAKERSCAN_TRAFFIC_RUN"
DEFAULT_USER_AGENT_TOKEN = "ShakerScan"
RUN_KINDS = frozenset({"scan", "hunt"})

_LABEL = re.compile(r"^(scan|hunt):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+()-]{0,63}$")
_OFF = {"0", "off", "false", "no", "disabled"}

# None: no run bound; "" : a run is bound but its attribution is switched off.
_current: contextvars.ContextVar[str | None] = contextvars.ContextVar("shakerscan_traffic_run", default=None)


def run_label(kind: str, run_id: object) -> str | None:
    """``scan:<uuid>`` / ``hunt:<uuid>``, or None for anything that is not a run id."""
    label = f"{str(kind or '').strip().lower()}:{str(run_id or '').strip().lower()}"
    return label if _LABEL.fullmatch(label) else None


def install_enabled(environ: Mapping[str, str] | None = None) -> bool:
    raw = str((os.environ if environ is None else environ).get(ENABLED_ENV) or "").strip().lower()
    return raw not in _OFF


def user_agent_token(environ: Mapping[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    if USER_AGENT_ENV not in env:
        return DEFAULT_USER_AGENT_TOKEN
    raw = str(env.get(USER_AGENT_ENV) or "").strip()
    return raw if _TOKEN.fullmatch(raw) else ""


@contextlib.contextmanager
def bound_run(kind: str, run_id: object, *, enabled: bool = True) -> Iterator[str | None]:
    """Bind the run for everything this task sends; ``enabled=False`` binds it silenced."""
    label = run_label(kind, run_id)
    token = _current.set((label or "") if enabled else "")
    try:
        yield label if enabled else None
    finally:
        _current.reset(token)


def current_label(environ: Mapping[str, str] | None = None) -> str | None:
    """The bound run's label when attribution applies, else None."""
    env = os.environ if environ is None else environ
    if not install_enabled(env):
        return None
    bound = _current.get()
    if bound is not None:
        return bound or None
    raw = str(env.get(RUN_ENV) or "").strip().lower()
    return raw if _LABEL.fullmatch(raw) else None


def headers(label: str | None = None) -> dict[str, str]:
    """The identification headers to add (empty when attribution does not apply)."""
    value = label if label is not None else current_label()
    return {HEADER: value} if value and _LABEL.fullmatch(value) else {}


def with_user_agent(user_agent: str | None, environ: Mapping[str, str] | None = None) -> str | None:
    """Append the token to a User-Agent the engine sets itself (once)."""
    token = user_agent_token(environ)
    if not token:
        return user_agent
    base = str(user_agent or "").strip()
    if token in base.split():
        return base
    return f"{base} {token}".strip()


def subprocess_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The variables a child process needs to attribute its own traffic to the bound run."""
    label = current_label(environ)
    return {RUN_ENV: label} if label else {}


def curl_arguments(cmd: list[str]) -> list[str]:
    """``cmd`` with the run header added and the User-Agent token appended, for curl only."""
    if not cmd or os.path.basename(str(cmd[0])) != "curl":
        return cmd
    label = current_label()
    out = list(cmd)
    token = user_agent_token()
    if token:
        for index, value in enumerate(out[:-1]):
            if value in {"-H", "--header"} and str(out[index + 1]).lower().startswith("user-agent:"):
                name, _, agent = str(out[index + 1]).partition(":")
                out[index + 1] = f"{name}: {with_user_agent(agent.strip())}"
                break
            if value in {"-A", "--user-agent"}:
                out[index + 1] = with_user_agent(str(out[index + 1])) or out[index + 1]
                break
        else:
            out[1:1] = ["-A", f"curl {token}"]
    if label and not any(str(v).lower().startswith(HEADER.lower() + ":") for v in out):
        out[1:1] = ["-H", f"{HEADER}: {label}"]
    return out


# How each external tool takes an extra request header.
TOOL_HEADER_FLAGS = {
    "nuclei": "-H", "katana": "-H", "katana_headless": "-H", "httpx": "-H",
    "ffuf": "-H", "dalfox": "--header",
}


def tool_arguments(tool: str, label: str | None = None) -> list[str]:
    """Header arguments for an external tool (sqlmap merges into its ``--headers``)."""
    value = headers(label)
    flag = TOOL_HEADER_FLAGS.get(str(tool or "").lower())
    if not value or not flag:
        return []
    return [flag, f"{HEADER}: {value[HEADER]}"]

"""The ``shakerscan`` command: MCP adapter and Hunt CLI for a ShakerScan instance.

One command name, two install channels. The engine installer (``curl -fsSL
https://install.shakerscan.com | sh``) puts a launcher named ``shakerscan`` on the PATH that
runs the local engine and also exposes ``mcp`` and ``hunt``. This package installs the same
command name as a client-only build: ``mcp``, ``hunt``, ``doctor`` and ``version`` talk to any
ShakerScan instance without Docker, and every other subcommand is handed to a local engine
install when one exists (``SHAKERSCAN_HOME``, default ``~/.shakerscan``).

The adapter and the product CLI are the runtime's own ``scripts/shakerscan_mcp.py`` and
``scripts/v2_cli.py``, vendored at build time, so a client and a ``scanner.sh`` of the same
release run identical code; the tools an agent sees come from the instance's live contracts.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import urllib.parse
from collections.abc import Mapping, Sequence
from pathlib import Path

from . import __version__
from ._vendored import load

INSTALL_ONE_LINER = "curl -fsSL https://install.shakerscan.com | sh"
CLIENT_COMMANDS = ("mcp", "hunt", "doctor", "version")
DEFAULT_API_URL = "http://127.0.0.1:8080"
ENV_HOME = "SHAKERSCAN_HOME"
ENV_URL = "SHAKERSCAN_API_URL"
ENV_TOKEN = "SHAKERSCAN_API_TOKEN"
ENV_TOKEN_FILE = "SHAKERSCAN_API_TOKEN_FILE"
ENV_ALLOW_REMOTE = "SHAKERSCAN_MCP_ALLOW_REMOTE_API"
ENV_TIMEOUT = "SHAKERSCAN_MCP_TIMEOUT_SECONDS"
_TRUE = {"1", "true", "yes", "on"}
_IMAGE_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ClientError(Exception):
    """A configuration problem the operator can fix; reported without a traceback."""


# --- connection ------------------------------------------------------------------------------


def read_token(token_file: str | None, environ: Mapping[str, str] | None = None) -> str | None:
    """The service token from ``--token-file``, ``SHAKERSCAN_API_TOKEN_FILE``, or ``SHAKERSCAN_API_TOKEN``."""
    environ = os.environ if environ is None else environ
    path = token_file or environ.get(ENV_TOKEN_FILE) or ""
    if path:
        try:
            token = Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ClientError(f"cannot read the token file {path}: {exc.strerror or exc}") from exc
        if not token:
            raise ClientError(f"the token file {path} is empty")
        return token
    return environ.get(ENV_TOKEN, "").strip() or None


def connection_environment(
    url: str | None,
    token_file: str | None,
    timeout: float | None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Environment overrides for the vendored adapter and CLI.

    An explicit ``--url`` is the operator's authorization to talk to that origin, so it also
    sets the adapter's remote-origin flag; a URL taken from the environment keeps the adapter's
    own rule (a non-loopback origin needs ``SHAKERSCAN_MCP_ALLOW_REMOTE_API=true``). The token
    travels only through the environment, never argv, so it does not show in process listings;
    the adapter and the CLI still refuse to send it over plain http.
    """
    environ = os.environ if environ is None else environ
    overrides: dict[str, str] = {}
    if url:
        overrides[ENV_URL] = url
        overrides[ENV_ALLOW_REMOTE] = "true"
    token = read_token(token_file, environ)
    if token:
        overrides[ENV_TOKEN] = token
    if timeout is not None:
        overrides[ENV_TIMEOUT] = str(timeout)
    return overrides


def apply_connection(args: argparse.Namespace) -> str:
    """Put the connection into the process environment and return the API origin in use."""
    os.environ.update(connection_environment(args.url, args.token_file, args.timeout))
    os.environ.pop(ENV_TOKEN_FILE, None)
    return os.environ.get(ENV_URL) or DEFAULT_API_URL


# --- the local engine -----------------------------------------------------------------------


def engine_home(environ: Mapping[str, str] | None = None) -> Path:
    environ = os.environ if environ is None else environ
    return Path(environ.get(ENV_HOME) or (Path.home() / ".shakerscan"))


def engine_launcher(home: Path | None = None) -> Path | None:
    launcher = (home or engine_home()) / "scanner.sh"
    return launcher if launcher.is_file() else None


def engine_version(home: Path | None = None) -> str | None:
    """The installed engine release (``VERSION`` beside ``scanner.sh``), or None without one."""
    home = home or engine_home()
    if engine_launcher(home) is None:
        return None
    try:
        version = (home / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return version or None


def is_loopback(url: str) -> bool:
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return False
    return host.lower().rstrip(".") in LOOPBACK_HOSTS


def engine_environment(home: Path, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """What the installer's launcher shim sets: ``SCANNER_IMAGE_TAG`` defaults to the installed
    release (``VERSION``) unless already set. The launcher applies the release image lock itself."""
    environ = os.environ if environ is None else environ
    env = dict(environ)
    if not env.get("SCANNER_IMAGE_TAG"):
        try:
            tag = (home / "VERSION").read_text(encoding="utf-8").strip()
        except OSError:
            tag = ""
        if tag and _IMAGE_TAG.fullmatch(tag):
            env["SCANNER_IMAGE_TAG"] = tag
    return env


def run_engine(argv: Sequence[str]) -> int:
    """Hand an engine subcommand to the local install, or explain how to get one."""
    home = engine_home()
    launcher = engine_launcher(home)
    if launcher is None:
        name = argv[0] if argv else "that command"
        sys.stderr.write(
            f"shakerscan: '{name}' runs the local ShakerScan engine, which this client build does not include\n"
            f"(client commands: {', '.join(CLIENT_COMMANDS)}).\n"
            f"Install the engine with:  {INSTALL_ONE_LINER}\n"
            f"Looked for {home / 'scanner.sh'}; set {ENV_HOME} if the engine lives elsewhere.\n"
        )
        return 2
    try:
        os.execve(str(launcher), [str(launcher), *argv], engine_environment(home))
    except OSError as exc:
        sys.stderr.write(f"shakerscan: cannot run {launcher}: {exc.strerror or exc}\n")
        return 2
    return 0  # unreachable: execve replaced the process


# --- client commands ------------------------------------------------------------------------


def cmd_version(args: argparse.Namespace) -> int:  # noqa: ARG001
    """The client version, and the engine release installed beside it when there is one, so the
    output means the same thing whichever install channel put ``shakerscan`` on the PATH."""
    print(f"shakerscan client {__version__}")
    engine = engine_version()
    if engine:
        print(f"engine {engine} ({engine_home() / 'scanner.sh'})")
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    apply_connection(args)
    mcp = load("_mcp")
    mcp.SERVER_VERSION = f"client-{__version__}"
    return int(mcp.main())


def cmd_hunt(args: argparse.Namespace) -> int:
    url = apply_connection(args)
    rest = list(args.args) or ["--help"]
    if rest and rest[0] == "--":
        rest = rest[1:]
    return int(load("_v2_cli").main(["--api-url", url, "hunt", *rest]))


def _with_reason(exc: Exception) -> str:
    """The adapter's error message plus the transport reason it carries (a timeout, a refused
    connection, a certificate failure), so `doctor` says why and not only that."""
    message = str(getattr(exc, "message", None) or exc)
    reason = getattr(exc, "data", None)
    return f"{message}: {reason}" if reason else message


def cmd_doctor(args: argparse.Namespace) -> int:
    url = apply_connection(args)
    mcp = load("_mcp")
    allow_remote = os.environ.get(ENV_ALLOW_REMOTE, "").strip().lower() in _TRUE
    token = os.environ.get(ENV_TOKEN, "").strip() or None
    lines = [f"client:   {__version__}", f"api url:  {url}"]
    try:
        base_url = mcp.normalize_api_url(url, allow_remote=allow_remote)
        timeout = float(args.timeout) if args.timeout is not None else float(mcp.DEFAULT_TIMEOUT_SECONDS)
        client = mcp.ArsenalClient(base_url, timeout_seconds=timeout, api_token=token)
    except (TypeError, ValueError) as exc:
        print("\n".join(lines + [f"error:    {exc}"]))
        return 2
    lines.append(
        "token:    set (sent as a bearer token, https only)"
        if token
        else "token:    none (fine for a local engine; an Enterprise gateway needs a service token)"
    )
    try:
        health = client.request_json("GET", "/health")
        status = health.get("status") if isinstance(health, dict) else None
        lines.append(f"engine:   reachable ({status or 'ok'})")
    except mcp.MCPError as exc:
        lines.append(f"engine:   {_with_reason(exc)}")
    ok = True
    try:
        tools = client.list_tools()
        hunt = sum(1 for tool in tools if str(tool.get("name", "")).startswith("shakerscan_hunt"))
        lines.append(f"mcp:      {len(tools)} tools ({len(tools) - hunt} read-only Arsenal, {hunt} Hunt)")
    except mcp.MCPError as exc:
        lines.append(f"mcp:      {_with_reason(exc)}")
        ok = False
    print("\n".join(lines))
    if is_loopback(url) and engine_launcher() is not None:
        # For a local engine, the launcher's own `doctor` (Docker, disk, host checks) is what
        # a curl-installed user expects from this command: hand off after the connection lines.
        sys.stdout.flush()
        return run_engine(["doctor"])
    return 0 if ok else 1


COMMANDS = {"version": cmd_version, "mcp": cmd_mcp, "hunt": cmd_hunt, "doctor": cmd_doctor}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shakerscan",
        description="ShakerScan client: the MCP adapter and Hunt CLI for a ShakerScan instance.",
        epilog=(
            "Any other subcommand (start, stop, status, update, ...) runs the local engine from "
            f"{ENV_HOME} (default ~/.shakerscan) when it is installed: {INSTALL_ONE_LINER}"
        ),
    )
    parser.add_argument("--version", action="version", version=f"shakerscan client {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="command")

    def connection(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--url",
            help=(
                f"ShakerScan API origin, e.g. https://scanner.example.com (default: ${ENV_URL}, else "
                f"{DEFAULT_API_URL}); an explicit --url authorizes a remote origin"
            ),
        )
        sub.add_argument(
            "--token-file",
            help=(
                "file holding a service token, sent as a bearer token over https only "
                f"(default: ${ENV_TOKEN_FILE}, else ${ENV_TOKEN}); never printed, never on argv"
            ),
        )
        sub.add_argument("--timeout", type=float, help="seconds per API request (default 20)")

    mcp = commands.add_parser("mcp", help="run the MCP stdio adapter (read-only Arsenal plus target-bound Hunt) for an agent")
    connection(mcp)
    hunt = commands.add_parser(
        "hunt",
        help="scripted Hunt lifecycle: start, get, list, query, call, candidate, verify, finish, cancel, resume",
    )
    connection(hunt)
    hunt.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="the hunt subcommand and its options; nothing prints the runtime CLI's own help",
    )
    doctor = commands.add_parser(
        "doctor",
        help=(
            "check the connection: URL rules, token transport, engine reachability, MCP tool catalogue; "
            "for a local engine, then run the launcher's own host checks"
        ),
    )
    connection(doctor)
    commands.add_parser("version", help="print the client version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "help":
        argv = ["--help"]
    if argv and argv[0] not in CLIENT_COMMANDS and not argv[0].startswith("-"):
        return run_engine(argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        return COMMANDS[args.command](args)
    except ClientError as exc:
        sys.stderr.write(f"shakerscan: {exc}\n")
        return 2

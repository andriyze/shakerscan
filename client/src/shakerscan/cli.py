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
import getpass
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path

from . import __version__
from ._vendored import kit_sources, load

INSTALL_ONE_LINER = "curl -fsSL https://install.shakerscan.com | sh"
CLIENT_COMMANDS = ("connect", "disconnect", "agent", "api", "scan", "check", "mcp", "hunt", "doctor", "version")
AGENTS = ("claude", "codex", "opencode")
CONNECT_PATH = "/_enterprise/connect/"
ENV_CONFIG_DIR = "SHAKERSCAN_CONFIG_DIR"
DEFAULT_API_URL = "http://127.0.0.1:8080"
PUBLIC_API_URL = "https://pub.shakerscan.com"
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


# --- the saved profile -----------------------------------------------------------------------


def config_dir(environ: Mapping[str, str] | None = None) -> Path:
    """``$SHAKERSCAN_CONFIG_DIR`` or ``~/.config/shakerscan``: the saved instance and its token."""
    environ = os.environ if environ is None else environ
    return Path(environ.get(ENV_CONFIG_DIR) or (Path.home() / ".config" / "shakerscan"))


def profile(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The saved instance (``url``, ``token_file``), written by ``shakerscan connect``."""
    try:
        data = json.loads((config_dir(environ) / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: str(v) for k, v in data.items() if isinstance(v, str)} if isinstance(data, dict) else {}


def save_profile(url: str, token: str | None, environ: Mapping[str, str] | None = None) -> Path:
    """Write the instance address and, when there is one, the token (owner-only).

    ``token=None`` saves an open-source engine reached by address (``shakerscan start --lan``
    on the server): no credential, so any token file from an earlier connection is removed
    rather than left to be sent to an engine that never issued it.
    """
    directory = config_dir(environ)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    token_path = directory / "token"
    record: dict[str, str] = {"url": url}
    if token is None:
        token_path.unlink(missing_ok=True)
    else:
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(token + "\n")
        os.chmod(token_path, 0o600)
        record["token_file"] = str(token_path)
    (directory / "config.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return directory


# --- connection ------------------------------------------------------------------------------


def _origin(url: str) -> tuple[str, str, int] | None:
    """``(scheme, host, effective port)``, or ``None`` when the URL is not an http(s) origin."""
    try:
        parts = urllib.parse.urlsplit(str(url or "").strip())
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    return parts.scheme, parts.hostname.lower().rstrip("."), port or (443 if parts.scheme == "https" else 80)


def same_origin(left: str, right: str) -> bool:
    """Whether two URLs name the same scheme, host and effective port.

    ``https://host`` and ``https://host:443`` are one origin; a different port, a
    different host, or a downgrade to http is a different one.
    """
    resolved = _origin(left)
    return resolved is not None and resolved == _origin(right)


def read_token(
    token_file: str | None,
    environ: Mapping[str, str] | None = None,
    saved: Mapping[str, str] | None = None,
) -> str | None:
    """The service token: ``--token-file``, then ``SHAKERSCAN_API_TOKEN_FILE``, then
    ``SHAKERSCAN_API_TOKEN``, then the saved profile's token file."""
    environ = os.environ if environ is None else environ
    path = token_file or environ.get(ENV_TOKEN_FILE) or ""
    if not path and not environ.get(ENV_TOKEN, "").strip() and saved and saved.get("token_file"):
        path = saved["token_file"]
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
    saved = profile(environ)
    if url:
        overrides[ENV_URL] = url
        overrides[ENV_ALLOW_REMOTE] = "true"
    elif not environ.get(ENV_URL) and saved.get("url"):
        # The saved instance: the operator connected to it deliberately.
        overrides[ENV_URL] = saved["url"]
        overrides[ENV_ALLOW_REMOTE] = "true"
    # The saved profile is one connection: its token belongs to its URL. Inherit it only
    # when the origin actually being addressed is the one that was connected to, so a
    # mistyped or agent-supplied URL cannot carry an existing credential elsewhere. An
    # explicit --token-file or SHAKERSCAN_API_TOKEN remains a deliberate override.
    effective_url = url or environ.get(ENV_URL) or saved.get("url") or ""
    bound = saved if saved.get("url") and same_origin(effective_url, saved["url"]) else None
    token = read_token(token_file, environ, bound)
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


# --- connect -------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def fetch_connect_link(link: str, *, opener=None, timeout: float = 20.0) -> dict[str, str]:
    """Claim a one-time connect link: the instance hands out the token exactly once, over HTTPS."""
    parts = urllib.parse.urlsplit(link)
    if parts.scheme != "https" or not parts.hostname or CONNECT_PATH not in parts.path:
        raise ClientError("a connect link looks like https://<instance>/_enterprise/connect/<code> (https only)")
    opener = opener or urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(link, headers={"Accept": "application/json", "User-Agent": f"shakerscan-client/{__version__}"})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(65536)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ClientError(
                "this connect link has expired or was already used; create a new token in the console"
            ) from exc
        if exc.code == 429:
            raise ClientError("too many connect attempts from this address; wait a few minutes") from exc
        raise ClientError(f"the instance answered HTTP {exc.code} to the connect link") from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise ClientError(f"cannot reach the instance: {getattr(exc, 'reason', exc)}") from exc
    try:
        data = json.loads(body.decode("utf-8"))
    except ValueError as exc:
        raise ClientError("the connect link did not answer with JSON") from exc
    if not isinstance(data, dict) or not str(data.get("url", "")).startswith("https://") or not data.get("token"):
        raise ClientError("the connect link answered without an instance address and token")
    return {k: str(data[k]) for k in ("url", "token", "role", "label") if k in data}


def client_executable() -> str:
    """The path Claude Code should spawn: this very command when it is on disk, else by name."""
    candidate = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
    if candidate and candidate.name == "shakerscan" and candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate.resolve())
    return shutil.which("shakerscan") or "shakerscan"


def register_claude_code() -> int:
    """Register `shakerscan mcp` as a user-scoped MCP server in Claude Code, when it is installed."""
    claude = shutil.which("claude")
    argv = ["claude", "mcp", "add", "--scope", "user", "shakerscan", "--", client_executable(), "mcp"]
    if not claude:
        print("claude:    Claude Code is not on this PATH; register later with:\n           " + " ".join(argv))
        return 0
    result = subprocess.run([claude, *argv[1:]], capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["no output"]
        print(f"claude:    registration failed ({detail[0]}); run later: {' '.join(argv)}")
        return 1
    print("claude:    registered as MCP server 'shakerscan' (user scope); restart Claude Code to see it")
    return 0


def cmd_connect(args: argparse.Namespace) -> int:
    """Save an instance, then check it.

    Three shapes: an Enterprise connect link (token claimed once, over https); an https address
    with a token from a prompt or stdin; or an open-source engine's address with no token. A
    plain-http address is always the last kind, since a bearer token is never sent over http;
    an https engine without a login needs ``--no-token`` said explicitly.
    """
    target = str(args.target).strip()
    token: str | None
    if CONNECT_PATH in target:
        claimed = fetch_connect_link(target, timeout=float(args.timeout or 20.0))
        url, token = claimed["url"], claimed["token"]
        who = f" ({claimed.get('role', '?')} token '{claimed.get('label', '')}')"
    else:
        parts = urllib.parse.urlsplit(target)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.path not in ("", "/") \
                or parts.query or parts.fragment or "@" in parts.netloc:
            raise ClientError(
                "give the instance address as https://scanner.example.com (Enterprise, a token is "
                "asked for), http://192.168.1.50:8080 (an open-source engine, no token), or a connect link"
            )
        url = f"{parts.scheme}://{parts.netloc}"
        if parts.scheme == "http" or args.no_token:
            token = None
            who = " (open-source engine reached by address; no token, no per-person identity)"
        else:
            token = sys.stdin.readline().strip() if args.token_stdin else getpass.getpass("Service token: ").strip()
            if not token:
                raise ClientError("no token given (an open-source engine over https needs --no-token)")
            who = ""
    directory = save_profile(url, token)
    if token is None:
        print(f"saved:     {url}{who}\n           address in {directory / 'config.json'}; no token file")
    else:
        print(f"saved:     {url}{who}\n           token in {directory / 'token'} (owner-only), address in {directory / 'config.json'}")
    for key in (ENV_URL, ENV_TOKEN, ENV_TOKEN_FILE, ENV_ALLOW_REMOTE):
        os.environ.pop(key, None)
    code = cmd_doctor(argparse.Namespace(url=None, token_file=None, timeout=args.timeout))
    if args.claude:
        code = max(code, register_claude_code())
    if not args.claude:
        print("next:      shakerscan agent claude   (or codex, opencode: the ShakerScan agent workspace against this instance)")
        print("           claude mcp add --scope user shakerscan -- shakerscan mcp   (MCP only, any client)")
    else:
        print("next:      shakerscan agent claude   (the ShakerScan agent workspace against this instance)")
    return code


def cmd_disconnect(args: argparse.Namespace) -> int:  # noqa: ARG001
    directory = config_dir()
    removed = []
    for name in ("token", "config.json"):
        path = directory / name
        if path.exists():
            path.unlink()
            removed.append(str(path))
    print("removed:   " + (", ".join(removed) if removed else "nothing saved under " + str(directory)))
    return 0


# --- the agent workspace ---------------------------------------------------------------------


INSTANCE_NOTE = """# Connected ShakerScan instance

This workspace was prepared by `shakerscan agent` for **{url}** ({who}). There is no local engine
here: `./scanner.sh start`, `stop`, `scale`, `docker compose` and `/queue` do not apply. Talk to
the instance with `shakerscan api METHOD PATH [JSON]`, `shakerscan scan …`, `shakerscan hunt …`
and the MCP tools (server `shakerscan`); the credential is in a file those commands read, never
in the environment. Every action runs under that person's identity and role and is audited. A
route the instance keeps closed answers with a refusal that names what is missing: report it and
choose another path. Kit version: ShakerScan {kit_version}.

"""

ENGINE_NOTE = """# Remote ShakerScan engine

This workspace was prepared by `shakerscan agent --url` for **{url}** ({who}). There is no local
engine here: `./scanner.sh start`, `stop`, `scale`, `docker compose` and `/queue` do not apply;
lifecycle commands run on the server. Talk to the engine with `shakerscan api METHOD PATH [JSON]`,
`shakerscan scan …`, `shakerscan hunt …` and the MCP tools (server `shakerscan`). The engine has
no login: there is no credential and no per-person identity, so it must only be reachable on a
network whose users you trust (`shakerscan start --lan` on the server). Target authorization,
budgets, credential admission and the deterministic proof rules still apply on the server, and a
closed route answers with a refusal that names what is missing. Kit version: ShakerScan
{kit_version}.

"""


def agent_origin(url: str) -> str:
    """A validated API origin for ``agent --url``: http(s), a host, no path or credentials."""
    candidate = str(url or "").strip().rstrip("/")
    parts = urllib.parse.urlsplit(candidate)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.path not in {"", "/"} \
            or parts.query or parts.fragment or "@" in parts.netloc:
        raise ClientError(
            f"--url must be the engine's API origin such as http://192.168.1.50:8080, not {url!r}"
        )
    return f"{parts.scheme}://{parts.netloc}"


def _copy_tree(source: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def _retire_legacy_agent_guide(workspace: Path) -> None:
    """Remove stale guide precedence without losing operator edits or following links."""
    legacy = workspace / "CLAUDE.md"
    if not legacy.is_file() and not legacy.is_symlink():
        return
    fd, backup_name = tempfile.mkstemp(
        prefix=".shakerscan-retired-CLAUDE-", suffix=".bak", dir=workspace,
    )
    os.close(fd)
    backup = Path(backup_name)
    try:
        legacy.replace(backup)  # Moves the symlink itself, never its destination.
    except OSError:
        backup.unlink(missing_ok=True)
        raise


def prepare_workspace(
    workspace: Path, url: str, who: str, executable: str, *, authenticated: bool = True,
) -> list[str]:
    """Materialize the agent kit against the instance; return what was written.

    ``authenticated`` is the saved Enterprise connection (token in its file, per-person
    identity). Otherwise the workspace addresses an open-source engine by URL: the MCP
    registrations carry ``--url`` so the agent's own subprocesses reach it without any
    environment, and the note says what that means.
    """
    sources = kit_sources()
    mcp_args = ["mcp"] if authenticated else ["mcp", "--url", url]
    workspace.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    _copy_tree(sources["skills"], workspace / "skills")
    written.append("skills/")
    _copy_tree(sources[".claude"], workspace / ".claude")
    for hook in (workspace / ".claude" / "hooks").glob("*.sh"):
        hook.chmod(hook.stat().st_mode | 0o111)
    written.append(".claude/")
    kit_version = "unknown"
    version_file = sources["AGENTS.md"].parent / "VERSION"
    if version_file.is_file():
        kit_version = version_file.read_text(encoding="utf-8").strip() or kit_version
    template = INSTANCE_NOTE if authenticated else ENGINE_NOTE
    note = template.format(url=url, who=who, kit_version=kit_version)
    for name in ("AGENTS.md",):
        (workspace / name).write_text(note + sources[name].read_text(encoding="utf-8"), encoding="utf-8")
        written.append(name)
    (workspace / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"shakerscan": {"command": executable, "args": mcp_args}}}, indent=2) + "\n",
        encoding="utf-8",
    )
    written.append(".mcp.json")
    (workspace / "opencode.json").write_text(
        json.dumps(
            {
                "$schema": "https://opencode.ai/config.json",
                "mcp": {"shakerscan": {"type": "local", "command": [executable, *mcp_args], "enabled": True}},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append("opencode.json")
    _retire_legacy_agent_guide(workspace)
    return written


def agent_environment(
    url: str, token_file: str | None, agent: str, environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """What the launcher exports, plus the connection: the token stays in its file.

    Without a token file (an open-source engine addressed by URL) no credential variable is
    set at all, so a stale ``SHAKERSCAN_API_TOKEN_FILE`` cannot follow the agent to an engine
    that never issued it.
    """
    env = dict(os.environ if environ is None else environ)
    env.pop(ENV_TOKEN, None)
    env.pop(ENV_TOKEN_FILE, None)
    env.update(
        {
            "SHAKERSCAN_API_BASE": url,
            "SHAKERSCAN_API_URL": url,
            "SHAKERSCAN_UI_BASE": url,
            ENV_ALLOW_REMOTE: "true",
            "SHAKERSCAN_MANAGED_INSTANCE": "1",
            "SHAKERSCAN_AGENT_NAME": agent,
            "SHAKERSCAN_RESEARCH_PLANNER_MODE": "agent",
        }
    )
    if token_file:
        env[ENV_TOKEN_FILE] = token_file
    return env


def resolve_agent_instance(args: argparse.Namespace, environ: Mapping[str, str] | None = None) -> tuple[str, str | None, str]:
    """Where ``shakerscan agent`` works: (url, token file or None, how to describe it).

    An explicit ``--url`` is an open-source engine reached by address (``shakerscan start
    --lan`` on the server), with no credential, unless it names the saved connection, which
    keeps its token. Otherwise the saved Enterprise connection, then ``SHAKERSCAN_API_URL`` from
    the environment as another unauthenticated engine.
    """
    environ = os.environ if environ is None else environ
    saved = profile(environ)
    engine = "an open-source engine reached by address; no credential, no per-person identity"
    if getattr(args, "url", None):
        url = agent_origin(args.url)
        if saved.get("url") and saved.get("token_file") and same_origin(url, saved["url"]):
            return saved["url"], saved["token_file"], "the connected person's identity and role"
        return url, None, engine
    if saved.get("url"):
        # `shakerscan connect`: an Enterprise instance with its token, or an open-source engine
        # saved by address with none.
        if saved.get("token_file"):
            return saved["url"], saved["token_file"], "the connected person's identity and role"
        return agent_origin(saved["url"]), None, engine
    if environ.get(ENV_URL):
        url = agent_origin(environ[ENV_URL])
        return url, None, "an open-source engine reached by address; no credential, no per-person identity"
    raise ClientError(
        "no instance to work against: run `shakerscan connect <link>` for an Enterprise instance "
        "(the console shows the link), or pass `--url http://<server>:8080` for an open-source "
        "engine started with `shakerscan start --lan`"
    )


def cmd_agent(args: argparse.Namespace) -> int:
    url, token_file, who = resolve_agent_instance(args)
    authenticated = token_file is not None
    agents = [args.agent] if args.agent else [a for a in AGENTS if shutil.which(a)]
    if args.agent and args.agent not in AGENTS:
        raise ClientError(f"unsupported agent '{args.agent}'; use one of {', '.join(AGENTS)}")
    if not agents and not args.no_launch:
        raise ClientError("no supported agent on this PATH; install Claude Code, Codex or OpenCode, or pass --no-launch")
    agent = agents[0] if agents else "claude"
    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else (Path.cwd() if args.here else config_dir() / "agent")
    executable = client_executable()
    written = prepare_workspace(workspace, url, who, executable, authenticated=authenticated)
    print(f"workspace: {workspace} ({', '.join(written)})\ninstance:  {url} ({who})")
    if agent == "codex" and shutil.which("codex"):
        # Codex keeps MCP servers in its own configuration, not in the workspace.
        mcp_args = ["mcp"] if authenticated else ["mcp", "--url", url]
        result = subprocess.run(
            ["codex", "mcp", "add", "shakerscan", "--", executable, *mcp_args],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if result.returncode == 0:
            print("codex:     MCP server 'shakerscan' registered")
        else:
            detail = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["no output"]
            print(f"codex:     MCP registration skipped ({detail[0]})")
    if args.no_launch:
        if authenticated:
            print(f"launch:    cd {workspace} && {agent}")
        else:
            # The kit's `shakerscan api` calls need the engine's address; the MCP registration
            # already carries it.
            print(f"launch:    cd {workspace} && {ENV_URL}={url} {ENV_ALLOW_REMOTE}=true {agent}")
        return 0
    if not shutil.which(agent):
        raise ClientError(f"{agent} is not on this PATH")
    env = agent_environment(url, token_file, agent)
    print(f"starting:  {agent} in {workspace}")
    sys.stdout.flush()
    os.chdir(workspace)
    os.execvpe(agent, [agent], env)
    return 0  # unreachable


def cmd_api(args: argparse.Namespace) -> int:
    url = apply_connection(args)
    rest = list(args.args) or ["--help"]
    if rest and rest[0] == "--":
        rest = rest[1:]
    return int(load("_api_cli").main(["--api-url", url, *rest]))


def scan_ui_url(api_url: str) -> str:
    """Recognize a bare local IP, not every reverse proxy listening on 8080.

    Named gateways and path prefixes retain the configured URL. The forwarded
    scan CLI's explicit --ui-url always wins for custom/private proxy layouts.
    """
    parts = urllib.parse.urlsplit(api_url)
    host = parts.hostname or ""
    try:
        address = ipaddress.ip_address(host)
        local = address.is_loopback or any(address in network for network in (
            ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("fc00::/7"),
        ) if network.version == address.version)
    except ValueError:
        local = host.lower() == "localhost"
    if (parts.scheme == "http" and parts.port == 8080 and local
            and parts.path in {"", "/"} and not parts.query and not parts.fragment
            and parts.username is None):
        if ":" in host:
            host = f"[{host}]"
        return urllib.parse.urlunsplit(("http", f"{host}:3000", "", "", ""))
    return api_url


def cmd_scan(args: argparse.Namespace) -> int:
    url = apply_connection(args)
    rest = list(args.args) or ["--help"]
    if rest and rest[0] == "--":
        rest = rest[1:]
    return int(load("_scan_cli").main(["--api-url", url, "--ui-url", scan_ui_url(url), *rest]))


# --- public checks ---------------------------------------------------------------------------

_PUBLIC_DOMAIN = re.compile(
    r"(?=^.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


_INSTANCE_HOST = re.compile(r"(?=^.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)*$")


def _ip_literal(host: str, *, public: bool) -> str | None:
    """The canonical form of an IP literal, or None for a hostname. The hosted service accepts
    only global addresses; a connected instance decides for itself and is sent any address."""
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
    if public and (not address.is_global or getattr(address, "ipv4_mapped", None)):
        raise ClientError("public checks require a public IP address or DNS hostname")
    return str(address)


def split_public_target(value: str, *, public: bool = True) -> tuple[str, str | None]:
    """Return the canonical hostname or IP address, and the URL path when one was given.

    ``public`` applies the hosted service's rules (public DNS names and global addresses).
    A connected OSS or Enterprise instance applies its own policy, so only syntax is checked."""
    raw = str(value or "").strip()
    if not raw:
        raise ClientError("give a public domain or IP address, for example: shakerscan check example.com")
    path = None
    if "://" in raw:
        parts = urllib.parse.urlsplit(raw)
        try:
            port = parts.port
        except ValueError as exc:
            raise ClientError("public checks accept a domain, IP address or http(s) URL") from exc
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or port is not None:
            raise ClientError("public checks accept a domain, IP address or http(s) URL without credentials or a port")
        host = parts.hostname
        if parts.path not in {"", "/"}:
            path = parts.path
    else:
        if any(ch in raw for ch in "/?#@"):
            raise ClientError("public checks accept a domain, IP address or http(s) URL, not a path or credential")
        host = raw
    address = _ip_literal(host, public=public)
    if address:
        return address, path
    host = host.rstrip(".").lower()
    if not public:
        if not _INSTANCE_HOST.fullmatch(host):
            raise ClientError("checks require an IP address or DNS hostname")
        return host, path
    if host in LOOPBACK_HOSTS or not _PUBLIC_DOMAIN.fullmatch(host):
        raise ClientError("public checks require a public IP address or DNS hostname")
    return host, path


def normalize_public_target(value: str) -> str:
    """Return a canonical public hostname or IP address for the hosted posture service."""
    return split_public_target(value)[0]


def public_request_json(path: str, payload: Mapping[str, object], *, timeout: float = 20.0, opener=None):
    """Call the fixed ShakerScan public service without consulting saved/private credentials."""
    if not path.startswith("/v1/"):
        raise ClientError("invalid public-service path")
    body = json.dumps(dict(payload), separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        PUBLIC_API_URL + path,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"shakerscan-client/{__version__}",
        },
    )
    opener = opener or urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(262144)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise ClientError("public ShakerScan rate limit reached; try again later") from exc
        raise ClientError(f"public ShakerScan answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise ClientError(f"cannot reach {PUBLIC_API_URL}: {getattr(exc, 'reason', exc)}") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise ClientError("public ShakerScan returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise ClientError("public ShakerScan returned an unexpected response")
    return data


# A few observed values that almost always need attention. The service returns facts only;
# these short hints are the client's reading of them and never replace the facts.
def _public_hint(item: Mapping[str, object]) -> str | None:
    result = item.get("result")
    if not isinstance(result, Mapping):
        return None
    ident = item.get("id")
    if ident == "mail.spf":
        return {"+": "SPF +all lets any server send as this domain",
                "?": "SPF ends with neutral ?all, which authorizes nothing",
                "absent": "SPF has no terminal all/redirect policy" if result.get("record_count") == 1 else None}.get(str(result.get("all_qualifier")))
    if ident == "mail.dmarc" and result.get("applied_policy") == "none":
        return "DMARC policy is p=none (monitoring only)"
    if ident == "dns.dnssec" and result.get("local_validation") == "bogus":
        return "DNSSEC validation failed"
    if ident == "tls.handshake":
        days = result.get("certificate_days_remaining")
        if result.get("certificate_verified") is False:
            return "certificate was not verified"
        if isinstance(days, int) and days < 30:
            return f"certificate expires in {days} days"
    return None


def _brief(value: object, limit: int = 4) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        items = [_brief(v) for v in value[:limit]]
        more = f" (+{len(value) - limit})" if len(value) > limit else ""
        return ", ".join(items) + more if items else "none"
    if isinstance(value, Mapping):
        return " ".join(f"{k}={_brief(v)}" for k, v in value.items() if not isinstance(v, (list, Mapping)))
    return str(value)


def _public_facts(item: Mapping[str, object]) -> list[str]:
    """Readable lines for one observation; nested address and connection records get one line each."""
    result = item.get("result")
    ident = item.get("id")
    if not isinstance(result, Mapping):
        return []
    if ident == "ip.network":
        lines = [" ".join(str(part) for part in (a.get("ip"), a.get("asn"), a.get("as_name"), a.get("country_code")) if part)
                 for a in result.get("addresses") or [] if isinstance(a, Mapping)]
        if result.get("reverse_dns"):
            lines.append("reverse DNS: " + _brief(result["reverse_dns"]))
        return lines
    if ident == "http.connections":
        lines = []
        for c in result.get("connections") or []:
            if not isinstance(c, Mapping):
                continue
            cert = c.get("certificate") if isinstance(c.get("certificate"), Mapping) else {}
            parts = [str(c.get("ip")), f"HTTP {c.get('status_code')}", c.get("tls_protocol"), c.get("cipher"),
                     f"cert {cert.get('subject')}" if cert.get("subject") else None,
                     f"expires {cert.get('valid_to')}" if cert.get("valid_to") else None,
                     None if cert.get("ip_address_match") is None else f"lists IP: {_brief(cert['ip_address_match'])}"]
            lines.append(" ".join(str(p) for p in parts if p))
        return lines
    return [f"{key}: {_brief(value)}" for key, value in result.items() if value not in (None, "", [], {})]


def render_public_check(data: Mapping[str, object], target: str,
                        service: str = f"{PUBLIC_API_URL} (no saved ShakerScan credential is sent)") -> str:
    """Plain-text view of the public service's factual observations (schema 2)."""
    lines = [f"ShakerScan Public Check\nTarget: {data.get('target') or target}"]
    if isinstance(data.get("checked_at"), str):
        cache = data.get("cache")
        cached = isinstance(cache, Mapping) and cache.get("hit") is True
        lines.append(f"Checked: {data['checked_at']}" + (" (cached)" if cached else ""))
    observations = [o for o in data.get("observations") or [] if isinstance(o, Mapping)]
    if not observations:
        lines.append(json.dumps(data, indent=2, sort_keys=True))
        return "\n".join(lines)
    hints = [(str(o.get("name") or o.get("id")), h) for o in observations if (h := _public_hint(o))]
    if hints:
        lines.append("\nReview:")
        lines.extend(f"  ! {name}: {hint}" for name, hint in hints)
    missing: list[str] = []
    for group in ("dns", "mail", "http", "tls", "ip"):
        members = [o for o in observations if o.get("group") == group]
        shown = False
        for item in members:
            facts = _public_facts(item)
            name = str(item.get("name") or item.get("id") or "observation")
            if not facts:
                missing.append(name)
                continue
            if not shown:
                lines.append(f"\n{group.upper()}")
                shown = True
            lines.append(f"  {name}")
            lines.extend(f"      {fact[:160]}" for fact in facts[:12])
    if missing:
        lines.append("\nNot observed or not applicable: " + ", ".join(missing))
    for limitation in data.get("limitations") or []:
        if isinstance(limitation, str):
            lines.append(f"Note: {limitation}")
    lines.append(f"\nService: {service}")
    return "\n".join(lines)


def instance_check_json(payload: Mapping[str, object], *, timeout: float = 60.0) -> dict:
    """POST /public/check on the connected instance with its saved credential."""
    url = apply_connection(argparse.Namespace(url=None, token_file=None, timeout=timeout))
    api = load("_api_cli")
    try:
        request = api.build_request("POST", "/public/check", json.dumps(dict(payload)), api_url=url, token=api.bearer_token())
        status, text = api.call(request, timeout=timeout)
    except api.ApiCliError as exc:
        raise ClientError(str(exc)) from exc
    if status >= 300:
        raise ClientError(api.render(status, text)[0])
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ClientError("the instance returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise ClientError("the instance returned an unexpected response")
    return data


def cmd_check(args: argparse.Namespace) -> int:
    """Run a bounded public posture lookup without an engine, account, or saved connection."""
    instance = has_configured_instance()
    target, url_path = split_public_target(args.target, public=not instance)
    path = getattr(args, "path", None) or url_path
    selector = getattr(args, "dkim_selector", None)
    payload: dict[str, object] = {"target": target}
    if path:
        payload["path"] = path
    if selector:
        payload["dkim_selector"] = selector
    if instance:
        # A configured/local ShakerScan instance owns all requests. Never send the target to
        # the public service once the user has chosen a private instance. The instance runs
        # the same check engine and answers in the same schema, so output is identical.
        data = instance_check_json(payload, timeout=float(args.timeout or 60.0))
    else:
        data = public_request_json("/v1/check", payload, timeout=float(args.timeout or 20.0))
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0
    print(render_public_check(data, target, "the connected ShakerScan instance" if instance else
                              f"{PUBLIC_API_URL} (no saved ShakerScan credential is sent)"))
    return 0


# --- client commands ------------------------------------------------------------------------


def cmd_version(args: argparse.Namespace) -> int:  # noqa: ARG001
    """The client version, and the engine release installed beside it when there is one, so the
    output means the same thing whichever install channel put ``shakerscan`` on the PATH."""
    print(f"shakerscan client {__version__}")
    engine = engine_version()
    if engine:
        print(f"engine {engine} ({engine_home() / 'scanner.sh'})")
    return 0


def has_configured_instance(environ: Mapping[str, str] | None = None) -> bool:
    """Whether the client has an explicit/saved/private ShakerScan instance to prefer."""
    environ = os.environ if environ is None else environ
    return bool(environ.get(ENV_URL) or profile(environ).get("url") or engine_launcher())


def apply_default_connection(args: argparse.Namespace) -> str:
    """Use the configured/local instance when one exists; otherwise use public ShakerScan.

    Public is a zero-configuration default, never an override. Once an instance is configured,
    normal client commands stay on that instance and do not fall back to public on failure.
    """
    if args.url or has_configured_instance():
        return apply_connection(args)
    os.environ[ENV_URL] = PUBLIC_API_URL
    os.environ[ENV_ALLOW_REMOTE] = "true"
    os.environ.pop(ENV_TOKEN, None)
    os.environ.pop(ENV_TOKEN_FILE, None)
    return PUBLIC_API_URL


def cmd_mcp(args: argparse.Namespace) -> int:
    url = apply_default_connection(args)
    if urllib.parse.urlsplit(url).hostname == "pub.shakerscan.com":
        os.environ.pop(ENV_TOKEN, None)
        os.environ.pop(ENV_TOKEN_FILE, None)
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
    if not args.url and not os.environ.get(ENV_URL) is None and profile().get("url") == url:
        lines[-1] = f"api url:  {url} (saved profile in {config_dir()})"
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
    # Health and catalogue are separate facts: a reachable tool catalogue does not
    # establish that the engine is healthy, so each failure stands on its own.
    ok = True
    try:
        health = client.request_json("GET", "/health")
        status = health.get("status") if isinstance(health, dict) else None
        lines.append(f"engine:   reachable ({status or 'ok'})")
    except mcp.MCPError as exc:
        lines.append(f"engine:   {_with_reason(exc)}")
        ok = False
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


COMMANDS = {
    "version": cmd_version,
    "mcp": cmd_mcp,
    "hunt": cmd_hunt,
    "doctor": cmd_doctor,
    "connect": cmd_connect,
    "disconnect": cmd_disconnect,
    "agent": cmd_agent,
    "api": cmd_api,
    "scan": cmd_scan,
    "check": cmd_check,
}


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
                f"the saved profile from `shakerscan connect`, else {DEFAULT_API_URL}); an explicit "
                "--url authorizes a remote origin"
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

    connect = commands.add_parser(
        "connect",
        help=(
            "save the instance every command then uses: an Enterprise connect link (or address "
            "plus token), or an open-source engine's address with no token; then check it"
        ),
    )
    connect.add_argument(
        "target",
        help=(
            "the connect link; an https instance address, to be prompted for a token; or an "
            "open-source engine's address such as http://192.168.1.50:8080 (as printed by "
            "`shakerscan start --lan`), saved with no token"
        ),
    )
    connect.add_argument(
        "--no-token",
        action="store_true",
        help="the address is an open-source engine without a login (implied for http://)",
    )
    connect.add_argument("--claude", action="store_true", help="also register `shakerscan mcp` in Claude Code (user scope)")
    connect.add_argument("--token-stdin", action="store_true", help="read the token from standard input instead of a prompt")
    connect.add_argument("--timeout", type=float, help="seconds per request (default 20)")
    commands.add_parser("disconnect", help="forget the saved instance and delete its token file")
    agent = commands.add_parser(
        "agent",
        help=(
            "start Claude Code, Codex or OpenCode in the ShakerScan agent workspace, against the "
            "connected instance or an open-source engine named with --url"
        ),
    )
    agent.add_argument("agent", nargs="?", choices=AGENTS, help="which agent (default: the first one installed)")
    agent.add_argument(
        "--url",
        help=(
            "an open-source engine's API origin, e.g. http://192.168.1.50:8080 as printed by "
            f"`shakerscan start --lan` on the server (default: the saved connection, else ${ENV_URL}); "
            "no token and no per-person identity, so only on a trusted network"
        ),
    )
    agent.add_argument("--workspace", help="workspace directory (default: ~/.config/shakerscan/agent)")
    agent.add_argument("--here", action="store_true", help="use the current directory as the workspace")
    agent.add_argument("--no-launch", action="store_true", help="prepare the workspace and print how to start")
    api = commands.add_parser("api", help="call the instance's API: METHOD PATH [JSON] (the agent kit's one way in)")
    connection(api)
    api.add_argument("args", nargs=argparse.REMAINDER, help="METHOD PATH [JSON]")
    scan = commands.add_parser("scan", help="submit and follow scans on the connected instance (the runtime's scan CLI)")
    connection(scan)
    scan.add_argument("args", nargs=argparse.REMAINDER, help="the scan CLI's arguments; nothing prints its help")
    check = commands.add_parser(
        "check",
        help="run a free bounded public posture check via https://pub.shakerscan.com (no engine or account)",
    )
    check.add_argument("target", help="public domain, IP address or http(s) URL, e.g. example.com or 1.1.1.1")
    check.add_argument("--path", help="URL path for the CORS probe (default /); a URL target's path is used when given")
    check.add_argument("--dkim-selector", help="DKIM selector to check, e.g. google or selector1")
    check.add_argument("--json", action="store_true", help="print the public service JSON response")
    check.add_argument("--timeout", type=float, help="seconds to wait for the public service (default 20)")
    mcp = commands.add_parser(
        "mcp",
        help="run MCP against the configured/local ShakerScan instance; with none configured, use the public service",
    )
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
        if argv[0] == "status" and engine_launcher() is None and profile().get("url"):
            # No engine on this machine but a connected instance: status means the instance.
            return main(["doctor", *argv[1:]])
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

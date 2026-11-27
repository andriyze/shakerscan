"""``shakerscan mcp install|uninstall|status``: register the ShakerScan MCP server in an agent once.

``shakerscan agent`` prepares a workspace for one session; this writes the ``shakerscan`` entry
into the agent's own configuration (user-wide or one project), so every session has the tools.

Only that entry is ever changed. The rest of each file is kept byte for byte: JSON and JSONC are
edited in place (comments, trailing commas, key order and formatting stay), and Codex's TOML
table is replaced as a block. A file that cannot be read safely (malformed, not UTF-8, a symbolic
or hard link, an entry defined in a form this does not edit) is refused with nothing written.
Every changed file is backed up beside itself first, and written as a new file renamed into place
(``_workspace.Root``), never through a link.

No token is ever written into an agent's file. A stdio entry runs this client, which reads the
saved ``shakerscan connect`` profile or a token file named by path; an entry for an MCP endpoint
that requires a bearer token names an environment variable the agent expands when it connects.

Before anything is written, the exact command the entry will run is started once and must list
the instance's tools (or, for an HTTP endpoint, the endpoint must answer ``tools/list``), so an
unreachable engine, a wrong path or the one-tool public mode are refused, not registered.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__, _workspace
from ._workspace import Root, WorkspaceError

SERVER = "shakerscan"
# The name an HTTP entry takes when the file already has a local (stdio) shakerscan entry.
REMOTE_SERVER = "shakerscan-enterprise"
NAMES = (SERVER, REMOTE_SERVER)
DISCOVERY_PATH = "/.well-known/shakerscan"
DISCOVERY_FORMAT = "shakerscan-discovery/v1"
CLIENTS = ("opencode", "claude", "codex", "cursor", "vscode")
DEFAULT_TOKEN_ENV = "SHAKERSCAN_API_TOKEN"
CODEX_STARTUP_SECONDS = 30
# A Hunt action can hold a call open for up to the adapter's action wait (120 s by default).
CODEX_TOOL_SECONDS = 180
PROTOCOL_VERSION = "2025-06-18"
PROBE_SECONDS = 90.0
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_CHECKS = {
    "opencode": "start `opencode` and type /mcps",
    "claude": "claude mcp list",
    "codex": "codex mcp list",
    "cursor": "cursor-agent mcp list-tools shakerscan (or Cursor Settings > MCP)",
    "vscode": "MCP: List Servers in the VS Code Command Palette",
}


class InstallError(Exception):
    """Refused; nothing was written."""


# --- JSON and JSONC, edited in place -------------------------------------------------------------


class JsoncError(ValueError):
    pass


@dataclass
class _Node:
    kind: str  # object, array, string, scalar
    start: int
    end: int
    value: Any = None
    members: list[_Member] = field(default_factory=list)


@dataclass
class _Member:
    key: str
    key_start: int
    node: _Node


_SCALAR = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null")


class _Parser:
    """JSON plus // and /* */ comments and trailing commas, with the span of every value."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.length = len(text)

    def where(self, index: int) -> str:
        line = self.text.count("\n", 0, index) + 1
        return f"line {line}, column {index - (self.text.rfind(chr(10), 0, index) + 1) + 1}"

    def skip(self, index: int) -> int:
        text = self.text
        while index < self.length:
            if text[index] in " \t\r\n" or (index == 0 and text[index] == "﻿"):
                index += 1
            elif text.startswith("//", index):
                newline = text.find("\n", index)
                index = self.length if newline < 0 else newline + 1
            elif text.startswith("/*", index):
                close = text.find("*/", index + 2)
                if close < 0:
                    raise JsoncError(f"unclosed comment at {self.where(index)}")
                index = close + 2
            else:
                break
        return index

    def string_end(self, index: int) -> int:
        position = index + 1
        while position < self.length:
            char = self.text[position]
            if char == "\\":
                position += 2
            elif char == '"':
                return position + 1
            elif ord(char) < 0x20:
                break
            else:
                position += 1
        raise JsoncError(f"unterminated string at {self.where(index)}")

    def value(self, index: int) -> _Node:
        index = self.skip(index)
        if index >= self.length:
            raise JsoncError("unexpected end of file")
        char = self.text[index]
        if char == "{":
            return self.object(index)
        if char == "[":
            return self.array(index)
        if char == '"':
            end = self.string_end(index)
            return _Node("string", index, end, self._decode(index, end))
        match = _SCALAR.match(self.text, index)
        if not match:
            raise JsoncError(f"unexpected {char!r} at {self.where(index)}")
        return _Node("scalar", index, match.end(), json.loads(match.group()))

    def _decode(self, start: int, end: int) -> str:
        try:
            return json.loads(self.text[start:end])
        except ValueError as exc:
            raise JsoncError(f"invalid string at {self.where(start)}") from exc

    def object(self, index: int) -> _Node:
        node = _Node("object", index, index, {})
        position = self.skip(index + 1)
        while True:
            if position >= self.length:
                raise JsoncError(f"unclosed object at {self.where(index)}")
            if self.text[position] == "}":
                node.end = position + 1
                return node
            if self.text[position] != '"':
                raise JsoncError(f"expected a key at {self.where(position)}")
            key_end = self.string_end(position)
            key = self._decode(position, key_end)
            colon = self.skip(key_end)
            if colon >= self.length or self.text[colon] != ":":
                raise JsoncError(f"expected ':' at {self.where(colon)}")
            child = self.value(colon + 1)
            node.members.append(_Member(key, position, child))
            node.value[key] = child.value
            position = self.skip(child.end)
            if position < self.length and self.text[position] == ",":
                position = self.skip(position + 1)
            elif position >= self.length or self.text[position] != "}":
                raise JsoncError(f"expected ',' or '}}' at {self.where(position)}")

    def array(self, index: int) -> _Node:
        node = _Node("array", index, index, [])
        position = self.skip(index + 1)
        while True:
            if position >= self.length:
                raise JsoncError(f"unclosed array at {self.where(index)}")
            if self.text[position] == "]":
                node.end = position + 1
                return node
            child = self.value(position)
            node.value.append(child.value)
            position = self.skip(child.end)
            if position < self.length and self.text[position] == ",":
                position = self.skip(position + 1)
            elif position >= self.length or self.text[position] != "]":
                raise JsoncError(f"expected ',' or ']' at {self.where(position)}")


def parse_jsonc(text: str) -> _Node:
    """The document's root object, with spans; raises JsoncError for anything else."""
    parser = _Parser(text)
    root = parser.value(0)
    rest = parser.skip(root.end)
    if rest != len(text):
        raise JsoncError(f"unexpected text after the document at {parser.where(rest)}")
    if root.kind != "object":
        raise JsoncError("the document is not a JSON object")
    return root


def _member(node: _Node, key: str, dotted: str) -> _Member | None:
    found = [member for member in node.members if member.key == key]
    if len(found) > 1:
        raise JsoncError(f'"{dotted}" appears more than once')
    return found[0] if found else None


def _line_indent(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    return re.match(r"[ \t]*", text[start:]).group()


def _indent_unit(text: str) -> str:
    match = re.search(r"\n([ \t]+)\S", text)
    return match.group(1) if match else "  "


def _render(value: Any, indent: str, unit: str) -> str:
    rendered = json.dumps(value, indent=unit, ensure_ascii=False)
    return rendered.replace("\n", "\n" + indent)


def jsonc_get(text: str, path: Sequence[str]) -> Any:
    node = parse_jsonc(text)
    for depth, key in enumerate(path):
        if node.kind != "object":
            return None
        member = _member(node, key, ".".join(path[:depth + 1]))
        if member is None:
            return None
        node = member.node
    return node.value


def jsonc_set(text: str, path: Sequence[str], value: Any) -> str:
    """``text`` with the value at ``path`` set; everything else is kept as written."""
    if not text.strip():
        nested: Any = value
        for key in reversed(path):
            nested = {key: nested}
        return json.dumps(nested, indent=2, ensure_ascii=False) + "\n"
    unit = _indent_unit(text)
    node = parse_jsonc(text)
    for depth, key in enumerate(path):
        dotted = ".".join(path[:depth + 1])
        member = _member(node, key, dotted)
        if member is None:
            rest: Any = value
            for inner in reversed(path[depth + 1:]):
                rest = {inner: rest}
            return _insert(text, node, key, rest, unit)
        if depth == len(path) - 1:
            indent = _line_indent(text, member.key_start)
            return text[:member.node.start] + _render(value, indent, unit) + text[member.node.end:]
        if member.node.kind != "object":
            raise JsoncError(f'"{dotted}" is not an object')
        node = member.node
    raise JsoncError("empty path")


def _insert(text: str, node: _Node, key: str, value: Any, unit: str) -> str:
    if node.members:
        last = node.members[-1]
        indent = _line_indent(text, last.key_start)
        member = f"\n{indent}{json.dumps(key)}: {_render(value, indent, unit)}"
        end = position = last.node.end
        while position < len(text) and text[position] in " \t":
            position += 1
        trailing = position < len(text) and text[position] == ","
        if trailing:
            position += 1
            while position < len(text) and text[position] in " \t":
                position += 1
        # A comment on the last member's line stays on that line.
        if text.startswith("//", position):
            newline = text.find("\n", position)
            position = len(text) if newline < 0 else newline
        elif text.startswith("/*", position):
            close = text.find("*/", position)
            if close >= 0 and "\n" not in text[position:close]:
                position = close + 2
        else:
            position = end if not trailing else position
        if trailing:
            return text[:position] + member + "," + text[position:]
        return text[:end] + "," + text[end:position] + member + text[position:]
    outer = _line_indent(text, node.start)
    inner = outer + unit
    snippet = f"\n{inner}{json.dumps(key)}: {_render(value, inner, unit)}\n{outer}"
    close = node.end - 1
    body = text[node.start + 1:close]
    # Keep a comment inside an empty object; drop only blank space before the closing brace.
    return text[:node.start + 1] + body.rstrip(" \t\r\n") + snippet + text[close:]


def jsonc_remove(text: str, path: Sequence[str]) -> str:
    """``text`` without the member at ``path`` (unchanged when it is not there)."""
    node = parse_jsonc(text)
    parent = node
    member = None
    for depth, key in enumerate(path):
        member = _member(parent, key, ".".join(path[:depth + 1]))
        if member is None:
            return text
        if depth < len(path) - 1:
            if member.node.kind != "object":
                return text
            parent = member.node
    assert member is not None
    members = parent.members
    index = members.index(member)
    if len(members) == 1:
        return text[:parent.start + 1] + text[parent.end - 1:]
    if index < len(members) - 1:
        return text[:member.key_start] + text[members[index + 1].key_start:]
    # The last member: drop the comma before it unless it had a trailing one of its own, and keep
    # a comment on the previous member's line.
    comma = _skip_blanks(text, members[index - 1].node.end)
    after = _skip_blanks(text, comma + 1)
    if text.startswith("//", after):
        newline = text.find("\n", after)
        after = len(text) if newline < 0 else newline
    else:
        after = comma + 1
    end = _skip_blanks(text, member.node.end)
    if end < len(text) and text[end] == ",":
        return text[:after] + text[end + 1:]
    return text[:comma] + text[comma + 1:after] + text[member.node.end:]


def _skip_blanks(text: str, index: int) -> int:
    while index < len(text) and text[index] in " \t":
        index += 1
    return index


# --- TOML (Codex): the [mcp_servers.shakerscan] table as a block ---------------------------------

_HEADER = re.compile(r"^\s*\[(\[)?\s*(.+?)\s*\]\]?\s*(?:#.*)?$")

try:  # Python 3.11+
    import tomllib as _tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    _tomllib = None


def _toml_key(raw: str) -> list[str]:
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|([A-Za-z0-9_-]+)', raw)
    return [a or b or c for a, b, c in parts]


def _toml_load(text: str) -> dict | None:
    if _tomllib is None:
        return None
    try:
        return _tomllib.loads(text)
    except _tomllib.TOMLDecodeError as exc:
        raise JsoncError(f"it is not valid TOML ({exc})") from exc


def _toml_blocks(lines: list[str]) -> list[tuple[int, int, list[str]]]:
    """(first line, end line, key) of every table; the root section is not listed."""
    headers = []
    for number, line in enumerate(lines):
        match = _HEADER.match(line)
        if match:
            headers.append((number, _toml_key(match.group(2))))
    return [(start, headers[i + 1][0] if i + 1 < len(headers) else len(lines), key)
            for i, (start, key) in enumerate(headers)]


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    raise TypeError(value)


def _toml_render(entry: Mapping[str, Any], name: str = SERVER) -> str:
    return f"[mcp_servers.{name}]\n" + "".join(f"{key} = {_toml_value(value)}\n" for key, value in entry.items())


def _toml_owned(text: str, name: str = SERVER) -> tuple[list[str], list[tuple[int, int]]]:
    if '"""' in text or "'''" in text:
        if _tomllib is None:
            raise JsoncError("it has multi-line strings, which this Python (3.10) cannot check; edit it by hand")
    lines = text.splitlines(keepends=True)
    owned = [(start, end) for start, end, key in _toml_blocks(lines) if key[:2] == ["mcp_servers", name]]
    data = _toml_load(text)
    defined = isinstance(data, dict) and isinstance(data.get("mcp_servers"), dict) and name in data["mcp_servers"]
    if data is None:
        pattern = r"(?m)^\s*(?:mcp_servers\s*\.\s*)?[\"']?" + re.escape(name) + r"[\"']?\s*[.=]"
        defined = bool(re.search(pattern, text)) or bool(owned)
        if re.search(r"(?m)^\s*mcp_servers\s*=", text):
            defined = True
    if defined and not owned:
        raise JsoncError(f"it defines mcp_servers.{name} inline; edit that entry by hand or remove it first")
    return lines, owned


def toml_get(text: str, name: str = SERVER) -> Any:
    data = _toml_load(text)
    if data is not None:
        servers = data.get("mcp_servers")
        return servers.get(name) if isinstance(servers, dict) else None
    lines, owned = _toml_owned(text, name)
    return "".join(line for start, end in owned for line in lines[start:end]) or None


def toml_set(text: str, entry: Mapping[str, Any], name: str = SERVER) -> str:
    lines, owned = _toml_owned(text, name)
    block = _toml_render(entry, name)
    if owned:
        first = owned[0][0]
        keep_gap = owned[0][1] < len(lines) and not lines[owned[0][1] - 1].strip()
        out = []
        for number, line in enumerate(lines):
            if number == first:
                out.append(block + ("\n" if keep_gap else ""))
            if any(start <= number < end for start, end in owned):
                continue
            out.append(line)
        result = "".join(out)
    else:
        result = text
        if result and not result.endswith("\n"):
            result += "\n"
        if result.strip():
            result += "\n"
        result += block
    check = _toml_load(result)
    if check is not None and (check.get("mcp_servers") or {}).get(name) != dict(entry):
        raise JsoncError("the edited file did not read back as expected; edit it by hand")
    return result


def toml_remove(text: str, name: str = SERVER) -> str:
    lines, owned = _toml_owned(text, name)
    if not owned:
        return text
    out = [line for number, line in enumerate(lines) if not any(s <= number < e for s, e in owned)]
    result = re.sub(r"\n{3,}", "\n\n", "".join(out)).rstrip("\n") + "\n" if any(line.strip() for line in out) else ""
    if _toml_load(result) is None and _tomllib is not None:
        raise JsoncError("the edited file did not read back; edit it by hand")
    return result


# --- what each agent reads -----------------------------------------------------------------------


@dataclass(frozen=True)
class Server:
    """What the entry runs: this client over stdio, or an MCP endpoint over HTTP."""

    command: str = ""
    args: tuple[str, ...] = ()
    url: str = ""
    token_env: str = ""

    @property
    def http(self) -> bool:
        return bool(self.url)

    def describe(self) -> str:
        if self.http:
            return f"{self.url} (bearer token from ${self.token_env})"
        return " ".join([self.command, *self.args])


@dataclass(frozen=True)
class Target:
    client: str
    scope: str  # user | project
    path: Path | None  # None: Claude Code's user scope, written by its own CLI
    form: str  # opencode | claude | cursor | copilot | vscode | codex | claude-cli


def _home(environ: Mapping[str, str]) -> Path:
    return Path(environ.get("HOME") or Path.home())


def _first_existing(directory: Path, names: Sequence[str]) -> Path:
    for name in names:
        if (directory / name).exists() or (directory / name).is_symlink():
            return directory / name
    return directory / names[-1]


def claude_user_file(environ: Mapping[str, str]) -> Path:
    base = environ.get("CLAUDE_CONFIG_DIR")
    return Path(base) / ".claude.json" if base else _home(environ) / ".claude.json"


def target(client: str, project: Path | None, environ: Mapping[str, str]) -> Target:
    home = _home(environ)
    scope = "project" if project is not None else "user"
    if client == "opencode":
        base = project if project is not None else Path(environ.get("XDG_CONFIG_HOME") or home / ".config") / "opencode"
        return Target(client, scope, _first_existing(base, ("opencode.jsonc", "opencode.json")), "opencode")
    if client == "claude":
        if project is not None:
            return Target(client, scope, project / ".mcp.json", "claude")
        return Target(client, scope, None, "claude-cli")
    if client == "codex":
        base = project / ".codex" if project is not None else Path(environ.get("CODEX_HOME") or home / ".codex")
        return Target(client, scope, base / "config.toml", "codex")
    if client == "cursor":
        base = project if project is not None else home
        return Target(client, scope, base / ".cursor" / "mcp.json", "cursor")
    if client == "vscode":
        if project is not None:
            return Target(client, scope, project / ".vscode" / "mcp.json", "vscode")
        base = Path(environ.get("COPILOT_HOME") or home / ".copilot")
        return Target(client, scope, base / "mcp-config.json", "copilot")
    raise InstallError(f"unknown client {client!r}")


def detected(client: str, environ: Mapping[str, str]) -> bool:
    """Whether the agent looks installed here (its command, or its configuration directory)."""
    home = _home(environ)
    commands = {"opencode": ("opencode",), "claude": ("claude",), "codex": ("codex",),
                "cursor": ("cursor-agent", "cursor"), "vscode": ("code",)}[client]
    places = {"opencode": [Path(environ.get("XDG_CONFIG_HOME") or home / ".config") / "opencode"],
              "claude": [claude_user_file(environ)],
              "codex": [Path(environ.get("CODEX_HOME") or home / ".codex")],
              "cursor": [home / ".cursor"],
              "vscode": [Path(environ.get("COPILOT_HOME") or home / ".copilot")]}[client]
    return any(shutil.which(name) for name in commands) or any(place.exists() for place in places)


def entry(form: str, server: Server, *, legacy: bool = False) -> dict[str, Any]:
    """The ``shakerscan`` entry in this agent's own format."""
    variable = server.token_env
    if form == "opencode":
        value: dict[str, Any] = (
            {"type": "remote", "url": server.url, "oauth": False,
             "headers": {"Authorization": f"Bearer {{env:{variable}}}"}}
            if server.http else {"type": "local", "command": [server.command, *server.args]})
        return {**value, "enabled": True} if legacy else value
    if form == "codex":
        head = ({"url": server.url, "bearer_token_env_var": variable} if server.http
                else {"command": server.command, "args": list(server.args)})
        return {**head, "startup_timeout_sec": CODEX_STARTUP_SECONDS, "tool_timeout_sec": CODEX_TOOL_SECONDS}
    reference = {"claude": "${%s}", "claude-cli": "${%s}", "copilot": "${%s}",
                 "cursor": "${env:%s}", "vscode": "${env:%s}"}[form] % variable
    if server.http:
        value = {"type": "http", "url": server.url, "headers": {"Authorization": f"Bearer {reference}"}}
        if form == "cursor":
            value.pop("type")
    else:
        value = {"type": "stdio", "command": server.command, "args": list(server.args)}
    if form == "copilot":
        value["tools"] = ["*"]
    return value


def _json_path(form: str, legacy: bool = False, name: str = SERVER) -> list[str]:
    return {"opencode": ["mcp", name] if legacy else ["mcp", "servers", name],
            "claude": ["mcpServers", name], "cursor": ["mcpServers", name],
            "copilot": ["mcpServers", name], "vscode": ["servers", name]}[form]


def _local(value: Any) -> bool:
    """Whether an existing entry runs a local command (stdio) rather than an HTTP endpoint."""
    if isinstance(value, str):  # a Codex table read as text (Python 3.10, no tomllib)
        return bool(re.search(r"(?m)^\s*command\s*=", value)) and not re.search(r"(?m)^\s*url\s*=", value)
    return isinstance(value, Mapping) and bool(value.get("command")) and not value.get("url")


def entry_name(server: Server, existing: Callable[[str], Any]) -> str:
    """An HTTP entry is named shakerscan-enterprise beside a local shakerscan entry (and keeps that
    name once it has it); everything else is shakerscan."""
    if server.http and (existing(REMOTE_SERVER) is not None or _local(existing(SERVER))):
        return REMOTE_SERVER
    return SERVER


def _opencode_major() -> int | None:
    opencode = shutil.which("opencode")
    if not opencode:
        return None
    try:
        out = subprocess.run([opencode, "--version"], capture_output=True, text=True, timeout=15, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"(\d+)\.\d+", out or "")
    return int(match.group(1)) if match else None


def opencode_legacy(document: Mapping[str, Any], major: Callable[[], int | None] = _opencode_major) -> bool:
    """OpenCode 1.x keeps servers directly under ``mcp``; 2.x under ``mcp.servers`` (and still
    reads the old shape). Follow the file's own shape; an empty file follows the installed version."""
    mcp = document.get("mcp")
    if isinstance(mcp, Mapping):
        if isinstance(mcp.get("servers"), Mapping):
            return False
        if any(isinstance(value, Mapping) and {"type", "command", "url"} & set(value)
               for key, value in mcp.items() if key not in {"servers", "timeout"}):
            return True
    return major() == 1


def _same(left: Any, right: Any) -> bool:
    """Equal, ignoring empty ``env``/``headers`` an agent's own CLI adds."""
    def clean(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {key: clean(item) for key, item in value.items() if item not in ({}, [])}
        return value
    return clean(left) == clean(right)


# --- reading and writing one file ----------------------------------------------------------------


def read_text(path: Path) -> tuple[str | None, int | None]:
    """(text, permission bits), (None, None) when the file is not there. A symbolic or hard link,
    anything but a plain file, or text that is not UTF-8 is refused."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, None
    if stat.S_ISLNK(info.st_mode):
        raise InstallError(f"{path} is a symbolic link (to {os.readlink(path)}). Writing through it would change "
                           "another file; edit the file it points to by hand, or replace the link with a file. "
                           "Nothing was written.")
    if not stat.S_ISREG(info.st_mode):
        raise InstallError(f"{path} is not a plain file. Nothing was written.")
    if info.st_nlink > 1:
        raise InstallError(f"{path} is a hard link shared with another name. Nothing was written.")
    try:
        raw = Root(path.parent).read(path.name)
    except WorkspaceError as exc:
        raise InstallError(f"{exc}. Nothing was written.") from exc
    if raw is None:
        return None, None
    try:
        return raw.decode("utf-8"), stat.S_IMODE(info.st_mode)
    except UnicodeDecodeError as exc:
        raise InstallError(f"{path} is not UTF-8 text. Nothing was written.") from exc


def write_text(path: Path, text: str, mode: int | None, original: str | None, scope: str) -> str | None:
    """Write ``text`` to ``path`` (a new file renamed into place); back up ``original`` beside it
    first. Returns the backup's name."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = Root(path.parent)
    backup = None
    if original is not None:
        backup = _workspace._backup_name(path.name)
        root.write(backup, original.encode("utf-8"), 0o600)
    if mode is None:
        mode = 0o644 if scope == "project" else 0o600
    root.write(path.name, text.encode("utf-8"), mode)
    return backup


@dataclass
class Plan:
    target: Target
    text: str | None = None  # the new file content (None: no change)
    original: str | None = None
    mode: int | None = None
    current: Any = None
    wanted: Any = None
    removing: bool = False
    note: str = ""
    name: str = SERVER
    names: list[str] = field(default_factory=list)  # uninstall: the entries found


def _refuse_file(path: Path, exc: Exception) -> InstallError:
    return InstallError(f"{path}: {exc}. Fix or move the file and run the command again; nothing was written.")


def plan_install(target_: Target, server: Server, major: Callable[[], int | None] = _opencode_major,
                 environ: Mapping[str, str] | None = None, *, name: str | None = None,
                 after: Plan | None = None) -> Plan:
    """The change that registers ``server`` (as ``name``, else the usual name) in one agent's file.
    ``after``: a plan for the same file this one builds on (two servers, one write)."""
    environ = os.environ if environ is None else environ
    plan = Plan(target_)
    if target_.form == "claude-cli":
        plan.name = name or entry_name(server, lambda name: claude_user_entry(environ, name))
        plan.current = claude_user_entry(environ, plan.name)
        plan.wanted = entry("claude-cli", server)
        if plan.current is not None and _same(plan.current, plan.wanted):
            plan.wanted = None
        return plan
    assert target_.path is not None
    if after is not None:
        text = after.text if after.text is not None else after.original
        mode = after.mode
        plan.original, plan.mode = after.original, mode
    else:
        text, mode = read_text(target_.path)
        plan.original, plan.mode = text, mode
    chosen = name
    try:
        if target_.form == "codex":
            plan.name = chosen or entry_name(server, lambda name: toml_get(text or "", name))
            plan.wanted = entry("codex", server)
            plan.current = toml_get(text or "", plan.name)
            if plan.current == plan.wanted or (  # without tomllib (3.10) the table is compared as text
                    isinstance(plan.current, str)
                    and plan.current.strip() == _toml_render(plan.wanted, plan.name).strip()):
                return plan
            plan.text = toml_set(text or "", plan.wanted, plan.name)
            return plan
        filled = bool(text and text.strip())
        document = parse_jsonc(text).value if filled else {}
        legacy = target_.form == "opencode" and opencode_legacy(document, major)
        plan.name = chosen or entry_name(server, lambda name: jsonc_get(text, _json_path(target_.form, legacy, name))
                                         if filled else None)
        path = _json_path(target_.form, legacy, plan.name)
        plan.wanted = entry(target_.form, server, legacy=legacy)
        plan.current = jsonc_get(text, path) if filled else None
        other = _json_path("opencode", not legacy, plan.name) if target_.form == "opencode" else None
        stale = other is not None and text and text.strip() and isinstance(jsonc_get(text, other), Mapping)
        if plan.current is not None and _same(plan.current, plan.wanted) and not stale:
            return plan
        new = text or ""
        if stale:
            new = jsonc_remove(new, other)
        new = jsonc_set(new, path, plan.wanted)
        if jsonc_get(new, path) != plan.wanted:
            raise JsoncError("the edited file did not read back as expected")
        plan.text = new
        plan.note = ".".join(path)
    except JsoncError as exc:
        raise _refuse_file(target_.path, exc) from exc
    return plan


def plan_uninstall(target_: Target, environ: Mapping[str, str] | None = None) -> Plan:
    environ = os.environ if environ is None else environ
    plan = Plan(target_, removing=True)
    if target_.form == "claude-cli":
        plan.names = [name for name in NAMES if claude_user_entry(environ, name) is not None]
        plan.current = plan.names or None
        return plan
    assert target_.path is not None
    text, mode = read_text(target_.path)
    plan.original, plan.mode = text, mode
    if not text or not text.strip():
        return plan
    try:
        if target_.form == "codex":
            new = text
            for name in NAMES:
                if toml_get(new, name) is not None:
                    plan.current = toml_get(new, name)
                    new = toml_remove(new, name)
            if new != text:
                plan.text = new
            return plan
        new = text
        paths = ([_json_path("opencode", legacy, name) for name in NAMES for legacy in (False, True)]
                 if target_.form == "opencode" else [_json_path(target_.form, False, name) for name in NAMES])
        for path in paths:
            if jsonc_get(new, path) is not None:
                plan.current = jsonc_get(new, path)
                new = jsonc_remove(new, path)
        if new != text:
            parse_jsonc(new)
            plan.text = new
    except JsoncError as exc:
        raise _refuse_file(target_.path, exc) from exc
    return plan


# --- Claude Code's user scope: its own CLI writes ~/.claude.json ---------------------------------


def claude_user_entry(environ: Mapping[str, str], name: str = SERVER) -> Any:
    """The user-scoped entry, read (never written) from Claude Code's own file."""
    path = claude_user_file(environ)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise InstallError(f"cannot read {path}: {exc}. Nothing was written.") from exc
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    return servers.get(name) if isinstance(servers, dict) else None


def _claude(argv: Sequence[str]) -> None:
    claude = shutil.which("claude")
    if not claude:
        raise InstallError("Claude Code (`claude`) is not on this PATH; install it, or use --project DIR to write "
                           "a project's .mcp.json. Nothing was written.")
    result = subprocess.run([claude, *argv], capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["no output"]
        raise InstallError(f"`claude {' '.join(argv[:4])}` failed: {detail[0]}")


def apply(plan: Plan) -> str:
    """Carry out a plan; return the line to print."""
    target_ = plan.target
    label = f"{target_.client:<9}"
    if target_.form == "claude-cli":
        where = "Claude Code user scope"
        if plan.removing:
            if not plan.names:
                return f"{label}not registered ({where})"
            for name in plan.names:
                _claude(["mcp", "remove", "--scope", "user", name])
            return f"{label}removed {', '.join(plan.names)} from {where}"
        if plan.wanted is None:
            return f"{label}unchanged {plan.name} ({where})"
        if plan.current is not None:
            _claude(["mcp", "remove", "--scope", "user", plan.name])
        _claude(["mcp", "add-json", "--scope", "user", plan.name, json.dumps(plan.wanted)])
        return f"{label}registered {plan.name} in {where} (`claude mcp add-json --scope user`)"
    assert target_.path is not None
    if plan.text is None:
        state = "not registered in" if plan.removing else "unchanged:"
        return f"{label}{state} {target_.path}"
    backup = write_text(target_.path, plan.text, plan.mode, plan.original, target_.scope)
    verb = "removed from" if plan.removing else (
        f"{plan.name} updated in" if plan.current is not None else f"{plan.name} added to")
    return f"{label}{verb} {target_.path}" + (f" (backup {backup})" if backup else "")


def describe_plan(plan: Plan) -> str:
    target_ = plan.target
    where = str(target_.path) if target_.path else "Claude Code user scope"
    if plan.removing:
        return f"{target_.client:<9}would remove the entry from {where}" if (plan.text or plan.current is not None) \
            else f"{target_.client:<9}not registered in {where}"
    changing = plan.text is not None or (target_.form == "claude-cli" and plan.wanted is not None)
    return f"{target_.client:<9}{'would write' if changing else 'unchanged:'} {where}" + (
        f"\n{' ' * 9}{json.dumps(plan.wanted)}" if changing else "")


# --- the connection and the check before writing -------------------------------------------------


def server_command(explicit: str | None) -> str:
    """The absolute path of this client, as found on the PATH (links not resolved, so a Homebrew
    or pipx upgrade keeps the path working)."""
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise InstallError(f"--server-command {explicit}: not an absolute path to an executable file")
        return str(path)
    argv0 = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
    if argv0 is not None and argv0.name == "shakerscan" and argv0.is_file() and os.access(argv0, os.X_OK):
        return str(argv0.absolute())
    found = shutil.which("shakerscan")
    if found:
        return str(Path(found).absolute())
    raise InstallError("cannot tell where this client is installed; pass --server-command /absolute/path/to/shakerscan")


def stdio_server(args: argparse.Namespace, environ: Mapping[str, str]) -> tuple[Server, str]:
    """The stdio entry and the API origin it reaches."""
    from . import cli

    saved = cli.profile(environ)
    explicit = args.url or environ.get(cli.ENV_URL) or ""
    if explicit:
        url = cli.agent_origin(explicit)
    elif saved.get("url"):
        url = saved["url"]
    elif cli.engine_launcher() is not None:
        url = cli.DEFAULT_API_URL
    else:
        raise InstallError(
            "no ShakerScan instance is configured here, so the server would only offer the public check. Pass "
            "--url http://HOST:8080 (an engine on another host), run `shakerscan connect` first, or install the "
            "engine on this machine. Nothing was written.")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "http" and not cli.is_loopback(url) and not args.lan:
        raise InstallError(
            f"{url} is plain http on another host: the open-source engine has no login, so anyone who can reach it "
            "can use these tools. Only on a network you trust, pass --lan to confirm; otherwise reach it through an "
            "SSH tunnel and use --url http://127.0.0.1:8080. Nothing was written.")
    token_file = ""
    if args.token_file:
        path = Path(args.token_file).expanduser()
        if not path.is_absolute():
            path = path.absolute()
        if not path.is_file():
            raise InstallError(f"--token-file {path}: no such file")
        if parts.scheme != "https":
            raise InstallError("a token is only ever sent over https; this URL is plain http. Nothing was written.")
        token_file = str(path)
    argv = ["mcp", *(["--url", url] if explicit else []), *(["--token-file", token_file] if token_file else [])]
    return Server(command=server_command(args.server_command), args=tuple(argv)), url


def probe_stdio(server: Server, timeout: float = PROBE_SECONDS) -> int:
    """Start the entry's exact command once, as an agent would (without this shell's ShakerScan
    connection variables), and count the tools it lists."""
    from . import cli

    environment = {key: value for key, value in os.environ.items()
                   if key not in {cli.ENV_URL, cli.ENV_TOKEN, cli.ENV_TOKEN_FILE, cli.ENV_ALLOW_REMOTE}}
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "shakerscan-mcp-install", "version": __version__}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    payload = "".join(json.dumps(message) + "\n" for message in messages)
    try:
        result = subprocess.run([server.command, *server.args], input=payload, capture_output=True, text=True,
                                timeout=timeout, env=environment, check=False)
    except subprocess.TimeoutExpired as exc:
        raise InstallError(f"`{server.describe()}` did not answer within {int(timeout)} s. "
                           "Nothing was written.") from exc
    except OSError as exc:
        raise InstallError(f"cannot start {server.command}: {exc.strerror or exc}. Nothing was written.") from exc
    answers = {}
    for line in result.stdout.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if isinstance(message, dict) and "id" in message:
            answers[message["id"]] = message
    listed = answers.get(2) or {}
    tools = (listed.get("result") or {}).get("tools") if isinstance(listed.get("result"), dict) else None
    if not isinstance(tools, list):
        reason = (listed.get("error") or {}).get("message") if isinstance(listed.get("error"), dict) else None
        reason = reason or (result.stderr.strip().splitlines() or ["no answer"])[-1]
        raise InstallError(f"`{server.describe()}` could not list the instance's tools: {reason}. Check the engine "
                           "with `shakerscan doctor` (with the same --url). Nothing was written.")
    names = [str(tool.get("name", "")) for tool in tools if isinstance(tool, dict)]
    if names and all(name == "shakerscan_public_check" for name in names):
        raise InstallError("the server reached only the public check service, not an engine. Pass --url or run "
                           "`shakerscan connect` first. Nothing was written.")
    return len(tools)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ARG002
        return None


def http_post(url: str, body: bytes, headers: Mapping[str, str], timeout: float) -> tuple[int, dict[str, str], bytes]:
    return _http("POST", url, body, headers, timeout)


def http_get(url: str, headers: Mapping[str, str], timeout: float) -> tuple[int, dict[str, str], bytes]:
    return _http("GET", url, None, headers, timeout)


def _http(method: str, url: str, body: bytes | None, headers: Mapping[str, str],
          timeout: float) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read(4_000_000)
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read(65_536) if exc.fp else b""


def _rpc_answer(headers: Mapping[str, str], body: bytes, wanted: int) -> dict:
    text = body.decode("utf-8", "replace")
    if "text/event-stream" in headers.get("content-type", ""):
        for event in re.split(r"\r?\n\r?\n", text):
            data = "\n".join(line[5:].lstrip() for line in event.splitlines() if line.startswith("data:"))
            try:
                message = json.loads(data) if data else None
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("id") == wanted:
                return message
        return {}
    try:
        message = json.loads(text)
    except ValueError:
        return {}
    return message if isinstance(message, dict) else {}


def probe_http(url: str, token: str, timeout: float = 30.0, post=None) -> int:
    """initialize, then tools/list, over streamable HTTP with the bearer token; the tool count."""
    post = post or http_post
    session = ""

    def call(message: dict) -> dict:
        nonlocal session
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": f"Bearer {token}", "MCP-Protocol-Version": PROTOCOL_VERSION}
        if session:
            headers["Mcp-Session-Id"] = session
        status, answer_headers, body = post(url, json.dumps(message).encode("utf-8"), headers, timeout)
        if status in (401, 403):
            raise InstallError(f"{url} refused the token (HTTP {status}). Nothing was written.")
        if 300 <= status < 400:
            raise InstallError(f"{url} redirects (HTTP {status} to {answer_headers.get('location', '?')}); "
                               "use the address it names. Nothing was written.")
        if status >= 400:
            raise InstallError(f"{url} answered HTTP {status}. Nothing was written.")
        session = answer_headers.get("mcp-session-id", session)
        return _rpc_answer(answer_headers, body, message["id"]) if "id" in message else {}

    try:
        first = call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "shakerscan-mcp-install", "version": __version__}}})
        if not isinstance(first.get("result"), dict):
            raise InstallError(f"{url} did not answer an MCP initialize. Nothing was written.")
        call({"jsonrpc": "2.0", "method": "notifications/initialized"})
        count, cursor = 0, None
        for page in range(20):
            listed = call({"jsonrpc": "2.0", "id": 2 + page, "method": "tools/list",
                           "params": {"cursor": cursor} if cursor else {}})
            result = listed.get("result")
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                raise InstallError(f"{url} did not list its tools. Nothing was written.")
            count += len(result["tools"])
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return count
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise InstallError(f"cannot reach {url}: {reason}. Nothing was written.") from exc


def discover(base: str, get=None, timeout: float = 20.0) -> dict[str, Any]:
    """What a deployment offers in its discovery document (``GET <base>/.well-known/shakerscan``, no
    credentials): ``servers``, every MCP server it lists (``name`` as published, or None, and its
    ``url``), each streamable HTTP with bearer authentication on the same origin; and ``api_url``,
    the engine API on that origin when the document names one (the engine's own MCP server runs
    here, as this client's ``shakerscan mcp``, against it)."""
    from . import cli

    get = get or http_get
    url = base.rstrip("/") + DISCOVERY_PATH
    try:
        status, _headers, body = get(url, {"Accept": "application/json"}, timeout)
    except (urllib.error.URLError, OSError) as exc:
        raise InstallError(f"cannot reach {url}: {getattr(exc, 'reason', exc)}. Nothing was written.") from exc
    if status != 200:
        raise InstallError(f"{url} answered HTTP {status}: no discovery document there. Pass the MCP endpoint's "
                           "own URL to --http instead. Nothing was written.")
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise InstallError(f"{url} is not a JSON discovery document. Nothing was written.") from exc
    stated = {document.get(key) for key in ("format", "schema_version", "schema")} if isinstance(document, dict) else set()
    servers = document.get("mcp_servers") if isinstance(document, dict) else None
    if DISCOVERY_FORMAT not in stated or not isinstance(servers, list):
        raise InstallError(f"{url} is not a {DISCOVERY_FORMAT} document. Nothing was written.")
    listed = [item for item in servers if isinstance(item, dict) and item.get("url")]
    if not listed:
        raise InstallError(f"{url} lists no MCP server. Nothing was written.")
    found = []
    for item in listed:
        endpoint = urllib.parse.urljoin(base.rstrip("/") + "/", str(item["url"]))
        if not cli.same_origin(endpoint, base):
            raise InstallError(f"{url} names an MCP server on another origin ({endpoint}); pass it to --http "
                               "yourself if you trust it. Nothing was written.")
        auth = item.get("auth", "bearer")
        # Either the bare scheme ("bearer") or an object naming it ({"type": "bearer", ...}, as an
        # Enterprise gateway publishes it); the object's other keys only describe which token.
        scheme = auth.get("type") if isinstance(auth, dict) else auth
        if item.get("transport", "streamable-http") != "streamable-http" or scheme != "bearer":
            shown = scheme if isinstance(scheme, str) else type(scheme).__name__
            raise InstallError(f"{url}: its MCP server uses {item.get('transport')}/{shown}, not "
                               "streamable HTTP with a bearer token. Nothing was written.")
        name = item.get("name") if isinstance(item.get("name"), str) and item.get("name") in NAMES else None
        found.append({"name": name, "url": endpoint})
    api_url = document.get("api_url") if isinstance(document.get("api_url"), str) else None
    if api_url:
        api_url = urllib.parse.urljoin(base.rstrip("/") + "/", api_url).rstrip("/")
        if not cli.same_origin(api_url, base) or urllib.parse.urlsplit(api_url).scheme != "https":
            api_url = None
    return {"servers": found, "api_url": api_url}


def discover_endpoint(base: str, get=None, timeout: float = 20.0) -> str:
    """The first MCP endpoint a deployment names in its discovery document."""
    return discover(base, get=get, timeout=timeout)["servers"][0]["url"]


def engine_server_for(api_url: str, args: argparse.Namespace, environ: Mapping[str, str]) -> tuple[Server | None, str]:
    """The engine's own MCP server for a deployment (this client over stdio against ``api_url``), or
    None and why not: it needs the token in a file, from ``shakerscan connect`` or ``--token-file``."""
    from . import cli

    saved = cli.profile(environ)
    if saved.get("url") and saved.get("token_file") and cli.same_origin(api_url, saved["url"]):
        return Server(command=server_command(args.server_command), args=("mcp",)), "the saved connection"
    if args.token_file:
        path = Path(args.token_file).expanduser().absolute()
        if not path.is_file():
            raise InstallError(f"--token-file {path}: no such file")
        return Server(command=server_command(args.server_command),
                      args=("mcp", "--url", api_url, "--token-file", str(path))), "--token-file"
    return None, (f"not registered: the engine's server reads its token from a file; run `shakerscan connect` "
                  f"for {api_url} first, or pass --token-file")


def http_servers(args: argparse.Namespace, environ: Mapping[str, str]) -> dict[str, Any]:
    """What ``--http`` registers: ``servers`` [(name or None, Server)], the ``token`` to check them
    with (from the variable, a file or the profile), and for a deployment address whose discovery
    document names its engine API, the engine's own server (``engine``, or None and ``engine_note``)."""
    from . import cli

    parts = urllib.parse.urlsplit(args.http)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise InstallError("--http needs an https:// address (a deployment, or its MCP endpoint) without credentials in it "
                           "(a bearer token is never sent over plain http). Nothing was written.")
    if args.url or args.lan:
        raise InstallError("--http names the endpoint itself; leave out --url and --lan")
    variable = args.token_env or DEFAULT_TOKEN_ENV
    if not _ENV_NAME.match(variable):
        raise InstallError(f"--token-env {variable!r} is not an environment variable name")
    engine, engine_note = None, ""
    if parts.path in ("", "/") and not parts.query:
        # A deployment's base address: its discovery document names the endpoints.
        offered = discover(args.http)
        listed = [(item["name"], Server(url=item["url"], token_env=variable)) for item in offered["servers"]]
        if offered["api_url"] and not any(name == SERVER for name, _server in listed):
            engine, engine_note = engine_server_for(offered["api_url"], args, environ)
    else:
        listed = [(None, Server(url=args.http, token_env=variable))]
    token = (environ.get(variable) or "").strip() or None
    if token is None:
        saved = cli.profile(environ)
        bound = saved if saved.get("url") and cli.same_origin(listed[0][1].url, saved["url"]) else None
        token = cli.read_token(args.token_file, {}, bound)
    return {"servers": listed, "token": token, "engine": engine, "engine_note": engine_note}


def http_server(args: argparse.Namespace, environ: Mapping[str, str]) -> tuple[Server, str | None]:
    """The first HTTP entry and the token to check it with."""
    found = http_servers(args, environ)
    return found["servers"][0][1], found["token"]


# --- commands ------------------------------------------------------------------------------------


def _targets(args: argparse.Namespace, environ: Mapping[str, str], notes: list[str]) -> list[Target]:
    project = Path(args.project).expanduser().absolute() if getattr(args, "project", None) else None
    if project is not None and not project.is_dir():
        raise InstallError(f"--project {project}: not a directory")
    clients = CLIENTS if args.client == "all" else (args.client,)
    chosen = []
    for client in clients:
        if args.client == "all" and not detected(client, environ):
            notes.append(f"{client:<9}skipped (not found on this machine)")
            continue
        if args.client == "all" and client == "claude" and project is None and not shutil.which("claude"):
            notes.append(f"{client:<9}skipped (its user scope is written with the `claude` command, not on PATH)")
            continue
        chosen.append(target(client, project, environ))
    if not chosen:
        raise InstallError("no supported agent was found on this machine; name one: " + ", ".join(CLIENTS))
    return chosen


def _entries(args: argparse.Namespace, environ: Mapping[str, str]) -> tuple[list[tuple[str | None, Server, str]], str | None, list[str]]:
    """[(name or None, server, what it reaches)] to register, the token for the HTTP ones, and lines to print."""
    if not args.http:
        server, reached = stdio_server(args, environ)
        return [(None, server, reached)], None, []
    found = http_servers(args, environ)
    if found["token"] is None:
        raise InstallError(f"set {found['servers'][0][1].token_env} (or pass --token-file) so the endpoint can be "
                           "checked before anything is written. Nothing was written.")
    entries: list[tuple[str | None, Server, str]] = []
    if found["engine"] is not None:
        # Both: the engine's server is `shakerscan` (this client over stdio, its token in a file) and
        # the deployment's own servers keep the names they publish.
        entries.append((SERVER, found["engine"], "the engine's server"))
    for name, server in found["servers"]:
        entries.append((name or (REMOTE_SERVER if found["engine"] is not None else None), server, server.url))
    notes = [f"engine:   {found['engine_note']}"] if found["engine"] is None and found["engine_note"] else []
    return entries, found["token"], notes


def cmd_install(args: argparse.Namespace) -> int:
    environ = os.environ
    notes: list[str] = []
    targets = _targets(args, environ, notes)
    entries, token, server_notes = _entries(args, environ)
    # Every file is read and checked first, then each server, and only then is anything written. Two
    # servers in one file are one write: each plan builds on the one before it.
    plans: list[list[Plan]] = []
    for item in targets:
        chain: list[Plan] = []
        for name, server, _reached in entries:
            chain.append(plan_install(item, server, name=name, after=chain[-1] if chain and item.path else None))
        plans.append(chain)
    for _name, server, reached in entries:
        count = probe_http(server.url, token or "") if server.http else probe_stdio(server)
        print(f"server:   {server.describe()}")
        print(f"checked:  {reached} lists {count} tools")
    for note in server_notes + notes:
        print(note)
    for chain in plans:
        for plan in _writes(chain):
            print(describe_plan(plan) if args.dry_run else apply(plan))
    if args.dry_run:
        print("dry run: nothing was written")
        return 0
    for chain in plans:
        target_ = chain[0].target
        check = _CHECKS[target_.client]
        if target_.client == "claude" and target_.scope == "project":
            check = f"run `claude` in {target_.path.parent} once to approve the project's server, then {check}"
        print(f"check:    {target_.client}: {check}")
    http = [server for _name, server, _reached in entries if server.http]
    if http and not (environ.get(http[0].token_env) or "").strip():
        print(f"note:     {http[0].token_env} is not set in this shell; the agent reads the token from it when it "
              "connects, so set it in the environment the agent starts from")
    return 0


def _writes(chain: list[Plan]) -> list[Plan]:
    """What to carry out for one agent: each of Claude Code's user-scope commands, or one file write
    (the last plan that changes the file holds every change before it)."""
    if not chain or chain[0].target.form == "claude-cli":
        return chain
    changed = [plan for plan in chain if plan.text is not None]
    if not changed:
        return [chain[-1]]
    final = changed[-1]
    final.name = ", ".join(plan.name for plan in changed)
    return [final]


def cmd_uninstall(args: argparse.Namespace) -> int:
    notes: list[str] = []
    plans = [plan_uninstall(item) for item in _targets(args, os.environ, notes)]
    for note in notes:
        print(note)
    for plan in plans:
        print(describe_plan(plan) if args.dry_run else apply(plan))
    return 0


def _summary(form: str, value: Any) -> str:
    if not isinstance(value, Mapping):
        return "registered (not in a form this client reads)"
    if value.get("url"):
        return f"registered: {value['url']} (HTTP)"
    command = value.get("command")
    parts = [str(item) for item in command] if isinstance(command, list) else [str(command or "")]
    parts += [str(item) for item in value.get("args") or []] if isinstance(value.get("args"), list) else []
    executable = parts[0] if parts else ""
    missing = "" if executable and Path(executable).is_file() and os.access(executable, os.X_OK) else \
        "  [command not found: run `shakerscan mcp install` again]"
    return f"registered: {' '.join(parts)}{missing}"


def cmd_status(args: argparse.Namespace) -> int:
    environ = os.environ
    project = Path(args.project).expanduser().absolute() if args.project else Path.cwd()
    for client in CLIENTS:
        for scope_project in (None, project):
            item = target(client, scope_project, environ)
            where = str(item.path) if item.path else f"user scope ({claude_user_file(environ)})"
            try:
                if item.form == "claude-cli":
                    value = claude_user_entry(environ)
                else:
                    assert item.path is not None
                    text, _ = read_text(item.path)
                    if item.form == "codex":
                        value = toml_get(text or "") if text else None
                    elif not text or not text.strip():
                        value = None
                    else:
                        value = None
                        paths = ([_json_path("opencode"), _json_path("opencode", True)]
                                 if item.form == "opencode" else [_json_path(item.form)])
                        for path in paths:
                            value = value or jsonc_get(text, path)
                state = _summary(item.form, value) if value is not None else "not registered"
            except (InstallError, JsoncError) as exc:
                state = f"unreadable: {exc}"
            print(f"{client:<9}{item.scope:<8}{state}\n{' ' * 17}{where}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shakerscan mcp",
        description="Register the ShakerScan MCP server in an agent's own configuration, permanently. "
                    "`shakerscan mcp` with no subcommand runs the server itself.")
    sub = parser.add_subparsers(dest="action", metavar="{install,uninstall,status}", required=True)

    def scope(command: argparse.ArgumentParser) -> None:
        group = command.add_mutually_exclusive_group()
        group.add_argument("--user", action="store_true", help="every project of this user (the default)")
        group.add_argument("--project", metavar="DIR", help="one project directory instead")
        command.add_argument("--dry-run", action="store_true", help="say what would change; write nothing")

    install = sub.add_parser("install", help="add or update the shakerscan entry in an agent's configuration")
    install.add_argument("client", choices=[*CLIENTS, "all"], help="the agent; all = every one found here")
    scope(install)
    install.add_argument("--url", help="the engine's API origin (default: the saved `shakerscan connect` "
                                       "instance, else an engine on this machine)")
    install.add_argument("--token-file", help="a service token file the server reads (its path is written, "
                                              "never the token); https only")
    install.add_argument("--lan", action="store_true",
                         help="confirm a plain-http engine on another host of a trusted network (no login)")
    install.add_argument("--http", metavar="ENDPOINT",
                         help="register an MCP endpoint that requires a bearer token (https) instead of this client: "
                              "the endpoint's URL, or the deployment's address when it publishes "
                              f"{DISCOVERY_PATH}")
    install.add_argument("--token-env", metavar="NAME",
                         help=f"with --http: the environment variable the agent reads the token from "
                              f"(default {DEFAULT_TOKEN_ENV})")
    install.add_argument("--server-command", metavar="PATH",
                         help="the absolute path of the shakerscan client to register (default: this one)")
    install.set_defaults(handler=cmd_install)

    uninstall = sub.add_parser("uninstall", help="remove the shakerscan entry (and nothing else)")
    uninstall.add_argument("client", choices=[*CLIENTS, "all"])
    scope(uninstall)
    uninstall.set_defaults(handler=cmd_uninstall)

    status = sub.add_parser("status", help="where the shakerscan entry is registered, and what it runs")
    status.add_argument("--project", metavar="DIR", help="the project to look in (default: this directory)")
    status.set_defaults(handler=cmd_status)
    return parser


SUBCOMMANDS = ("install", "uninstall", "status")


def main(argv: Sequence[str]) -> int:
    from .cli import ClientError

    args = build_parser().parse_args(list(argv))
    if getattr(args, "token_env", None) and not getattr(args, "http", None):
        raise ClientError("--token-env goes with --http")
    try:
        return int(args.handler(args))
    except (InstallError, WorkspaceError) as exc:
        raise ClientError(str(exc)) from exc

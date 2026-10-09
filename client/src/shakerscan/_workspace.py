"""The agent workspace's configuration: merged, never rewritten, never written through a link.

L3: re-running ``shakerscan agent`` rewrote the agents' configuration from scratch and dropped
what the person had added (OpenCode's ``permission`` block with their bash deny-list, Claude Code
``permissions``, other MCP servers). The client now owns only its parts of each file and merges
them into what is there; every other key is kept, and the command says so.

B2: the kit was copied with ``copytree(dirs_exist_ok=True)``, which writes through symbolic
links, so a link planted under ``.claude/`` (an agent can write the workspace) made the client
overwrite, and make executable, a file outside it. Nothing is written while any path the client
writes is a link, or while ``.claude/`` holds one.

What an agent may have written is made visible, not blocked: the security-relevant parts of the
configuration (permissions, plugins, providers, other MCP servers, instructions, hooks) are
fingerprinted at each launch, and the next launch lists exactly what changed in between, hook
command lines included. The fingerprint and the list of files and hook entries the kit wrote live
in the client's own configuration directory, never in the workspace (N1); the kit's own stale
files and hook entries are removed or replaced on a refresh, and the person's files are left
alone. Every write is a new file renamed into place through directories opened without following
links (N2), so neither a symbolic nor a hard link is ever written through.

Codex keeps its MCP servers in its own configuration (``codex mcp add`` replaces only the
``shakerscan`` entry) and Pi is given flags, so neither has a workspace file here.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

HUNT_SKILL_INSTRUCTION = "skills/hunt/SKILL.md"
OPENCODE_SCHEMA = "https://opencode.ai/config.json"
STATE_SCHEMA = "shakerscan-workspace/v1"
# Every path the client writes in a workspace; none of them may be a link, and nothing under the
# directories among them may be one either (``skills/`` is replaced whole, links included).
WRITTEN_PATHS = ("skills", ".claude", "AGENTS.md", ".mcp.json", "opencode.json")
SCANNED_DIRECTORIES = (".claude",)
_SECRET_PATH = re.compile(r"(api[_-]?key|token|secret|passw|authorization|credential|cookie)", re.IGNORECASE)
_DISPLAY_CHARS = 200


class WorkspaceError(Exception):
    """A workspace the client will not write into; nothing was written."""


# --- the workspace, opened without following links ---------------------------------------------

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
# Directory-relative calls (openat, mkdirat, renameat, unlinkat) make every step of a write
# refuse a link; without them (Windows) the paths are used, after refuse_links.
SAFE_CALLS = bool(_NOFOLLOW and _DIRECTORY and os.open in os.supports_dir_fd
                  and os.mkdir in os.supports_dir_fd and os.unlink in os.supports_dir_fd)


def _parts(relative: str) -> list[str]:
    parts = PurePosixPath(relative).parts
    if not parts or PurePosixPath(relative).is_absolute() or any(part in {"", ".", ".."} for part in parts) \
            or "\\" in relative or PurePosixPath(relative).as_posix() != relative:
        raise WorkspaceError(f"{relative!r} is not a path inside the workspace")
    return list(parts)


class Root:
    """A workspace directory. Every file is written as a new file (a fresh inode, its mode set
    before it is renamed into place), so a hard link at the destination is replaced, never
    written through; every directory on the way is opened with O_NOFOLLOW, so a component
    swapped for a symbolic link after refuse_links is refused, not followed (N2)."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _directory(self, parts: Sequence[str], *, create: bool) -> int:
        fd = os.open(self.path, os.O_RDONLY | _DIRECTORY)
        try:
            for index, part in enumerate(parts):
                if create:
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(part, 0o755, dir_fd=fd)
                try:
                    child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    raise
                except OSError as exc:
                    where = "/".join(parts[:index + 1])
                    raise WorkspaceError(
                        f"{self.path / where} is not a plain directory (a symbolic link?); nothing more "
                        "was written there") from exc
                os.close(fd)
                fd = child
        except BaseException:
            os.close(fd)
            raise
        return fd

    def write(self, relative: str, data: bytes, mode: int = 0o644) -> None:
        parts = _parts(relative)
        if not SAFE_CALLS:
            target = self.path.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                os.chmod(name, mode)
                os.replace(name, target)
            except BaseException:
                Path(name).unlink(missing_ok=True)
                raise
            return
        directory = self._directory(parts[:-1], create=True)
        temporary = f".{parts[-1]}.{uuid.uuid4().hex}.tmp"
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=directory)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fchmod(fd, mode)
            finally:
                os.close(fd)
            os.rename(temporary, parts[-1], src_dir_fd=directory, dst_dir_fd=directory)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=directory)
            raise
        finally:
            os.close(directory)

    def read(self, relative: str) -> bytes | None:
        """The file's bytes, None when it is not there; a link is refused, never followed."""
        parts = _parts(relative)
        if not SAFE_CALLS:
            target = self.path.joinpath(*parts)
            return target.read_bytes() if target.is_file() and not target.is_symlink() else None
        try:
            directory = self._directory(parts[:-1], create=False)
        except FileNotFoundError:
            return None
        try:
            fd = os.open(parts[-1], os.O_RDONLY | _NOFOLLOW, dir_fd=directory)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise WorkspaceError(f"{self.path / relative} is not a plain file (a symbolic link?)") from exc
        finally:
            os.close(directory)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise WorkspaceError(f"{self.path / relative} is not a plain file")
            return handle.read()

    def unlink(self, relative: str) -> None:
        parts = _parts(relative)
        if not SAFE_CALLS:
            self.path.joinpath(*parts).unlink()
            return
        directory = self._directory(parts[:-1], create=False)
        try:
            os.unlink(parts[-1], dir_fd=directory)  # removes the name; never follows a link
        finally:
            os.close(directory)

    def rename(self, relative: str, name: str) -> None:
        """Rename ``relative`` to ``name`` in the same directory (the entry itself, not a target)."""
        parts = _parts(relative)
        if not SAFE_CALLS:
            source = self.path.joinpath(*parts)
            os.replace(source, source.with_name(name))
            return
        directory = self._directory(parts[:-1], create=False)
        try:
            os.rename(parts[-1], name, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            os.close(directory)


# --- links -------------------------------------------------------------------------------------


def refuse_links(workspace: Path) -> None:
    """Refuse, before any write, a workspace where a path the client writes is a symbolic link
    or a hard-linked file (the fail-early check; Root makes each write safe on its own)."""
    links: list[str] = []
    directories: list[str] = []

    def check(path: Path) -> None:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            links.append(path.relative_to(workspace).as_posix())

    for name in WRITTEN_PATHS:
        path = workspace / name
        if not path.exists() and not path.is_symlink():
            continue
        check(path)
        if path.is_symlink():
            continue
        if name in {".mcp.json", "opencode.json", "AGENTS.md"} and path.is_dir():
            directories.append(name)
        elif name in SCANNED_DIRECTORIES and path.is_dir():
            for root, folders, files in os.walk(path, followlinks=False):
                for entry in [*folders, *files]:
                    check(Path(root) / entry)
    if links:
        raise WorkspaceError(
            f"{workspace} has symbolic or hard links where shakerscan writes the agent kit: "
            f"{', '.join(sorted(links))}. Writing through them would change files outside the workspace "
            "(an agent can plant such a link). Remove them and run `shakerscan agent` again; nothing was written."
        )
    if directories:
        raise WorkspaceError(
            f"{workspace}: {', '.join(directories)} should be a file but is a directory. Move it away and "
            "run `shakerscan agent` again; nothing was written."
        )


# --- reading and writing JSON (and OpenCode's JSONC) -------------------------------------------


def _strip_jsonc(text: str) -> str:
    """``text`` without // and /* */ comments and trailing commas; string contents untouched."""
    out: list[str] = []
    pending_comma = False
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char == '"':
            end = index + 1
            while end < length and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            if pending_comma:
                out.append(",")
                pending_comma = False
            out.append(text[index:end + 1])
            index = end + 1
        elif text.startswith("//", index):
            newline = text.find("\n", index)
            index = length if newline < 0 else newline
        elif text.startswith("/*", index):
            close = text.find("*/", index + 2)
            index = length if close < 0 else close + 2
        elif char == ",":
            if pending_comma:
                out.append(",")
            pending_comma = True  # written only if something other than } or ] follows
            index += 1
        elif char.isspace():
            out.append(char)
            index += 1
        else:
            if pending_comma and char not in "}]":
                out.append(",")
            pending_comma = False
            out.append(char)
            index += 1
    if pending_comma:
        out.append(",")
    return "".join(out)


def _parse(text: str) -> tuple[Any, bool]:
    """(value, was JSONC); raises ValueError when it is neither JSON nor JSONC."""
    try:
        return json.loads(text), False
    except ValueError:
        return json.loads(_strip_jsonc(text)), True


def _backup_name(label: str) -> str:
    return f".shakerscan-{label.replace('/', '-')}-{uuid.uuid4().hex[:8]}.bak"


def read_config(root: Root, relative: str, notes: list[str]) -> dict:
    """The JSON object in ``relative`` ({} when there is none). JSONC (comments, trailing commas)
    is read, and its original is kept beside it because the comments cannot be written back; a
    file that is neither is moved aside with the reason, never silently overwritten."""
    raw = root.read(relative)
    if raw is None:
        return {}
    try:
        loaded, jsonc = _parse(raw.decode("utf-8"))
        reason = "" if isinstance(loaded, dict) else "it is JSON but not an object"
    except UnicodeDecodeError:
        loaded, jsonc, reason = None, False, "it is not UTF-8 text"
    except ValueError as exc:
        loaded, jsonc, reason = None, False, f"it is not valid JSON or JSONC ({exc})"
    parent = relative.rpartition("/")[0]
    if reason:
        name = _backup_name(f"unreadable-{relative}")
        root.rename(relative, name)
        notes.append(f"moved:     {relative}: {reason}, so it was moved to {name} and written afresh")
        return {}
    if jsonc:
        name = _backup_name(f"jsonc-{relative}")
        root.write(f"{parent}/{name}" if parent else name, raw, 0o600)
        notes.append(f"note:      {relative} has comments or trailing commas; it is written back as plain JSON "
                     f"without them, and the original is kept as {name}")
    return loaded


def write_config(root: Root, relative: str, config: Mapping) -> None:
    root.write(relative, (json.dumps(config, indent=2) + "\n").encode("utf-8"))


# --- the client's record of a workspace (outside it) -------------------------------------------


def state_path(state_directory: Path, workspace: Path) -> Path:
    """Where the client keeps what it knows about ``workspace``: under its own configuration
    directory, keyed by the workspace's real path. N1: kept inside the workspace, an agent could
    edit it to have the client delete any file it names, drop the person's hooks as "the kit's",
    or hide its own changes from the next launch's report."""
    key = hashlib.sha256(str(workspace.resolve()).encode("utf-8")).hexdigest()[:32]
    return state_directory / f"{key}.json"


def _valid_state(state: Any, workspace: Path) -> bool:
    if not isinstance(state, dict) or state.get("schema_version") != STATE_SCHEMA:
        return False
    if state.get("workspace") != str(workspace.resolve()):
        return False
    files = state.get("kit_files", {})
    hooks = state.get("kit_hooks", {})
    security = state.get("security", {})
    if not isinstance(files, dict) or not isinstance(hooks, dict) or not isinstance(security, dict):
        return False
    target = (workspace / ".claude").resolve()
    for relative, digest in files.items():
        try:
            _parts(relative)
        except WorkspaceError:
            return False
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            return False
        if not str((target / relative).resolve()).startswith(str(target) + os.sep):
            return False
    if not all(isinstance(groups, list) for groups in hooks.values()):
        return False
    return all(isinstance(item, list) and len(item) == 2 and all(isinstance(part, str) for part in item)
               for item in security.values())


def load_state(path: Path, workspace: Path, notes: list[str]) -> dict:
    """The record of the last launch in ``workspace``; anything unexpected in it (a path that is
    not inside ``.claude/``, a malformed entry) and the whole record is treated as absent."""
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        state = None
    if _valid_state(state, workspace):
        return state
    notes.append(f"note:      the client's record of this workspace ({path}) was not valid and was ignored")
    return {}


def save_state(path: Path, workspace: Path, state: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"schema_version": STATE_SCHEMA, "workspace": str(workspace.resolve()),
                                     **state}, indent=2) + "\n")
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


# --- merging -----------------------------------------------------------------------------------


def _hook_commands(hooks: Any, skip: Mapping[str, Sequence[Any]] | None = None) -> list[str]:
    """``Event: command`` for each hook command, leaving out the groups in ``skip``."""
    lines = []
    for event, groups in (hooks.items() if isinstance(hooks, Mapping) else ()):
        for group in groups if isinstance(groups, list) else ():
            if skip and group in (skip.get(event) or ()):
                continue
            for hook in (group.get("hooks") if isinstance(group, Mapping) else None) or ():
                if isinstance(hook, Mapping) and hook.get("command"):
                    lines.append(f"{event}: {str(hook['command'])[:_DISPLAY_CHARS]}")
    return lines


def merge_opencode_config(existing: Mapping, server: Mapping) -> tuple[dict, list[str]]:
    """OpenCode's ``opencode.json``: the client owns ``mcp.shakerscan``, the Hunt skill in
    ``instructions`` and a missing ``$schema``; everything else is kept. Returns (config, kept)."""
    config = dict(existing)
    kept = [str(key) for key in config if key not in {"$schema", "instructions", "mcp"}]
    config.setdefault("$schema", OPENCODE_SCHEMA)
    instructions = config.get("instructions")
    if isinstance(instructions, str):
        instructions = [instructions]
    if isinstance(instructions, list):
        if any(item != HUNT_SKILL_INSTRUCTION for item in instructions):
            kept.append("instructions")
        config["instructions"] = [*instructions] + (
            [] if HUNT_SKILL_INSTRUCTION in instructions else [HUNT_SKILL_INSTRUCTION])
    else:
        # OpenCode loads AGENTS.md on its own; the Hunt skill is loaded with it so the permission,
        # budget and view rules are in every session that drives a Hunt.
        config["instructions"] = [HUNT_SKILL_INSTRUCTION]
    servers = config.get("mcp") if isinstance(config.get("mcp"), Mapping) else {}
    others = [str(name) for name in servers if name != "shakerscan"]
    if others:
        kept.append("MCP servers " + ", ".join(others))
    config["mcp"] = {**servers, "shakerscan": dict(server)}
    return config, kept


def merge_mcp_json(existing: Mapping, server: Mapping) -> tuple[dict, list[str]]:
    """Claude Code's ``.mcp.json``: the client owns ``mcpServers.shakerscan`` only."""
    config = dict(existing)
    kept = [str(key) for key in config if key != "mcpServers"]
    servers = config.get("mcpServers") if isinstance(config.get("mcpServers"), Mapping) else {}
    others = [str(name) for name in servers if name != "shakerscan"]
    if others:
        kept.append("MCP servers " + ", ".join(others))
    config["mcpServers"] = {**servers, "shakerscan": dict(server)}
    return config, kept


def merge_claude_settings(existing: Mapping, kit: Mapping,
                          previous_kit_hooks: Mapping[str, Sequence[Any]] | None = None) -> tuple[dict, list[str]]:
    """Claude Code's ``.claude/settings.json``: the kit's hook entries replace the ones the kit
    wrote last time (``previous_kit_hooks``) and are added where missing; the person's
    permissions, their own hooks and every other key are kept."""
    config = dict(existing)
    kept = [str(key) for key in config if key != "hooks"]
    hooks = dict(config["hooks"]) if isinstance(config.get("hooks"), Mapping) else {}
    kit_hooks = kit.get("hooks") if isinstance(kit.get("hooks"), Mapping) else {}
    previous = previous_kit_hooks or {}
    for event in list(hooks):
        if isinstance(hooks[event], list):
            hooks[event] = [group for group in hooks[event] if group not in (previous.get(event) or ())]
    theirs = _hook_commands(hooks, kit_hooks)
    if theirs:
        kept.append("hooks (" + "; ".join(theirs) + ")")
    for event, groups in kit_hooks.items():
        current = list(hooks.get(event) or []) if isinstance(hooks.get(event), list) else []
        current += [group for group in groups if group not in current]
        hooks[event] = current
    config["hooks"] = {event: groups for event, groups in hooks.items() if groups != []}
    for key, value in kit.items():
        if key != "hooks":
            config.setdefault(key, value)
    return config, kept


def kept_note(label: str, kept: Sequence[str], managed: str) -> str | None:
    if not kept:
        return None
    return f"kept:      {label}: kept your {', '.join(kept)}; the client updates only {managed}"


# --- the kit's .claude directory ----------------------------------------------------------------


def _mode(source: Path, relative: str) -> int:
    mode = source.stat().st_mode & 0o777
    return mode | 0o111 if relative.startswith("hooks/") and relative.endswith(".sh") else mode


def install_tree(root: Root, source: Path, prefix: str) -> None:
    """Write every file of ``source`` under ``prefix`` as new files (no link followed)."""
    for path in sorted(source.rglob("*")):
        if path.is_file():
            relative = path.relative_to(source).as_posix()
            root.write(f"{prefix}/{relative}", path.read_bytes(), _mode(path, relative))


def refresh_claude_dir(source: Path, root: Root, notes: list[str], previous: Mapping) -> dict:
    """Write the kit's ``.claude`` into the workspace.

    The kit's files are refreshed; kit files a previous refresh wrote that the kit no longer ships
    are removed when unchanged (kept and named when the person changed them); files that were
    never the kit's stay. ``settings.json`` is merged. Returns what the kit wrote, for the state
    the client keeps outside the workspace."""
    target = root.path / ".claude"
    kit_files = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(source.rglob("*")) if path.is_file() and path != source / "settings.json"
    }
    written_before = previous.get("kit_files") if isinstance(previous.get("kit_files"), Mapping) else {}
    removed, modified = [], []
    for relative, digest in written_before.items():
        if relative in kit_files:
            continue
        content = root.read(f".claude/{relative}")
        if content is None:
            continue
        if hashlib.sha256(content).hexdigest() == digest:
            root.unlink(f".claude/{relative}")
            removed.append(relative)
        else:
            modified.append(relative)
    settings = target / "settings.json"
    theirs = sorted(
        path.relative_to(target).as_posix() for path in target.rglob("*")
        if path.is_file() and path != settings and path.relative_to(target).as_posix() not in kit_files
        and path.relative_to(target).as_posix() not in written_before
    ) if target.is_dir() else []
    existing = read_config(root, ".claude/settings.json", notes)
    for relative in kit_files:
        root.write(f".claude/{relative}", (source / relative).read_bytes(), _mode(source / relative, relative))
    kit = json.loads((source / "settings.json").read_text(encoding="utf-8")) if (source / "settings.json").is_file() else {}
    previous_hooks = previous.get("kit_hooks") if isinstance(previous.get("kit_hooks"), Mapping) else None
    merged, kept = merge_claude_settings(existing, kit, previous_hooks)
    if merged:
        write_config(root, ".claude/settings.json", merged)
    local = read_config(root, ".claude/settings.local.json", [])
    local_hooks = _hook_commands(local.get("hooks"))
    note = kept_note(".claude/settings.json", kept, "the kit's hooks")
    if note:
        notes.append(note)
    if removed:
        notes.append(f"removed:   .claude/: {len(removed)} file(s) the kit no longer ships ({', '.join(removed[:5])})")
    if modified:
        notes.append(f"kept:      .claude/: {', '.join(modified[:5])}: no longer part of the kit, kept because you changed it")
    if theirs:
        shown = ", ".join(theirs[:5]) + (f" and {len(theirs) - 5} more" if len(theirs) > 5 else "")
        notes.append(f"kept:      .claude/: {len(theirs)} file(s) of yours ({shown})")
    if local_hooks:
        notes.append("kept:      .claude/settings.local.json hooks (" + "; ".join(local_hooks) + ")")
    return {"kit_files": kit_files, "kit_hooks": kit.get("hooks") if isinstance(kit.get("hooks"), Mapping) else {}}


# --- the security fingerprint -------------------------------------------------------------------


def security_view(configs: Mapping[str, Mapping]) -> dict[str, Any]:
    """The parts of the agents' configuration that change what an agent may do."""
    opencode = configs.get("opencode.json") or {}
    instructions = opencode.get("instructions")
    instructions = [instructions] if isinstance(instructions, str) else instructions
    servers = opencode.get("mcp") if isinstance(opencode.get("mcp"), Mapping) else {}
    claude_servers = (configs.get(".mcp.json") or {}).get("mcpServers")
    claude_servers = claude_servers if isinstance(claude_servers, Mapping) else {}
    view: dict[str, Any] = {
        "opencode.json": {
            "permission": opencode.get("permission"), "plugin": opencode.get("plugin"),
            "provider": opencode.get("provider"),
            "mcp": {name: value for name, value in servers.items() if name != "shakerscan"},
            "instructions": [item for item in instructions or () if item != HUNT_SKILL_INSTRUCTION]
            if isinstance(instructions, list) else instructions,
        },
        ".mcp.json": {"mcpServers": {name: value for name, value in claude_servers.items() if name != "shakerscan"}},
    }
    for label in (".claude/settings.json", ".claude/settings.local.json"):
        settings = configs.get(label) or {}
        # Hooks by their command line (the value is the tool matcher), so a list shifting by one
        # entry does not read as every hook changing.
        hooks = {}
        for event, groups in (settings.get("hooks") or {}).items() if isinstance(settings.get("hooks"), Mapping) else ():
            for group in groups if isinstance(groups, list) else ():
                matcher = str(group.get("matcher") or "*") if isinstance(group, Mapping) else "*"
                for line in _hook_commands({event: [group]}):
                    hooks[line] = f"matcher {matcher}"
        view[label] = {"permissions": settings.get("permissions"), "hook": hooks}
    return view


def _flatten(value: Any, path: str, out: dict[str, Any]) -> None:
    if isinstance(value, Mapping) and value:
        for key, item in value.items():
            _flatten(item, f"{path}.{key}", out)
    elif isinstance(value, list) and value and path.split(".")[-1] != "command":
        for index, item in enumerate(value):
            _flatten(item, f"{path}[{index}]", out)
    elif value is not None and value != {} and value != []:
        out[path] = value


def fingerprint(view: Mapping[str, Any]) -> dict[str, list[str]]:
    """``path -> [sha256 of the value, the value as shown]``; secrets are never shown or stored."""
    flat: dict[str, Any] = {}
    for label, parts in view.items():
        _flatten(parts, label, flat)
    prints = {}
    for path, value in flat.items():
        encoded = json.dumps(value, sort_keys=True)
        shown = "(hidden)" if _SECRET_PATH.search(path) else encoded[:_DISPLAY_CHARS]
        prints[path] = [hashlib.sha256(encoded.encode("utf-8")).hexdigest(), shown]
    return prints


def changes(before: Mapping[str, Sequence[str]], now: Mapping[str, Sequence[str]]) -> list[str]:
    """What differs between two fingerprints, one line per setting."""
    lines = []
    for path in sorted(set(before) | set(now)):
        if path not in now:
            lines.append(f"removed {path}")
        elif path not in before:
            lines.append(f"added {path} = {now[path][1]}")
        elif before[path][0] != now[path][0]:
            lines.append(f"changed {path} = {now[path][1]}")
    return lines


CONFIGS = ("opencode.json", ".mcp.json", ".claude/settings.json", ".claude/settings.local.json")


def quiet_configs(root: Root) -> dict[str, dict]:
    """The configs as they are, for a fingerprint; nothing moved, nothing noted."""
    configs = {}
    for relative in CONFIGS:
        try:
            raw = root.read(relative)
            value, _ = _parse(raw.decode("utf-8")) if raw is not None else ({}, False)
        except (OSError, ValueError, WorkspaceError):
            value = {}
        configs[relative] = value if isinstance(value, dict) else {}
    return configs

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
in ``.shakerscan/workspace.json``; the kit's own stale files and hook entries are removed or
replaced on a refresh, and the person's files are left alone.

Codex keeps its MCP servers in its own configuration (``codex mcp add`` replaces only the
``shakerscan`` entry) and Pi is given flags, so neither has a workspace file here.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

HUNT_SKILL_INSTRUCTION = "skills/hunt/SKILL.md"
OPENCODE_SCHEMA = "https://opencode.ai/config.json"
STATE_FILE = Path(".shakerscan") / "workspace.json"
STATE_SCHEMA = "shakerscan-workspace/v1"
# Every path the client writes in a workspace; none of them may be a link, and nothing under the
# directories among them may be one either (``skills/`` is replaced whole, links included).
WRITTEN_PATHS = ("skills", ".claude", "AGENTS.md", ".mcp.json", "opencode.json", ".shakerscan")
SCANNED_DIRECTORIES = (".claude", ".shakerscan")
_SECRET_PATH = re.compile(r"(api[_-]?key|token|secret|passw|authorization|credential|cookie)", re.IGNORECASE)
_DISPLAY_CHARS = 200


class WorkspaceError(Exception):
    """A workspace the client will not write into; nothing was written."""


# --- links -------------------------------------------------------------------------------------


def refuse_links(workspace: Path) -> None:
    """Refuse (before any write) a workspace where a path the client writes is a link."""
    links: list[str] = []
    directories: list[str] = []
    for name in WRITTEN_PATHS:
        path = workspace / name
        if path.is_symlink():
            links.append(name)
        elif name in {".mcp.json", "opencode.json", "AGENTS.md"} and path.is_dir():
            directories.append(name)
        elif name in SCANNED_DIRECTORIES and path.is_dir():
            for root, folders, files in os.walk(path, followlinks=False):
                for entry in [*folders, *files]:
                    if (Path(root) / entry).is_symlink():
                        links.append((Path(root) / entry).relative_to(workspace).as_posix())
    if links:
        raise WorkspaceError(
            f"{workspace} has symbolic links where shakerscan writes the agent kit: {', '.join(sorted(links))}. "
            "Writing through them would change files outside the workspace (an agent can plant such a "
            "link). Remove them and run `shakerscan agent` again; nothing was written."
        )
    if directories:
        raise WorkspaceError(
            f"{workspace}: {', '.join(directories)} should be a file but is a directory. Move it away and "
            "run `shakerscan agent` again; nothing was written."
        )


# --- reading and writing JSON (and OpenCode's JSONC) -------------------------------------------


def _strip_jsonc(text: str) -> str:
    """``text`` without // and /* */ comments and trailing commas, strings left intact."""
    out: list[str] = []
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char == '"':
            end = index + 1
            while end < length and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            out.append(text[index:end + 1])
            index = end + 1
        elif text.startswith("//", index):
            newline = text.find("\n", index)
            index = length if newline < 0 else newline
        elif text.startswith("/*", index):
            close = text.find("*/", index + 2)
            index = length if close < 0 else close + 2
        else:
            out.append(char)
            index += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _parse(text: str) -> tuple[Any, bool]:
    """(value, was JSONC); raises ValueError when it is neither JSON nor JSONC."""
    try:
        return json.loads(text), False
    except ValueError:
        return json.loads(_strip_jsonc(text)), True


def _backup(path: Path, label: str, *, move: bool) -> Path:
    fd, name = tempfile.mkstemp(prefix=f".shakerscan-{label}-", suffix=".bak", dir=path.parent)
    os.close(fd)
    backup = Path(name)
    if move:
        path.replace(backup)
    else:
        shutil.copyfile(path, backup)
    return backup


def read_config(path: Path, label: str, notes: list[str]) -> dict:
    """The JSON object in ``path`` ({} when there is none). JSONC (comments, trailing commas) is
    read, and its original is kept beside it because the comments cannot be written back; a file
    that is neither is moved aside with the reason, never silently overwritten."""
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
        loaded, jsonc = _parse(text)
        reason = "" if isinstance(loaded, dict) else "it is JSON but not an object"
    except UnicodeDecodeError:
        loaded, jsonc, reason = None, False, "it is not UTF-8 text"
    except ValueError as exc:
        loaded, jsonc, reason = None, False, f"it is not valid JSON or JSONC ({exc})"
    if reason:
        backup = _backup(path, f"unreadable-{label.replace('/', '-')}", move=True)
        notes.append(f"moved:     {label}: {reason}, so it was moved to {backup.name} and written afresh")
        return {}
    if jsonc:
        backup = _backup(path, f"jsonc-{label.replace('/', '-')}", move=False)
        notes.append(f"note:      {label} has comments or trailing commas; it is written back as plain JSON "
                     f"without them, and the original is kept as {backup.name}")
    return loaded


def write_config(path: Path, config: Mapping) -> None:
    """Replace ``path`` atomically."""
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(config, indent=2) + "\n")
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def load_state(workspace: Path) -> dict:
    try:
        state = json.loads((workspace / STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) and state.get("schema_version") == STATE_SCHEMA else {}


def save_state(workspace: Path, state: Mapping) -> None:
    (workspace / STATE_FILE).parent.mkdir(exist_ok=True)
    write_config(workspace / STATE_FILE, {"schema_version": STATE_SCHEMA, **state})


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


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def refresh_claude_dir(source: Path, target: Path, notes: list[str], previous: Mapping) -> dict:
    """Copy the kit's ``.claude`` into the workspace (no link anywhere: refuse_links ran first).

    The kit's files are refreshed; kit files a previous refresh wrote that the kit no longer ships
    are removed when unchanged (kept and named when the person changed them); files that were
    never the kit's stay. ``settings.json`` is merged. Returns what the kit wrote, for the state."""
    kit_files = {
        path.relative_to(source).as_posix(): _digest(path)
        for path in sorted(source.rglob("*")) if path.is_file() and path != source / "settings.json"
    }
    written_before = previous.get("kit_files") if isinstance(previous.get("kit_files"), Mapping) else {}
    removed, modified = [], []
    for relative, digest in written_before.items():
        path = target / relative
        if relative in kit_files or not path.is_file():
            continue
        if _digest(path) == digest:
            path.unlink()
            removed.append(relative)
        else:
            modified.append(relative)
    settings = target / "settings.json"
    theirs = sorted(
        path.relative_to(target).as_posix() for path in target.rglob("*")
        if path.is_file() and path != settings and path.relative_to(target).as_posix() not in kit_files
        and path.relative_to(target).as_posix() not in written_before
    ) if target.is_dir() else []
    existing = read_config(settings, ".claude/settings.json", notes)
    for relative in kit_files:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, destination)
        shutil.copymode(source / relative, destination)
    kit = json.loads((source / "settings.json").read_text(encoding="utf-8")) if (source / "settings.json").is_file() else {}
    previous_hooks = previous.get("kit_hooks") if isinstance(previous.get("kit_hooks"), Mapping) else None
    merged, kept = merge_claude_settings(existing, kit, previous_hooks)
    if merged:
        write_config(settings, merged)
    local = read_config(target / "settings.local.json", ".claude/settings.local.json", []) \
        if (target / "settings.local.json").is_file() else {}
    local_hooks = _hook_commands(local.get("hooks"))
    for note in (kept_note(".claude/settings.json", kept, "the kit's hooks"),):
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


def read_configs(workspace: Path, notes: list[str], reader: Callable[..., dict] = read_config) -> dict[str, dict]:
    return {label: reader(workspace / label, label, notes)
            for label in ("opencode.json", ".mcp.json", ".claude/settings.json", ".claude/settings.local.json")}


def quiet_configs(workspace: Path) -> dict[str, dict]:
    """The configs as they are, for a fingerprint; nothing moved, nothing noted."""
    def reader(path: Path, label: str, notes: list[str]) -> dict:
        try:
            value, _ = _parse(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}
    return read_configs(workspace, [], reader)

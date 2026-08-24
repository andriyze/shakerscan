#!/usr/bin/env python3
"""Generate the exhaustive code-derived inventory in docs/functionality-reference.md."""

from __future__ import annotations

import argparse
import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "functionality-reference.md"
START = "<!-- BEGIN GENERATED CAPABILITY INVENTORY -->"
END = "<!-- END GENERATED CAPABILITY INVENTORY -->"


def literal(node: ast.AST | None, default: Any = None) -> Any:
    if node is None:
        return default
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return default


def keyword(call: ast.Call, name: str, default: Any = None) -> Any:
    for item in call.keywords:
        if item.arg == name:
            return literal(item.value, default)
    return default


def assigned_tuple(path: Path, variable: str, constructor: str) -> list[ast.Call]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == variable for target in targets):
            continue
        value = node.value
        if not isinstance(value, (ast.Tuple, ast.List)):
            return []
        return [
            item for item in value.elts
            if isinstance(item, ast.Call)
            and isinstance(item.func, ast.Name)
            and item.func.id == constructor
        ]
    return []


def esc(value: Any) -> str:
    text = str(value if value is not None else "")
    return " ".join(text.split()).replace("|", "\\|") or "-"


def code(value: Any) -> str:
    return f"`{esc(value).replace('`', '')}`"


def source_link(path: Path) -> str:
    return str(path.relative_to(ROOT))


@dataclass(frozen=True)
class ApiOperation:
    method: str
    path: str
    handler: str


def api_operations() -> list[ApiOperation]:
    path = ROOT / "api" / "api.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    rows: list[ApiOperation] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            owner = decorator.func.value
            method = decorator.func.attr.upper()
            if not isinstance(owner, ast.Name) or owner.id != "app" or method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            route = literal(decorator.args[0]) if decorator.args else None
            if isinstance(route, str):
                rows.append(ApiOperation(method, route, node.name))
    return sorted(rows, key=lambda row: (row.path, row.method, row.handler))


def arsenal_commands() -> list[dict[str, Any]]:
    path = ROOT / "api" / "command_arsenal.py"
    rows = []
    for call in assigned_tuple(path, "COMMANDS", "ArsenalCommand"):
        rows.append({
            "name": keyword(call, "name"),
            "family": keyword(call, "family"),
            "status": keyword(call, "status"),
            "risk": keyword(call, "risk_tier"),
            "method": keyword(call, "method"),
            "path": keyword(call, "path"),
            "description": keyword(call, "description"),
        })
    return sorted(rows, key=lambda row: row["name"] or "")


def check_families() -> list[dict[str, Any]]:
    path = ROOT / "api" / "check_registry.py"
    rows = []
    for call in assigned_tuple(path, "CHECK_REGISTRY", "CheckFamilySpec"):
        rows.append({
            "name": keyword(call, "name"),
            "phase": keyword(call, "phase"),
            "family": keyword(call, "family"),
            "active": bool(keyword(call, "is_active", False)),
            "risk": keyword(call, "risk_level", "low"),
            "runnable": bool(keyword(call, "runnable", False)),
            "adapter": keyword(call, "dispatch_adapter"),
            "telemetry": keyword(call, "telemetry_schema"),
            "description": keyword(call, "description"),
        })
    return sorted(rows, key=lambda row: row["name"] or "")


def tool_adapters() -> list[dict[str, Any]]:
    path = ROOT / "api" / "command_arsenal.py"
    rows = []
    for call in assigned_tuple(path, "TOOL_ADAPTERS", "ToolAdapterSpec"):
        values = [literal(arg) for arg in call.args]
        rows.append({
            "name": values[0] if len(values) > 0 else None,
            "family": values[1] if len(values) > 1 else None,
            "description": values[2] if len(values) > 2 else None,
            "risk": values[3] if len(values) > 3 else None,
            "status": values[4] if len(values) > 4 else None,
            "parser": values[8] if len(values) > 8 else None,
            "proof": values[9] if len(values) > 9 else None,
        })
    return sorted(rows, key=lambda row: row["name"] or "")


def local_agents() -> list[dict[str, Any]]:
    path = ROOT / "api" / "command_arsenal.py"
    rows = []
    for call in assigned_tuple(path, "LOCAL_AGENT_SPECS", "LocalAgentSpec"):
        rows.append({
            "agent": keyword(call, "agent"),
            "display": keyword(call, "display_name"),
            "headless": bool(keyword(call, "supports_headless_prompt", False)),
            "timeout": bool(keyword(call, "supports_timeout", False)),
            "isolation": bool(keyword(call, "supports_workdir_isolation", False)),
            "max_prompt": keyword(call, "max_prompt_bytes"),
            "max_output": keyword(call, "max_output_bytes"),
        })
    return sorted(rows, key=lambda row: row["agent"] or "")


def cli_flags() -> list[dict[str, Any]]:
    path = ROOT / "scanner" / "scanner.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != "add_argument":
            continue
        flags = [literal(arg) for arg in node.args]
        flags = [flag for flag in flags if isinstance(flag, str) and flag.startswith("--")]
        if not flags:
            continue
        help_text = keyword(node, "help", "")
        if help_text is None:
            help_text = "internal/hidden execution flag"
        choices = keyword(node, "choices", ())
        for flag in flags:
            if flag in seen:
                continue
            seen.add(flag)
            rows.append({"flag": flag, "help": help_text, "choices": choices})
    return sorted(rows, key=lambda row: row["flag"])


DEPRECATED_WRAPPER_COMMANDS = frozenset({"scan-full", "scan-smart"})


def _all_scanner_wrapper_commands() -> list[str]:
    path = ROOT / "scanner.sh"
    text = path.read_text(encoding="utf-8")
    markers = ('case "$COMMAND" in', "case $COMMAND in")
    positions = [text.rfind(marker) for marker in markers]
    start = max(positions)
    if start < 0:
        return []
    dispatch = text[start:]
    commands: set[str] = set()
    for match in re.finditer(r"^\s{4}([^\r\n()]+)\)\s*$", dispatch, re.M):
        commands.update(
            command for command in match.group(1).split("|")
            if re.fullmatch(r"[a-z][a-z0-9_-]*", command)
        )
    return sorted(commands)


def scanner_wrapper_commands() -> list[str]:
    """Return only the canonical wrapper command surface."""
    return [
        command for command in _all_scanner_wrapper_commands()
        if command not in DEPRECATED_WRAPPER_COMMANDS
    ]


def scanner_wrapper_compatibility_commands() -> list[str]:
    """Return aliases retained solely for the documented migration window."""
    return [
        command for command in _all_scanner_wrapper_commands()
        if command in DEPRECATED_WRAPPER_COMMANDS
    ]


def make_targets() -> list[str]:
    path = ROOT / "Makefile"
    return sorted(set(re.findall(r"^([A-Za-z0-9][A-Za-z0-9_.-]*):", path.read_text(encoding="utf-8"), re.M)))


def release_gates() -> list[str]:
    path = ROOT / "scripts" / "release_gates.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name) or node.target.id != "GATES":
            continue
        if isinstance(node.value, ast.Dict):
            return sorted(value for key in node.value.keys if isinstance((value := literal(key)), str))
    return []


def environment_variables() -> list[dict[str, str]]:
    """Inventory explicit process-environment reads without exposing values."""
    references: dict[str, set[str]] = {}
    call_pattern = re.compile(r"os\.(?:getenv|environ\.get)\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]")
    index_pattern = re.compile(r"os\.environ\[\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*\]")
    for base in (ROOT / "api", ROOT / "scanner", ROOT / "scripts", ROOT / "scheduler"):
        for path in sorted(base.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for name in set(call_pattern.findall(text) + index_pattern.findall(text)):
                references.setdefault(name, set()).add(source_link(path))

    # Compose substitutions are also public deployment configuration even when no Python file reads them.
    for path in sorted(ROOT.glob("docker-compose*.yml")):
        for name in set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", path.read_text(encoding="utf-8"))):
            references.setdefault(name, set()).add(source_link(path))
    return [
        {"name": name, "sources": ", ".join(code(path) for path in sorted(references[name]))}
        for name in sorted(references)
    ]


def ui_pages() -> list[dict[str, str]]:
    rows = []
    base = ROOT / "ui" / "src" / "app"
    for path in sorted(base.rglob("page.tsx")):
        rel = path.relative_to(base)
        parts = list(rel.parts[:-1])
        route = "/" + "/".join(parts)
        if route != "/":
            route = re.sub(r"\[([^]]+)\]", r"{\1}", route)
        rows.append({"route": route, "source": source_link(path)})
    return rows


def frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}
    block = text.split("---", 2)[1]
    values = {}
    for line in block.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def skills() -> list[dict[str, str]]:
    rows = []
    for path in sorted((ROOT / "skills").glob("*/SKILL.md")):
        meta = frontmatter(path)
        rows.append({"name": meta.get("name", path.parent.name), "description": meta.get("description", ""), "source": source_link(path)})
    return rows


def markdown_surfaces(folder: Path, kind: str) -> list[dict[str, str]]:
    rows = []
    for path in sorted(folder.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        meta = frontmatter(path)
        heading = next((line[2:].strip() for line in text.splitlines() if line.startswith("# ")), path.stem)
        description = meta.get("description", "")
        if not description:
            description = next((line.strip() for line in text.splitlines() if line.strip() and not line.startswith(("#", "---"))), "")
        rows.append({"name": meta.get("name", path.stem), "title": heading, "description": description, "source": source_link(path), "kind": kind, "model": meta.get("model", "")})
    return rows


def scanner_modules() -> list[str]:
    base = ROOT / "scanner" / "scanner_tools"
    return sorted(path.name for path in base.glob("*.py") if path.name != "__init__.py")


def durable_tables() -> list[dict[str, str]]:
    rows: dict[str, str] = {}
    pattern = re.compile(r"CREATE TABLE(?: IF NOT EXISTS)?\s+([a-zA-Z0-9_]+)", re.I)
    for path in (ROOT / "db" / "init.sql", ROOT / "api" / "retest_contract.py"):
        for name in pattern.findall(path.read_text(encoding="utf-8")):
            rows.setdefault(name, source_link(path))
    return [{"name": name, "source": rows[name]} for name in sorted(rows)]


def table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(esc(value) for value in row) + " |" for row in rows)
    return lines


def render() -> str:
    api = api_operations()
    commands = arsenal_commands()
    families = check_families()
    adapters = tool_adapters()
    agents = local_agents()
    flags = cli_flags()
    wrapper_commands = scanner_wrapper_commands()
    compatibility_wrapper_commands = scanner_wrapper_compatibility_commands()
    make = make_targets()
    gates = release_gates()
    env = environment_variables()
    pages = ui_pages()
    skill_rows = skills()
    slash = markdown_surfaces(ROOT / ".claude" / "commands", "command")
    deprecated_slash_names = {"scan-full", "scan-smart"}
    canonical_slash = [row for row in slash if row["name"] not in deprecated_slash_names]
    compatibility_slash = [row for row in slash if row["name"] in deprecated_slash_names]
    subagents = markdown_surfaces(ROOT / ".claude" / "agents", "agent")
    modules = scanner_modules()
    tables = durable_tables()

    lines = [
        START,
        "",
        "> **Generated source inventory.** Run `python3 scripts/generate_capability_inventory.py` after",
        "> changing any inventoried surface. CI uses `--check`; do not edit this block manually.",
        "",
        "### Inventory Summary",
        "",
        *table(["Surface", "Count", "Source"], [
            ["Public REST operations", len(api), "`api/api.py` FastAPI decorators"],
            ["Unique REST paths", len({row.path for row in api}), "`api/api.py`"],
            ["Check families", len(families), "`api/check_registry.py`"],
            ["Command Arsenal commands", len(commands), "`api/command_arsenal.py`"],
            ["Tool adapters", len(adapters), "`api/command_arsenal.py`"],
            ["Local-agent adapters", len(agents), "`api/command_arsenal.py`"],
            ["Internal compatibility scanner flags", len(flags), "`scanner/scanner.py`"],
            ["Canonical scanner wrapper commands", len(wrapper_commands), "`scanner.sh`"],
            ["Deprecated wrapper aliases", len(compatibility_wrapper_commands), "`scanner.sh`"],
            ["Make targets", len(make), "`Makefile`"],
            ["Release gates", len(gates), "`scripts/release_gates.py`"],
            ["Runtime environment keys", len(env), "Python sources + Compose manifests"],
            ["Internal compatibility scanner modules", len(modules), "`scanner/scanner_tools/`"],
            ["UI pages", len(pages), "`ui/src/app/`"],
            ["Skills", len(skill_rows), "`skills/`"],
            ["Canonical slash commands", len(canonical_slash), "`.claude/commands/`"],
            ["Deprecated Scan-name slash shims", len(compatibility_slash), "`.claude/commands/`"],
            ["Specialized subagents", len(subagents), "`.claude/agents/`"],
            ["Durable tables", len(tables), "`db/init.sql` + migrations"],
        ]),
        "",
        "### Public REST Operations",
        "",
        *table(["Method", "Path", "Handler"], [[code(row.method), code(row.path), code(row.handler)] for row in api]),
        "",
        "### Check-Family Registry",
        "",
        *table(["Name", "Phase", "Family", "Active", "Risk", "Runnable", "Adapter", "Telemetry", "Description"], [
            [code(row["name"]), row["phase"], row["family"], row["active"], row["risk"], row["runnable"], code(row["adapter"] or "none"), code(row["telemetry"] or "none"), row["description"]]
            for row in families
        ]),
        "",
        "### Command Arsenal",
        "",
        *table(["Command", "Family", "Status", "Risk", "HTTP", "Path", "Description"], [
            [code(row["name"]), row["family"], row["status"], row["risk"], row["method"], code(row["path"]), row["description"]]
            for row in commands
        ]),
        "",
        "### Tool And Local-Agent Adapters",
        "",
        *table(["Tool", "Family", "Status", "Risk", "Parser", "Proof contract", "Description"], [
            [code(row["name"]), row["family"], row["status"], row["risk"], code(row["parser"] or "none"), code(row["proof"] or "none"), row["description"]]
            for row in adapters
        ]),
        "",
        *table(["Agent", "Display", "Headless prompt", "Timeout", "Workdir isolation", "Max prompt bytes", "Max output bytes"], [
            [code(row["agent"]), row["display"], row["headless"], row["timeout"], row["isolation"], row["max_prompt"], row["max_output"]]
            for row in agents
        ]),
        "",
        "### Internal Compatibility Scanner Flags",
        "",
        "These parser flags inventory the private compatibility scanner surface. They are not the",
        "public Scan contract, must not receive secrets directly from V2 clients, and cannot grant",
        "execution authority. Public clients use `GET /scan/contracts` plus `/scans` policy, budget,",
        "opaque profile, and collection-reference fields.",
        "",
        *table(["Flag", "Choices", "Purpose"], [
            [code(row["flag"]), ", ".join(map(str, row["choices"] or ())) or "-", row["help"]]
            for row in flags
        ]),
        "",
        "### Wrapper Commands, Make Targets, And Release Gates",
        "",
        *table(["Surface", "Names"], [
            ["Canonical `scanner.sh` commands", ", ".join(code(name) for name in wrapper_commands)],
            ["Deprecated compatibility aliases (sunset 2026-12-31)", ", ".join(code(name) for name in compatibility_wrapper_commands)],
            ["Make targets", ", ".join(code(name) for name in make)],
            ["Release gates", ", ".join(code(name) for name in gates)],
        ]),
        "",
        "### Runtime Environment-Key Inventory",
        "",
        "Only key names and declaring sources are documented; secret values are never read or emitted.",
        "",
        *table(["Environment key", "Referenced by"], [[code(row["name"]), row["sources"]] for row in env]),
        "",
        "### UI Pages",
        "",
        *table(["Route", "Source"], [[code(row["route"]), code(row["source"])] for row in pages]),
        "",
        "### Skills, Slash Commands, And Subagents",
        "",
        *table(["Skill", "Purpose", "Source"], [[code(row["name"]), row["description"], code(row["source"])] for row in skill_rows]),
        "",
        *table(["Canonical slash command", "Title", "Purpose", "Source"], [[code('/' + row["name"]), row["title"], row["description"], code(row["source"])] for row in canonical_slash]),
        "",
        "Deprecated Scan-name shims (sunset 2026-12-31):",
        "",
        *table(["Compatibility slash command", "Title", "Purpose", "Source"], [[code('/' + row["name"]), row["title"], row["description"], code(row["source"])] for row in compatibility_slash]),
        "",
        *table(["Subagent", "Model", "Purpose", "Source"], [[code(row["name"]), row["model"] or "unspecified", row["description"], code(row["source"])] for row in subagents]),
        "",
        "### Internal Compatibility Scanner Module Inventory",
        "",
        "Implementation modules below are inventory only. The immutable action graph and canonical",
        "capability registry define execution authority; module presence does not advertise a public",
        "Scan feature or a second orchestration engine.",
        "",
        ", ".join(code(name) for name in modules),
        "",
        "### Durable Storage Inventory",
        "",
        *table(["Table", "Declared by"], [[code(row["name"]), code(row["source"])] for row in tables]),
        "",
        END,
    ]
    return "\n".join(lines)


def update_document(*, check: bool) -> int:
    text = DOC.read_text(encoding="utf-8")
    if START not in text or END not in text:
        raise SystemExit(f"{DOC} is missing generated inventory markers")
    generated = render()
    updated = text[:text.index(START)] + generated + text[text.index(END) + len(END):]
    if check:
        if updated != text:
            print(f"stale generated capability inventory: {DOC.relative_to(ROOT)}")
            return 1
        return 0
    DOC.write_text(updated, encoding="utf-8")
    print(f"updated {DOC.relative_to(ROOT)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail when the generated inventory is stale")
    args = parser.parse_args()
    return update_document(check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())

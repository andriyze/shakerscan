"""Vendor the runtime's MCP adapter and product CLI into the client at build time.

The release runtime ships ``scripts/shakerscan_mcp.py`` (``scanner.sh mcp``) and
``scripts/v2_cli.py`` (``scanner.sh hunt``) as standalone files. The client is that same code
installed without the engine. Rather than committing copies that drift, the build maps them from
the repository checkout into the package:

- wheel: ``../scripts/shakerscan_mcp.py`` -> ``shakerscan/_mcp.py`` (and ``v2_cli.py`` -> ``_v2_cli.py``)
- sdist: the same files under ``src/shakerscan/`` so a wheel built from the sdist carries them

A wheel built from an unpacked sdist has no repository beside it; the copies are already in
``src/`` and nothing is mapped. A build that can find neither fails rather than ship a client
without its adapter.
"""

from __future__ import annotations

from pathlib import Path

try:
    from hatchling.builders.hooks.plugin.interface import BuildHookInterface
except ImportError:  # the pure helpers are importable (and tested) without a build backend
    BuildHookInterface = object  # type: ignore[assignment,misc]

VENDORED = {
    "shakerscan_mcp.py": "_mcp.py",
    "v2_cli.py": "_v2_cli.py",
    "api_cli.py": "_api_cli.py",
    "scan_cli.py": "_scan_cli.py",
}
# The agent kit the launcher runs agents inside (`shakerscan agent …`): materialized into a
# workspace by the client's `agent` command against the connected instance. `.claude` is
# carried as `claude` so no hidden directory has to survive packaging.
KIT = {"skills": "_kit/skills", ".claude": "_kit/claude", "AGENTS.md": "_kit/AGENTS.md", "CLAUDE.md": "_kit/CLAUDE.md"}
REPOSITORY_MARKERS = ("VERSION", "scanner.sh")


def repository_scripts(root: Path) -> Path | None:
    """The repository's ``scripts/`` directory when ``root`` is ``<repo>/client``, else None."""
    repo = Path(root).resolve().parent
    if all((repo / marker).is_file() for marker in REPOSITORY_MARKERS) and (repo / "scripts").is_dir():
        return repo / "scripts"
    return None


def plan_force_include(target_name: str, root: Path) -> dict[str, str]:
    """Source path -> distribution path for the vendored runtime modules of one build target."""
    root = Path(root)
    prefix = "src/shakerscan/" if target_name == "sdist" else "shakerscan/"
    scripts = repository_scripts(root)
    if scripts is not None:
        repo = scripts.parent
        missing = [name for name in VENDORED if not (scripts / name).is_file()]
        missing += [name for name in KIT if not (repo / name).exists()]
        if missing:
            raise RuntimeError(f"vendored runtime sources are missing from the repository: {missing}")
        mapping = {str(scripts / name): prefix + module for name, module in VENDORED.items()}
        mapping.update({str(repo / name): prefix + target for name, target in KIT.items()})
        return mapping
    package = root / "src" / "shakerscan"
    copies = [module for module in VENDORED.values() if (package / module).is_file()]
    copies += [target for target in KIT.values() if (package / target).exists()]
    if len(copies) == len(VENDORED) + len(KIT):
        return {}
    raise RuntimeError(
        "vendored runtime sources not found: build from the repository checkout (../scripts, "
        "../skills, ../.claude) or from an sdist that carries them under src/shakerscan/"
    )


class CustomBuildHook(BuildHookInterface):  # type: ignore[misc]
    def initialize(self, version: str, build_data: dict) -> None:  # noqa: ARG002
        mapping = plan_force_include(self.target_name, Path(self.root))
        build_data.setdefault("force_include", {}).update(mapping)

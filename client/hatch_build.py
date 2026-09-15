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

VENDORED = {"shakerscan_mcp.py": "_mcp.py", "v2_cli.py": "_v2_cli.py"}
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
        missing = [name for name in VENDORED if not (scripts / name).is_file()]
        if missing:
            raise RuntimeError(f"vendored runtime sources are missing from the repository: {missing}")
        return {str(scripts / name): prefix + module for name, module in VENDORED.items()}
    copies = [module for module in VENDORED.values() if (root / "src" / "shakerscan" / module).is_file()]
    if len(copies) == len(VENDORED):
        return {}
    raise RuntimeError(
        "vendored runtime sources not found: build from the repository checkout (../scripts) or "
        "from an sdist that carries src/shakerscan/_mcp.py and src/shakerscan/_v2_cli.py"
    )


class CustomBuildHook(BuildHookInterface):  # type: ignore[misc]
    def initialize(self, version: str, build_data: dict) -> None:  # noqa: ARG002
        mapping = plan_force_include(self.target_name, Path(self.root))
        build_data.setdefault("force_include", {}).update(mapping)

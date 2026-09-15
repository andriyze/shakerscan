"""Load the runtime modules the client vendors: the MCP adapter and the product CLI.

An installed client carries ``shakerscan._mcp`` and ``shakerscan._v2_cli``, copied from
``scripts/shakerscan_mcp.py`` and ``scripts/v2_cli.py`` when the package was built. In a
repository checkout those copies do not exist and the runtime scripts are loaded in place, so
the client and ``scanner.sh`` always run the same code.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

RUNTIME_SCRIPTS = {"_mcp": "shakerscan_mcp.py", "_v2_cli": "v2_cli.py"}


def repository_scripts() -> Path | None:
    """``<repo>/scripts`` when this file lives in a checkout (``client/src/shakerscan``)."""
    candidate = Path(__file__).resolve().parents[3] / "scripts"
    return candidate if candidate.is_dir() else None


def load(name: str) -> ModuleType:
    """Return the vendored runtime module ``name`` (``_mcp`` or ``_v2_cli``)."""
    if name not in RUNTIME_SCRIPTS:
        raise ValueError(f"unknown runtime module {name!r}")
    qualified = f"shakerscan.{name}"
    if qualified in sys.modules:
        return sys.modules[qualified]
    try:
        return importlib.import_module(qualified)
    except ModuleNotFoundError as exc:
        if exc.name != qualified:
            raise
    scripts = repository_scripts()
    if scripts is None:
        raise RuntimeError(
            f"{qualified} is not part of this installation and no repository checkout is beside it; "
            "reinstall the shakerscan client"
        )
    path = scripts / RUNTIME_SCRIPTS[name]
    spec = importlib.util.spec_from_file_location(qualified, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualified] = module
    spec.loader.exec_module(module)
    return module

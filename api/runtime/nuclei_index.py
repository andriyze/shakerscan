"""Warm nuclei's template metadata index before a worker takes scan work.

nuclei v3 parses every template in the installed bundle on its first run and writes
``index.gob`` to its cache directory, even when the run selects a handful of templates
with ``-id``. On the pinned ~13k-template bundle that costs seconds to tens of seconds,
and paid inside a scan action's wall it times the action out. The scanner image bakes the
index at build time; this guard rebuilds it at worker start when it is missing (a tmpfs
``/tmp``, an overridden ``HOME`` or ``XDG_CACHE_HOME``), so no scan pays the cold start.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path

_PROXY_VARIABLES = frozenset({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"})
# ``-duc`` keeps the build offline; ``-tl`` loads (and indexes) every template and exits
# without contacting any target.
INDEX_BUILD_ARGV = ("-duc", "-silent", "-no-color", "-tl")


def nuclei_index_path(env: Mapping[str, str] | None = None) -> Path:
    """Resolve the index path the way nuclei resolves its cache directory."""
    environment = os.environ if env is None else env
    cache_root = str(environment.get("XDG_CACHE_HOME") or "").strip()
    if not cache_root:
        home = str(environment.get("HOME") or "").strip() or str(Path.home())
        cache_root = os.path.join(home, ".cache")
    return Path(cache_root) / "nuclei" / "index.gob"


def _index_present(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def ensure_nuclei_template_index(
    *,
    binary: str | None = None,
    timeout: float = 120,
) -> Path | None:
    """Build the nuclei template index when it is missing; return its path.

    Returns ``None`` when this worker has no nuclei binary. Raises ``RuntimeError`` when
    the build fails or leaves no index, so a worker never starts with a cold index.
    """
    executable = binary or shutil.which("nuclei")
    if not executable:
        return None
    index = nuclei_index_path()
    if _index_present(index):
        return index
    environment = {
        key: value for key, value in os.environ.items()
        if key.upper() not in _PROXY_VARIABLES
    }
    started = time.monotonic()
    try:
        result = subprocess.run(
            [executable, *INDEX_BUILD_ARGV],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"nuclei template index build failed: {type(exc).__name__}") from exc
    elapsed = time.monotonic() - started
    if result.returncode != 0 or not _index_present(index):
        detail = (result.stderr or "").strip()[-500:]
        raise RuntimeError(
            f"nuclei template index was not written to {index} "
            f"(exit {result.returncode}){': ' + detail if detail else ''}"
        )
    print(f"[preflight] built nuclei template index at {index} in {elapsed:.1f}s", flush=True)
    return index

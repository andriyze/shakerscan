"""pytest plugin: run only one shard's test files out of a complete collection.

run_complete_python_suite.py --shard K/N loads this with ``-p scripts.pytest_shard_select``.
The shard still collects its whole import-layout group, in the same order as the unsharded run,
so module-level side effects (for example ``sys.modules.setdefault`` stubs that only apply when
the real package has not been imported yet) resolve exactly as they do in the complete run. Only
the items from files outside the shard's slice are deselected before anything executes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

SELECT_ENV = "SHAKERSCAN_PYTEST_SHARD_FILES"


def pytest_collection_modifyitems(config, items):
    selection = os.environ.get(SELECT_ENV)
    if not selection:
        return
    root = Path(str(config.rootpath)).resolve()
    keep = set(json.loads(Path(selection).read_text(encoding="utf-8")))
    selected, deselected = [], []
    for item in items:
        relative = Path(str(item.path)).resolve().relative_to(root).as_posix()
        (selected if relative in keep else deselected).append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected

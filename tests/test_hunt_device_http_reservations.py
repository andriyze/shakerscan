from __future__ import annotations

from pathlib import Path
from tests.api_sources import definition_source


ROOT = Path(__file__).resolve().parents[1]


def _handler_source() -> str:
    adapter = (
        definition_source("execute_hunt_capability")
        + definition_source("_execute_hunt_capability_lifecycle")
    )

    assert '"path": _redact_hunt_path_query(args["path"])' in adapter
    assert '"body_preview": _redact_device_http_body_preview(' in adapter

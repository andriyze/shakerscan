"""Soak N11: `advanced.max_workers: true` was coerced to 1 and admitted (scan b2a63faa)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scanner"))

from request_models import ScanAdvancedLimits, ScanRequest  # noqa: E402

CEILINGS = (
    "max_duration_seconds", "max_http_requests", "max_state_changing_requests", "max_endpoints",
    "max_hosts", "max_browser_actions", "max_tcp_ports", "max_tool_wall_seconds", "max_workers",
)


@pytest.mark.parametrize("name", CEILINGS)
@pytest.mark.parametrize("value", [True, False])
def test_a_boolean_ceiling_is_refused(name, value):
    with pytest.raises(ValidationError, match="whole number"):
        ScanAdvancedLimits(**{name: value})


def test_whole_number_ceilings_still_parse():
    limits = ScanAdvancedLimits(max_workers=2, max_state_changing_requests=0)
    assert (limits.max_workers, limits.max_state_changing_requests) == (2, 0)


def test_the_public_request_refuses_it():
    with pytest.raises(ValidationError):
        ScanRequest(target="https://example.test", advanced={"max_workers": True})

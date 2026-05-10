import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.discovery import calculate_adaptive_depth  # noqa: E402


def test_smart_discovery_uses_conservative_depth_without_signals():
    depth, paths_per_level = calculate_adaptive_depth({}, base_depth=3)

    assert depth == 2
    assert paths_per_level == 8


def test_smart_discovery_expands_when_sql_signals_exist():
    depth, paths_per_level = calculate_adaptive_depth({"sql_errors": True}, base_depth=3)

    assert depth > 2
    assert paths_per_level > 8

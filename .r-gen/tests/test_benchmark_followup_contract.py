"""A benchmark miss must reruns the family that actually owns it.

The follow-up mapping drives a focused rerun, so a stale entry sends the wrong
verifier at the miss. It shipped mapping ``nosqli`` to ``sqli`` -- true only
before NoSQLi became a family of its own -- and ``broken_access_control`` to
``auth``, which the canonical contract does not implement at all.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from api.scan.contracts import SCAN_V2_FAMILY_NAMES


_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "benchmark_targets.py"


def _module():
    spec = importlib.util.spec_from_file_location("benchmark_targets", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_every_followup_family_is_a_canonical_scan_family():
    mapping = _module().FOCUSED_FAMILY_FOR_BENCHMARK_MISS
    unknown = sorted(set(mapping.values()) - set(SCAN_V2_FAMILY_NAMES))
    assert not unknown, f"follow-up targets families the contract cannot run: {unknown}"


@pytest.mark.parametrize("family,expected", (
    ("sqli", "sqli"),
    ("nosqli", "nosqli"),
    ("xss", "xss"),
    ("bola", "bola"),
    ("sensitive_exposure", "sensitive_exposure"),
    # Function-level access control is authz_surface; object-level is bola.
    ("broken_access_control", "authz_surface"),
))
def test_a_miss_reruns_the_family_that_owns_it(family, expected):
    assert _module().FOCUSED_FAMILY_FOR_BENCHMARK_MISS[family] == expected


def test_a_family_with_no_focused_executor_stays_a_detector_gap():
    """An unmapped family must not imply a campaign that cannot run.

    Emitting a focused rerun for a family the contract does not implement would
    claim runnable work where none exists, so those misses are recorded as
    detector gaps instead.
    """
    module = _module()
    fixture = {"name": "honey", "target_url": "http://honey.test"}

    unmapped = module._benchmark_miss_followup(
        {"id": "webhook-bypass", "family": "webhook", "proof": "deterministic",
         "route": "/webhooks/x"},
        fixture, {"status": "ok"},
    )
    assert unmapped["status"] == "detector_gap"
    assert unmapped["next_test_action"] is None

    mapped = module._benchmark_miss_followup(
        {"id": "nosqli-reviews", "family": "nosqli", "proof": "deterministic",
         "route": "/rest/products/reviews"},
        fixture, {"status": "ok"},
    )
    assert mapped["status"] == "ready"
    action = mapped["next_test_action"]
    assert action["command"] == "scan.focused_family"
    # The rerun must target the family that owns the miss, not a neighbouring one.
    assert action["parameters"]["check_family"] == "nosqli"

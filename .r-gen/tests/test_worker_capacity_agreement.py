"""Worker capacity must be continuous, and never smaller than the fleet already running.

Reported from a clean 2.3.6 install: the dashboard read "9 running - max 5". The launcher and
the API compute capacity with the same shaped formula but from different memory readings -- the
launcher reads the host (16 GB), the API reads Docker's MemTotal (15.6 GB after the kernel's
reserve). A flat five-worker band between 8 and 16 GB then put them on opposite sides of a
cliff: below it the answer was a fixed 5, above it (16 - 7) = 9. A 0.4 GB difference in
measurement moved the cap by four workers, and the UI reported a fleet larger than its own
maximum.

The step is gone: above the small-machine floor, capacity grows with memory, so a measurement
difference can only move the answer by about as much as the difference itself. No host size
gets fewer workers than the flat band gave it.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from api import deployment_policy as policy

ROOT = Path(__file__).resolve().parents[1]


def _launcher_workers(memory_gb: int) -> int:
    """What scanner.sh would start for this host size."""
    script = (
        f'source <(sed -n "/^auto_workers_for_memory_gb()/,/^}}$/p" {ROOT}/scanner.sh); '
        f"auto_workers_for_memory_gb {memory_gb}"
    )
    # Pin the platform ceiling so the comparison is about the curve, not about the launcher's
    # deliberate smaller auto-cap on a developer Mac.
    out = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, cwd=ROOT,
        env={**os.environ, "SHAKERSCAN_AUTO_WORKER_MAX": "20"},
    )
    return int(out.stdout.strip())


@pytest.mark.parametrize("mem_gb, at_least", [
    (8, 5), (12, 5), (15.6, 8), (16, 9), (24, 17), (32, 25), (64, 57),
])
def test_capacity_grows_with_memory(mem_gb, at_least):
    assert policy.max_allowed_workers_for_memory_gb(mem_gb) >= at_least


def test_a_small_measurement_difference_cannot_move_the_cap_by_four():
    """The reported case: the launcher's 16 and the API's 15.6 must not disagree by four."""
    low = policy.max_allowed_workers_for_memory_gb(15.6)
    high = policy.max_allowed_workers_for_memory_gb(16.0)
    assert abs(high - low) <= 1, (low, high)


def test_no_host_size_loses_capacity_against_the_old_flat_band():
    """The old curve: <8 -> mem-3 (max 4), 8..16 -> 5, else (mem - 7). Never return less."""
    def previous(mem: float) -> int:
        if mem < 8:
            return max(1, min(4, int(mem) - 3))
        if mem < 16:
            return 5
        return max(5, min(200, int(mem - 7)))
    for mem in (1, 2, 4, 6, 7.5, 8, 9.5, 12, 15.6, 16, 20, 32, 64, 128, 512):
        assert policy.max_allowed_workers_for_memory_gb(mem) >= previous(mem), mem


def test_tiny_hosts_still_get_a_workable_floor():
    for mem_gb in (1, 2, 4, 7):
        assert policy.max_allowed_workers_for_memory_gb(mem_gb) >= 1


def test_unknown_memory_keeps_the_conservative_default():
    assert policy.max_allowed_workers_for_memory_gb(0) == 5
    assert policy.max_allowed_workers_for_memory_gb(16, per_worker_gb=0) == 5


def test_the_reported_cap_is_never_below_the_running_fleet():
    """Whatever the formula says, the UI must not claim a maximum smaller than the fleet that is
    actually running: that is what made "9 running - max 5" possible."""
    assert policy.reported_max_allowed_workers(5, running_count=9) == 9
    assert policy.reported_max_allowed_workers(9, running_count=4) == 9
    assert policy.reported_max_allowed_workers(5, running_count=0) == 5
    assert policy.reported_max_allowed_workers(5, running_count="nonsense") == 5


@pytest.mark.parametrize("mem_gb", [8, 12, 15, 16, 24, 32])
def test_the_launcher_and_the_api_agree_on_the_same_host(mem_gb):
    """One curve, two implementations: they must not disagree about the same machine."""
    launcher = _launcher_workers(mem_gb)
    api_side = policy.max_allowed_workers_for_memory_gb(float(mem_gb))
    assert launcher == min(api_side, 20), (mem_gb, launcher, api_side)

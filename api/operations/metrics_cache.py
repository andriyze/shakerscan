"""The single-flight cache in front of ``GET /metrics/v2``.

Counting every Scan and action is a pass over the largest tables, so any number of pollers share
one computation per ``METRICS_CACHE_SECONDS`` (default 15 s; 0 disables the cache).
"""
from __future__ import annotations

import os

from .dashboard_data import SingleFlightCache


def metrics_cache_seconds() -> float:
    try:
        return max(0.0, float(os.environ.get("METRICS_CACHE_SECONDS", "15")))
    except ValueError:
        return 15.0


METRICS_CACHE = SingleFlightCache(ttl=metrics_cache_seconds)

__all__ = ["METRICS_CACHE", "metrics_cache_seconds"]

"""Constants the removed Research runtime shared with code that remains.

The runtime itself (episodes, autopilot, campaigns) is gone. Arsenal still orders commands by risk
tier, and the data lifecycle still inventories the ``research_episodes`` rows a deployment kept.
"""

from __future__ import annotations


RESEARCH_EPISODE_VERSION = "research-episode-2026-07-11.v1"

RISK_TIER_ORDER = {
    "read_only": 0,
    "passive": 1,
    "active": 2,
    "intrusive": 3,
    "credential": 4,
    "dangerous": 5,
}

TERMINAL_EPISODE_STATUSES = {
    "completed",
    "cancelled",
    "failed",
    "budget_exhausted",
    "blocked",
}

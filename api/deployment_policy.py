"""Deployment-level policy read from the environment by the API and the workers.

These settings exist for operators who run the engine on their own hosts without the Docker
socket (hardened Compose, ECS, Kubernetes) and who scan their own internal networks. Every one
of them keeps the safe default when unset; each is reported by ``/health`` so an operator, or a
gateway in front of the engine, can see what the deployment allows.
"""
from __future__ import annotations

import os
import shutil
import sys
from typing import Callable

PRIVATE_NETWORK_TARGETS_ENV = "SHAKERSCAN_PRIVATE_NETWORK_TARGETS"
FLEET_MEMORY_GB_ENV = "SHAKERSCAN_FLEET_MEMORY_GB"
CRAWLER_MEMORY_LIMIT_MB_ENV = "SHAKERSCAN_CRAWLER_MEMORY_LIMIT_MB"
CRAWLER_MEMORY_LIMIT_MB_DEFAULT = 2048
CRAWLER_TOOLS_WITH_MEMORY_BOUND = frozenset({"katana"})


def private_network_targets_policy(environ: dict[str, str] | None = None) -> str:
    """``allow`` when the deployment admits private and loopback targets, else ``refuse``.

    The default refuses them unless the target is labelled as a lab environment (the historical
    rule). ``allow`` is meant for self-hosted installations scanning their own intranet; every
    admission under it is recorded in the scope receipt as ``allowed_by_deployment_policy``.
    """
    value = str((environ or os.environ).get(PRIVATE_NETWORK_TARGETS_ENV) or "").strip().lower()
    return "allow" if value in {"allow", "allowed", "1", "true", "yes", "on"} else "refuse"


def private_network_targets_allowed(environ: dict[str, str] | None = None) -> bool:
    return private_network_targets_policy(environ) == "allow"


def fleet_memory_declaration_gb(environ: dict[str, str] | None = None) -> float | None:
    """Fleet memory declared by the operator when Docker's ``/info`` is not reachable."""
    raw = str((environ or os.environ).get(FLEET_MEMORY_GB_ENV) or "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def crawler_memory_limit_bytes(environ: dict[str, str] | None = None) -> int:
    """Data-segment limit for the crawler process; 0 disables the bound."""
    raw = str((environ or os.environ).get(CRAWLER_MEMORY_LIMIT_MB_ENV) or "").strip()
    if not raw:
        return CRAWLER_MEMORY_LIMIT_MB_DEFAULT * 1024 * 1024
    try:
        megabytes = int(raw)
    except ValueError:
        return CRAWLER_MEMORY_LIMIT_MB_DEFAULT * 1024 * 1024
    return max(0, megabytes) * 1024 * 1024


def crawler_memory_bound_argv(
    tool_name: str,
    *,
    limit_bytes: int | None = None,
    platform: str = sys.platform,
    which: Callable[[str], str | None] = shutil.which,
) -> list[str]:
    """The ``prlimit`` prefix that bounds the crawler's memory, or nothing.

    ``RLIMIT_DATA`` counts the Go heap on Linux 4.7+, so a runaway parser ends with Go's own
    ``fatal error: runtime: out of memory`` (exit 2) at the bound instead of taking the whole
    worker container to its cgroup limit. Measured with the 2.3.1 crawler on a synthetic
    Next.js page: killed at 1.7 GiB after 10 s under a 2 GiB bound, where the unbounded process
    exceeded 6 GiB. Only the static crawler is bounded: the headless variant spawns Chromium,
    which inherits the limit and must not be starved. Applied only on Linux, only when
    ``prlimit`` (util-linux) exists, and never for other tools.
    """
    if tool_name not in CRAWLER_TOOLS_WITH_MEMORY_BOUND or not platform.startswith("linux"):
        return []
    limit = crawler_memory_limit_bytes() if limit_bytes is None else int(limit_bytes)
    if limit <= 0:
        return []
    prlimit = which("prlimit")
    if not prlimit:
        return []
    return [prlimit, f"--data={limit}", "--"]


def crawler_memory_bound_exceeded(stderr: bytes | str) -> bool:
    """Go reports a refused allocation as a fatal runtime error on stderr."""
    text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else str(stderr or "")
    return "runtime: out of memory" in text or "cannot allocate memory" in text

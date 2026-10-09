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
# Every crawl runs under a memory ceiling on its whole process tree (the browser included).
CRAWLER_TOOLS_WITH_MEMORY_BOUND = frozenset({"katana", "katana_headless"})
# Only the static crawler also gets a per-process data-segment bound: Chromium would
# inherit it, and a browser needs more address space per process than a Go parser.
CRAWLER_TOOLS_WITH_DATA_SEGMENT_BOUND = frozenset({"katana"})
# A ceiling above the container's own limit is no ceiling: the kernel kills the worker
# first. The crawler may use at most this share of the worker container's memory.
CRAWLER_CONTAINER_MEMORY_SHARE = 0.6
_CGROUP_MEMORY_LIMIT_FILES = (
    "/sys/fs/cgroup/memory.max",                      # cgroup v2
    "/sys/fs/cgroup/memory/memory.limit_in_bytes",    # cgroup v1
)


def private_network_targets_policy(environ: dict[str, str] | None = None) -> str:
    """``allow`` when the deployment admits private and loopback targets, else ``refuse``.

    A self-hosted scanner exists to examine the operator's own network, so the default admits
    RFC1918, loopback and unique-local targets. The refusing default made a fresh install unable
    to do the first thing an operator tries: adding `192.168.1.50` reported "Failed to add
    target" (while creating it anyway), the standing authorization the operator grants by ticking
    "I own or am authorized to test this target" was refused with `loopback_or_private_range`,
    and the active scan that needs that authorization was then refused for want of an approval
    receipt the operator had no way to create.

    This is a deployment decision, not a silent one: every admission under it is recorded in the
    scope receipt as ``allowed_by_deployment_policy``, and ``/health`` reports the policy so a
    gateway in front of the engine can see it. A deployment that must not reach private ranges --
    a hosted or multi-tenant one, where the engine's network is not the customer's -- sets
    ``SHAKERSCAN_PRIVATE_NETWORK_TARGETS=refuse``. The Enterprise gateway always passes an
    explicit value, so its behaviour does not change with this default.
    """
    if environ is not None:
        raw = environ.get(PRIVATE_NETWORK_TARGETS_ENV)
    else:
        raw = os.environ.get("SHAKERSCAN_PRIVATE_NETWORK_TARGETS")
    value = str(raw or "").strip().lower()
    if not value:
        return "allow"
    return "allow" if value in {"allow", "allowed", "1", "true", "yes", "on"} else "refuse"


def _validate_nat64_prefixes_setting(raw: str | None = None) -> tuple[object, ...]:
    try:
        from scanner_tools.address_classes import validate_nat64_prefixes_setting
    except ModuleNotFoundError:  # package import (api.deployment_policy)
        from scanner.scanner_tools.address_classes import (
            validate_nat64_prefixes_setting,
        )
    return validate_nat64_prefixes_setting(raw)


def require_valid_destination_settings() -> None:
    """Refuse to start the API or a worker with a malformed destination setting.

    ``SHAKERSCAN_NAT64_PREFIXES`` is parsed once here; an invalid value raises ``RuntimeError``
    naming the setting instead of failing each IPv6 destination check later as a 500.
    """
    try:
        _validate_nat64_prefixes_setting()
    except ValueError as exc:
        raise RuntimeError(f"refusing to start: {exc}") from None


def health_report() -> dict[str, object]:
    """The deployment policy ``/health`` reports, with the NAT64 setting's readiness."""
    try:
        prefixes = {"status": "ok", "prefixes": [str(item) for item in _validate_nat64_prefixes_setting()]}
    except ValueError as exc:
        prefixes = {"status": "error", "error": str(exc)}
    return {"private_network_targets": private_network_targets_policy(), "nat64_prefixes": prefixes}


def private_network_targets_allowed(environ: dict[str, str] | None = None) -> bool:
    return private_network_targets_policy(environ) == "allow"


def max_allowed_workers_for_memory_gb(
    mem_gb: float, *, per_worker_gb: float = 1.0, platform_reserve_gb: float = 7.0,
) -> int:
    """Workers a host of this size can carry: what is left after the platform reserve.

    The launcher computes the same curve in shell, and the two read memory from different places
    -- the launcher from the host, the API from Docker's ``MemTotal``, which is smaller. A flat
    five-worker band between 8 and 16 GB used to make that difference matter: one 16 GB machine
    could land on either side of the step, and the dashboard reported "9 running - max 5". Above
    the small-machine floor capacity now grows with memory, so the two readings stay within about
    a worker of each other, and no host size gets fewer workers than the flat band gave it.
    """
    if mem_gb <= 0 or per_worker_gb <= 0:
        return 5
    if mem_gb < 8:
        return max(1, min(4, int(mem_gb) - 3))
    return max(5, min(200, int((mem_gb - max(0.0, platform_reserve_gb)) / per_worker_gb)))


def reported_max_allowed_workers(computed: int, running_count: int = 0) -> int:
    """The capacity to *display*, never below the fleet that is actually running.

    A dashboard reading "9 running, max 5" is nonsense, so what is shown accommodates what is
    there. This number is for presentation only: it must never become the cap that governs
    execution. Use `operational_max_allowed_workers` for that.
    """
    try:
        running = max(0, int(running_count))
    except (TypeError, ValueError):
        running = 0
    return max(int(computed), running)


def operational_max_allowed_workers(computed: int, running_count: int = 0) -> int:
    """The cap that governs execution: what the deployment configured, and nothing else.

    The displayed maximum was briefly fed into the published active-scan concurrency, so reading
    the worker list could raise the limit workers obey -- and that list includes exited
    containers, so stopped workers inflated it above an explicitly configured
    SHAKERSCAN_MAX_WORKERS. A monitoring read must not change policy. `running_count` is accepted
    so callers can pass the same inputs to both functions; it deliberately has no effect.
    """
    return int(computed)


def fleet_memory_declaration_gb(environ: dict[str, str] | None = None) -> float | None:
    """Fleet memory declared by the operator when Docker's ``/info`` is not reachable."""
    if environ is not None:
        raw = str(environ.get(FLEET_MEMORY_GB_ENV) or "").strip()
    else:
        raw = str(os.environ.get("SHAKERSCAN_FLEET_MEMORY_GB") or "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def crawler_memory_limit_bytes(environ: dict[str, str] | None = None) -> int:
    """The configured crawler memory ceiling in bytes; 0 disables every crawler bound."""
    if environ is not None:
        raw = str(environ.get(CRAWLER_MEMORY_LIMIT_MB_ENV) or "").strip()
    else:
        raw = str(os.environ.get("SHAKERSCAN_CRAWLER_MEMORY_LIMIT_MB") or "").strip()
    if not raw:
        return CRAWLER_MEMORY_LIMIT_MB_DEFAULT * 1024 * 1024
    try:
        megabytes = int(raw)
    except ValueError:
        return CRAWLER_MEMORY_LIMIT_MB_DEFAULT * 1024 * 1024
    return max(0, megabytes) * 1024 * 1024


def container_memory_limit_bytes(
    read: Callable[[str], str] | None = None,
) -> int | None:
    """The worker container's own cgroup memory limit, or None when unlimited/unknown."""
    def _read(path: str) -> str:
        with open(path, encoding="ascii") as handle:
            return handle.read()

    reader = read or _read
    for path in _CGROUP_MEMORY_LIMIT_FILES:
        try:
            raw = reader(path).strip()
        except (OSError, ValueError):
            continue
        if not raw or raw == "max":
            return None
        try:
            value = int(raw)
        except ValueError:
            continue
        # cgroup v1 reports "unlimited" as a page-rounded huge number.
        return value if 0 < value < 1 << 60 else None
    return None


def crawler_memory_ceiling(
    tool_name: str,
    *,
    environ: dict[str, str] | None = None,
    container_limit: Callable[[], int | None] | None = None,
) -> tuple[int, str]:
    """``(bytes, source)`` of the memory ceiling for a crawler's whole process tree.

    ``SHAKERSCAN_CRAWLER_MEMORY_LIMIT_MB`` (default 2048, 0 disables) sets it, lowered to
    ``CRAWLER_CONTAINER_MEMORY_SHARE`` of the worker container's own memory limit when that
    is smaller, so the tool is stopped and reported before the kernel kills the worker.
    Non-crawler tools get ``(0, "not_a_crawler")``.
    """
    if tool_name not in CRAWLER_TOOLS_WITH_MEMORY_BOUND:
        return 0, "not_a_crawler"
    configured = crawler_memory_limit_bytes(environ)
    if configured <= 0:
        return 0, "disabled"
    container = (container_limit or container_memory_limit_bytes)()
    if container is not None and container > 0:
        share = int(container * CRAWLER_CONTAINER_MEMORY_SHARE)
        if share < configured:
            return share, "container_limit_share"
    return configured, "configured"


def crawler_memory_environment(tool_name: str, limit_bytes: int) -> dict[str, str]:
    """``GOMEMLIMIT`` for the crawler: Go collects harder well before the hard ceiling.

    A soft limit, not a bound -- the process-tree ceiling is the bound. The static crawler
    is all Go heap; in a headless crawl the browser holds most of the memory.
    """
    if tool_name not in CRAWLER_TOOLS_WITH_MEMORY_BOUND or limit_bytes <= 0:
        return {}
    share = 3 / 4 if tool_name in CRAWLER_TOOLS_WITH_DATA_SEGMENT_BOUND else 1 / 4
    return {"GOMEMLIMIT": f"{max(64, int(limit_bytes * share) // (1024 * 1024))}MiB"}


def crawler_memory_bound_argv(
    tool_name: str,
    *,
    limit_bytes: int | None = None,
    platform: str = sys.platform,
    which: Callable[[str], str | None] = shutil.which,
) -> list[str]:
    """The ``prlimit`` prefix that bounds the static crawler's data segment, or nothing.

    ``RLIMIT_DATA`` counts the Go heap on Linux 4.7+, so a runaway parser ends with Go's own
    ``fatal error: runtime: out of memory`` (exit 2) at the bound instead of taking the whole
    worker container to its cgroup limit. Measured with the 2.3.1 crawler on a synthetic
    Next.js page: killed at 1.7 GiB after 10 s under a 2 GiB bound, where the unbounded process
    exceeded 6 GiB. It is per process, so it is only a first line: the supervisor's
    process-tree ceiling (``scanner_tools.process_memory``) bounds every crawler, the headless
    one and its browser included. The headless crawler gets no data-segment bound because
    every Chromium process would inherit it. Applied only on Linux, only when ``prlimit``
    (util-linux) exists, and never for other tools.
    """
    if tool_name not in CRAWLER_TOOLS_WITH_DATA_SEGMENT_BOUND or not platform.startswith("linux"):
        return []
    limit = crawler_memory_limit_bytes() if limit_bytes is None else int(limit_bytes)
    if limit <= 0:
        return []
    prlimit = which("prlimit")
    if not prlimit:
        return []
    return [prlimit, f"--data={limit}", "--"]


def crawler_memory_bound_exceeded(stderr: bytes | str, *, ceiling_reached: bool = False) -> bool:
    """The supervisor's process-tree ceiling fired, or Go reported a refused allocation."""
    if ceiling_reached:
        return True
    text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else str(stderr or "")
    return "runtime: out of memory" in text or "cannot allocate memory" in text

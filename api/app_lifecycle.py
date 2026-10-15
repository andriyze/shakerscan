"""API process lifecycle ownership independent of the route composition root.

The primary API module supplies concrete database and controller callbacks. This
module owns their startup/shutdown ordering so product-router extraction cannot
silently duplicate a scheduler, leak a pool, or change Fleet edge behavior.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

try:
    import deployment_policy
    import loop_leader
    import request_guards
except ModuleNotFoundError:  # package import (api.app_lifecycle)
    from . import deployment_policy, loop_leader, request_guards


AsyncPoolFactory = Callable[..., Awaitable[Any]]
PoolCallback = Callable[[Any], Awaitable[Any]]
PoolSetter = Callable[[Any], None]
ValueProvider = Callable[[], Any]

LIFESPAN_TASK_NAMES = (
    "stale_scan_checker",
    "schedule_runner",
    "asm_dispatcher",
    "research_autopilot_runner",
    "scan_artifact_retention_runner",
    "model_intake_automatic_review_runner",
    "summary_compactor",
)


@dataclass(frozen=True)
class ApiLifecycleDependencies:
    """Concrete process dependencies supplied once by ``api.py``."""

    database_url: str
    create_pool: AsyncPoolFactory
    int_env: Callable[[str, int], int]
    set_pool: PoolSetter
    ensure_schema: PoolCallback
    publish_max_active_scans: Callable[[], Any]
    publish_scanner_version: Callable[[], Any]
    fleet_edge_mode: ValueProvider
    background_controllers: tuple[tuple[str, PoolCallback], ...]
    # One-off background maintenance started once the API serves (never fatal, never awaited).
    background_maintenance: tuple[tuple[str, PoolCallback], ...] = ()

    def validate(self) -> None:
        names = tuple(name for name, _callback in self.background_controllers)
        if names != LIFESPAN_TASK_NAMES:
            raise ValueError(
                "API background controller ownership changed: "
                f"expected {LIFESPAN_TASK_NAMES!r}, got {names!r}"
            )


def create_api_lifespan(dependencies: ApiLifecycleDependencies):
    """Build the one FastAPI lifespan that owns the pool and controllers."""

    dependencies.validate()

    @asynccontextmanager
    async def lifespan(app: Any):
        # A malformed destination setting stops startup with an error naming it.
        deployment_policy.require_valid_destination_settings()
        pool_min = dependencies.int_env("DB_POOL_MIN_SIZE", 5)
        pool_max = dependencies.int_env("DB_POOL_MAX_SIZE", 25)
        statement_timeout_ms = dependencies.int_env(
            "DB_STATEMENT_TIMEOUT_MS", 30_000
        )

        # The timeout is the session default (server_settings), not a SET in ``init``: asyncpg
        # runs RESET ALL on every release, which silently removed an ``init`` SET after each
        # connection's first use. Request classes narrow or widen it per acquire.
        pool = await dependencies.create_pool(
            dependencies.database_url,
            min_size=pool_min,
            max_size=pool_max,
            **request_guards.statement_timeout_pool_options(statement_timeout_ms),
        )
        dependencies.set_pool(pool)
        app.state.db_pool = pool
        # Startup migrations may build an index over a large table: never cancel them.
        with request_guards.unbounded_statements():
            await dependencies.ensure_schema(pool)

        try:
            dependencies.publish_max_active_scans()
            dependencies.publish_scanner_version()
        except Exception:
            # Publishing operator-facing capacity/version hints is best effort;
            # database readiness remains authoritative for API startup.
            pass

        tasks: list[asyncio.Task[Any]] = []
        if not bool(dependencies.fleet_edge_mode()):
            tasks = [
                asyncio.create_task(callback(pool), name=name)
                for name, callback in (
                    *dependencies.background_controllers, *dependencies.background_maintenance)
            ]

        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            # Loop leadership holds one pool connection; give it back before the pool closes.
            await loop_leader.leadership_for(pool).close()
            await pool.close()

    return lifespan


__all__ = [
    "ApiLifecycleDependencies",
    "LIFESPAN_TASK_NAMES",
    "create_api_lifespan",
]

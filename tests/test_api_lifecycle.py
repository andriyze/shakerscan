from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from api.app_lifecycle import (
    ApiLifecycleDependencies,
    LIFESPAN_TASK_NAMES,
    create_api_lifespan,
)


class _Pool:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


def _dependencies(*, edge: bool = False):
    events: list[str] = []
    pool = _Pool()

    async def create_pool(url, **options):
        events.append(f"pool:{url}:{options['min_size']}:{options['max_size']}")
        connection = SimpleNamespace()

        async def execute(statement):
            events.append(statement)

        connection.execute = execute
        await options["init"](connection)
        return pool

    async def ensure_schema(candidate):
        assert candidate is pool
        events.append("schema")

    async def controller(name, candidate):
        assert candidate is pool
        events.append(f"start:{name}")
        try:
            await asyncio.Event().wait()
        finally:
            events.append(f"stop:{name}")

    dependencies = ApiLifecycleDependencies(
        database_url="postgresql://fixture",
        create_pool=create_pool,
        int_env=lambda name, default: {
            "DB_POOL_MIN_SIZE": 7,
            "DB_POOL_MAX_SIZE": 31,
            "DB_STATEMENT_TIMEOUT_MS": 12_345,
        }.get(name, default),
        set_pool=lambda candidate: events.append(
            "published" if candidate is pool else "wrong-pool"
        ),
        ensure_schema=ensure_schema,
        publish_max_active_scans=lambda: events.append("capacity"),
        publish_scanner_version=lambda: events.append("version"),
        fleet_edge_mode=lambda: edge,
        background_controllers=tuple(
            (
                name,
                lambda candidate, name=name: controller(name, candidate),
            )
            for name in LIFESPAN_TASK_NAMES
        ),
    )
    return dependencies, pool, events


def test_lifespan_owns_exact_pool_controller_and_shutdown_order():
    dependencies, pool, events = _dependencies()
    app = SimpleNamespace(state=SimpleNamespace())

    async def exercise():
        async with create_api_lifespan(dependencies)(app):
            await asyncio.sleep(0)
            assert app.state.db_pool is pool
            assert [
                item.removeprefix("start:")
                for item in events
                if item.startswith("start:")
            ] == list(LIFESPAN_TASK_NAMES)
            assert pool.closed is False

    asyncio.run(exercise())

    assert events[:6] == [
        "pool:postgresql://fixture:7:31",
        "SET statement_timeout = 12345",
        "published",
        "schema",
        "capacity",
        "version",
    ]
    assert [
        item.removeprefix("stop:")
        for item in events
        if item.startswith("stop:")
    ] == list(LIFESPAN_TASK_NAMES)
    assert pool.closed is True


def test_fleet_edge_lifespan_never_duplicates_background_controllers():
    dependencies, pool, events = _dependencies(edge=True)
    app = SimpleNamespace(state=SimpleNamespace())

    async def exercise():
        async with create_api_lifespan(dependencies)(app):
            await asyncio.sleep(0)

    asyncio.run(exercise())

    assert not any(item.startswith(("start:", "stop:")) for item in events)
    assert pool.closed is True


def test_lifespan_rejects_missing_reordered_or_duplicate_controller_ownership():
    dependencies, _pool, _events = _dependencies()
    malformed = ApiLifecycleDependencies(
        **{
            **dependencies.__dict__,
            "background_controllers": tuple(
                reversed(dependencies.background_controllers)
            ),
        }
    )

    with pytest.raises(ValueError, match="background controller ownership changed"):
        create_api_lifespan(malformed)


def test_api_remains_the_composition_root_without_lifecycle_reimplementation():
    root = Path(__file__).resolve().parents[1]
    api_source = (root / "api" / "api.py").read_text(encoding="utf-8")
    lifecycle_source = (root / "api" / "app_lifecycle.py").read_text(
        encoding="utf-8"
    )

    assert "lifespan = create_api_lifespan(ApiLifecycleDependencies(" in api_source
    assert "async def lifespan(" not in api_source
    assert "from api import" not in lifecycle_source
    assert "from api.api import" not in lifecycle_source

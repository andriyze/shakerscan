"""The dashboard's CT monitor switch acts on the monitor of its own Compose stack only.

Unit tests with a stand-in Docker socket (no Docker, Redis or database): a host that runs two
stacks lists both stacks' containers to every API that has the socket.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from operations import router as operations_router  # noqa: E402


def container(project: str, service: str, state: str = "running") -> dict:
    return {
        "Id": f"id-{project}-{service}",
        "Names": [f"/{project}-{service}-1"],
        "State": state,
        "Image": f"{project}-{service}:latest",
        "Labels": {"com.docker.compose.project": project, "com.docker.compose.service": service},
        "NetworkSettings": {"Networks": {f"{project}_default": {}}},
    }


class Socket:
    """A Docker socket that lists the containers it holds and records every change asked."""

    def __init__(self, containers: list[dict]):
        self.containers = containers
        self.changes: list[tuple[str, str]] = []
        self.created: list[dict] = []

    def __call__(self, method: str, path: str, body: dict | None = None):
        if method == "GET" and path.startswith("/containers/json"):
            return 200, list(self.containers)
        if method == "GET" and path.startswith("/images/json"):
            return 200, []
        if method == "POST" and path.startswith("/containers/create"):
            self.created.append(body or {})
            return 201, {"Id": "id-created"}
        self.changes.append((method, path))
        return 204, {}


class Redis:
    def __init__(self):
        self.status: dict[str, str] = {}

    def hset(self, _key, field, value):
        self.status[field] = value


@pytest.fixture
def stack(monkeypatch):
    def wire(containers: list[dict], project: str | None = "second"):
        socket, redis = Socket(containers), Redis()
        monkeypatch.setitem(operations_router._deps, "docker_socket_request", socket)
        monkeypatch.setitem(operations_router._deps, "get_redis", lambda: redis)
        monkeypatch.setitem(operations_router._deps, "local_compose_project", lambda: project)
        return socket, redis

    return wire


def test_stop_leaves_another_stacks_monitor_running(stack):
    # The other stack's monitor is listed first, as the Docker listing may order it.
    socket, redis = stack([container("first", "gungnir-worker"), container("second", "api")])
    answer = asyncio.run(operations_router.gungnir_stop())
    assert answer["status"] == "not_found"
    assert socket.changes == []
    assert redis.status == {"running": "false"}


def test_stop_stops_its_own_monitor(stack):
    socket, _redis = stack([container("first", "gungnir-worker"), container("second", "gungnir-worker")])
    answer = asyncio.run(operations_router.gungnir_stop())
    assert answer["status"] == "stopped"
    assert socket.changes == [("POST", "/containers/id-second-gungnir-worker/stop")]


def test_start_does_not_take_another_stacks_running_monitor_for_its_own(stack):
    socket, redis = stack([
        container("first", "gungnir-worker"),
        container("first", "worker"),
        container("second", "worker"),
        container("second", "api"),
    ])
    answer = asyncio.run(operations_router.gungnir_start())
    assert answer["status"] == "started"
    # Its own container, from its own stack's image, network and project.
    assert len(socket.created) == 1
    created = socket.created[0]
    assert created["Image"] == "second-worker:latest"
    assert created["HostConfig"]["NetworkMode"] == "second_default"
    assert created["Labels"]["com.docker.compose.project"] == "second"
    assert socket.changes == [("POST", "/containers/id-created/start")]
    assert redis.status == {"running": "true"}


def test_start_starts_its_own_stopped_monitor(stack):
    socket, _redis = stack([
        container("first", "gungnir-worker"),
        container("second", "gungnir-worker", state="exited"),
    ])
    answer = asyncio.run(operations_router.gungnir_start())
    assert answer["status"] == "started"
    assert socket.created == []
    assert socket.changes == [("POST", "/containers/id-second-gungnir-worker/start")]


@pytest.mark.parametrize("route", ["gungnir_start", "gungnir_stop"])
def test_an_api_that_cannot_tell_its_stack_changes_nothing(stack, route):
    socket, redis = stack([container("first", "gungnir-worker", state="exited")], project=None)
    with pytest.raises(HTTPException) as refused:
        asyncio.run(getattr(operations_router, route)())
    assert refused.value.status_code == 503
    assert "./scanner.sh gungnir" in refused.value.detail
    assert socket.changes == [] and socket.created == []
    assert redis.status == {}

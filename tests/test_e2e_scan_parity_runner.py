from __future__ import annotations

import pytest

from tests.e2e import run_scan_parity


def test_parity_runner_requires_a_real_ready_broker(monkeypatch):
    monkeypatch.setattr(run_scan_parity.H, "get", lambda _path: {
        "nodes": [{"id": "overlay-node", "transport": "wireguard", "status": "ready"}],
    })

    with pytest.raises(RuntimeError, match="cannot be skipped"):
        run_scan_parity._broker_node_id(None)

    monkeypatch.setattr(run_scan_parity.H, "get", lambda _path: {
        "nodes": [{"id": "broker-node", "transport": "broker", "status": "ready"}],
    })
    assert run_scan_parity._broker_node_id(None) == "broker-node"


def test_parity_runner_submits_identical_authority_with_explicit_placement(monkeypatch):
    captured = []

    def post(path, body):
        captured.append((path, body))
        return 202, {"scan_id": "scan-id", "parallel": True}

    monkeypatch.setattr(run_scan_parity.H, "post", post)
    scan_id = run_scan_parity._submit(
        target="https://app.example.test",
        approval_id="approval-id",
        collection={
            "collection_id": "collection-id",
            "binding_id": "binding-id",
            "selection_id": "selection-id",
            "replay_policy": "confirmed_active",
        },
        placement={"node_scope": "remote"},
        parallel=True,
    )

    assert scan_id == "scan-id"
    assert captured[0][0] == "/scans"
    assert captured[0][1]["options"] == {
        "require_current_workers": True,
        "placement": {"node_scope": "remote"},
        "parallel": True,
        "shards": 2,
    }
    assert captured[0][1]["request_collections"][0]["selection_id"] == "selection-id"


def test_parity_runner_rejects_silent_parallel_downgrade(monkeypatch):
    monkeypatch.setattr(
        run_scan_parity.H,
        "post",
        lambda _path, _body: (202, {"scan_id": "scan-id", "parallel": False}),
    )

    with pytest.raises(RuntimeError, match="silently changed"):
        run_scan_parity._submit(
            target="https://app.example.test",
            approval_id="approval-id",
            collection={"selection_id": "selection-id"},
            placement={"node_scope": "remote"},
            parallel=True,
        )

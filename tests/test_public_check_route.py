"""POST /public/check forwards the raw request to the bundled posture engine and returns its answer."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.public_check as public_check

ROOT = Path(__file__).resolve().parents[1]

# A stand-in engine with the real stdin/stdout contract: echo what it received and its environment.
FAKE_ENGINE = r'''
import json, os, sys
raw = sys.stdin.read()
mode = os.environ.get("POSTURE_RESOLVER", "")
if raw == "crash":
    sys.exit(3)
if raw == "hang":
    import time; time.sleep(30)
body = {"schema_version": "2", "received": json.loads(raw), "resolver": mode,
        "leaked": sorted(k for k in os.environ if k.startswith(("DATABASE", "SHAKERSCAN", "FLEET")))}
print(json.dumps({"status": 200, "body": body}))
'''


@pytest.fixture()
def client(tmp_path, monkeypatch):
    engine = tmp_path / "engine.py"
    engine.write_text(FAKE_ENGINE)
    monkeypatch.setattr(public_check, "NODE_BINARY", sys.executable)
    monkeypatch.setattr(public_check, "ENGINE_PATH", str(engine))
    monkeypatch.setenv("DATABASE_URL", "postgres://secret")
    monkeypatch.setenv("SHAKERSCAN_POSTURE_RESOLVER", "system")
    app = FastAPI()
    app.include_router(public_check.router)
    return TestClient(app)


def test_forwards_the_raw_body_and_returns_the_engine_document(client):
    response = client.post("/public/check", json={"target": "10.0.0.5", "path": "/api"})
    assert response.status_code == 200
    body = response.json()
    assert body["received"] == {"target": "10.0.0.5", "path": "/api"}
    assert body["resolver"] == "system"
    # Database and API credentials never reach the engine process.
    assert body["leaked"] == []
    assert response.headers["cache-control"] == "no-store"


def test_request_limits_match_the_public_service(client):
    too_large = client.post("/public/check", content=b'{"target":"' + b"a" * 3000 + b'"}', headers={"content-type": "application/json"})
    assert too_large.status_code == 413 and too_large.json()["error"]["code"] == "body_too_large"
    text = client.post("/public/check", content=b"target=example.com", headers={"content-type": "text/plain"})
    assert text.status_code == 415 and text.json()["error"]["code"] == "unsupported_media_type"


def test_engine_failures_become_public_error_documents(client, monkeypatch):
    assert client.post("/public/check", content=b"crash", headers={"content-type": "application/json"}).json()["error"]["code"] == "service_unavailable"
    monkeypatch.setattr(public_check, "ENGINE_TIMEOUT_SECONDS", 1)
    hung = client.post("/public/check", content=b"hang", headers={"content-type": "application/json"})
    assert hung.status_code == 504 and hung.json()["error"]["code"] == "timeout"
    monkeypatch.setattr(public_check, "NODE_BINARY", "/nonexistent/node")
    missing = client.post("/public/check", json={"target": "example.com"})
    assert missing.status_code == 503 and "not installed" in missing.json()["error"]["message"]


@pytest.mark.skipif(not shutil.which("node") or not (ROOT / "posture" / "node_modules").is_dir(), reason="needs node and posture/ dependencies")
def test_real_engine_bundle_validates_requests_like_the_public_service(tmp_path, monkeypatch):
    subprocess.run(["npm", "run", "build", "--silent"], cwd=ROOT / "posture", check=True, capture_output=True)
    monkeypatch.setattr(public_check, "NODE_BINARY", shutil.which("node"))
    monkeypatch.setattr(public_check, "ENGINE_PATH", str(ROOT / "posture" / "dist" / "instance.cjs"))
    app = FastAPI()
    app.include_router(public_check.router)
    response = TestClient(app).post("/public/check", json={"target": "example.com", "unexpected": True})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"

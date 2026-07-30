"""Authenticated durable service wrapper for the physical Firecracker runner."""

from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import secrets
import threading
from datetime import datetime, timezone
from typing import Any, Literal
import uuid

from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

try:
    from model_intake_control_plane import canonical_bytes
    from model_intake_firecracker_runner import FirecrackerRunner, firecracker_readiness
except ModuleNotFoundError:  # pragma: no cover
    from api.model_intake_control_plane import canonical_bytes
    from api.model_intake_firecracker_runner import FirecrackerRunner, firecracker_readiness


class RunnerJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    submission_id: str
    mode: Literal["runtime", "conversion"] = "runtime"
    environment: Literal["development", "test", "staging", "production"]
    subject_path: str = Field(min_length=1, max_length=4096)
    repository_manifest_path: str = Field(min_length=1, max_length=4096)
    repository_snapshot_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    model_artifact_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    deployment_bundle_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    runtime_image_digest: str = Field(pattern="^sha256:[0-9a-f]{64}$")
    loader_profile: dict[str, Any]
    loader_profile_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    reviewed_custom_code_sha256: str | None = Field(default=None, pattern="^[0-9a-f]{64}$")
    known_answer_inputs: list[str] = Field(default_factory=list, max_length=100)
    known_answer_embedding_sha256: str | None = Field(default=None, pattern="^[0-9a-f]{64}$")
    vcpu_count: int = Field(default=2, ge=1, le=32)
    memory_mib: int = Field(default=4096, ge=256, le=262144)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    output_bytes: int | None = Field(default=None, ge=64 * 1024**2, le=20 * 1024**3)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DurableRunnerQueue:
    def __init__(self) -> None:
        self.root = Path(os.getenv("MODEL_INTAKE_RUNNER_JOB_ROOT", "/var/lib/shakerscan/model-intake-runner/jobs")).resolve()
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.pending: queue.Queue[str] = queue.Queue(maxsize=int(os.getenv("MODEL_INTAKE_RUNNER_QUEUE_LIMIT", "32")))
        self.runner = FirecrackerRunner()
        self._recover()
        self.thread = threading.Thread(target=self._loop, name="model-intake-firecracker", daemon=True)
        self.thread.start()

    def _path(self, job_id: str) -> Path:
        try:
            normalized = str(uuid.UUID(job_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="runner job not found") from exc
        return self.root / f"{normalized}.json"

    def _write(self, job: dict[str, Any]) -> None:
        path = self._path(job["id"])
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_bytes(canonical_bytes(job))
        temporary.chmod(0o600)
        os.replace(temporary, path)

    def _recover(self) -> None:
        for path in sorted(self.root.glob("*.json")):
            try:
                job = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if job.get("state") in {"pending", "running"}:
                job["state"] = "failed"
                job["error"] = {"code": "runner_restarted", "message": "Runner restarted before a terminal receipt was committed"}
                job["finished_at"] = _now()
                self._write(job)

    def submit(self, request: RunnerJobRequest) -> dict[str, Any]:
        if self.pending.full():
            raise HTTPException(status_code=429, detail="runner queue is full")
        job = {
            "schema_version": "model-intake-runner-job/v1",
            "id": str(uuid.uuid4()),
            "state": "pending",
            "request": request.model_dump(mode="json"),
            "created_at": _now(),
            "started_at": None,
            "finished_at": None,
            "result": None,
            "error": None,
        }
        self._write(job)
        self.pending.put_nowait(job["id"])
        return job

    def get(self, job_id: str) -> dict[str, Any]:
        path = self._path(job_id)
        if not path.is_file():
            raise HTTPException(status_code=404, detail="runner job not found")
        return json.loads(path.read_text())

    def _loop(self) -> None:
        while True:
            job_id = self.pending.get()
            try:
                job = self.get(job_id)
                if job["state"] != "pending":
                    continue
                job["state"] = "running"
                job["started_at"] = _now()
                self._write(job)
                try:
                    job["result"] = self.runner.execute_and_sign(job["request"])
                    job["state"] = "completed"
                except Exception as exc:
                    job["state"] = "failed"
                    job["error"] = {"code": type(exc).__name__, "message": str(exc)[:4000]}
                job["finished_at"] = _now()
                self._write(job)
            finally:
                self.pending.task_done()


def _authorize(token: str | None) -> None:
    expected = os.getenv("MODEL_INTAKE_RUNNER_INTERNAL_TOKEN", "")
    if len(expected) < 32 or not token or not secrets.compare_digest(expected, token):
        raise HTTPException(status_code=403, detail="runner service authentication failed")


jobs: DurableRunnerQueue | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global jobs
    if len(os.getenv("MODEL_INTAKE_RUNNER_INTERNAL_TOKEN", "")) < 32:
        raise RuntimeError("MODEL_INTAKE_RUNNER_INTERNAL_TOKEN must contain at least 32 characters")
    jobs = DurableRunnerQueue()
    yield


app = FastAPI(title="ShakerScan Model Intake Firecracker Runner", lifespan=lifespan)


@app.get("/health")
async def health():
    readiness = firecracker_readiness()
    return {**readiness, "service": "model-intake-firecracker-runner", "queue_depth": jobs.pending.qsize() if jobs else 0}


@app.post("/internal/model-intake/runner/jobs")
async def submit_job(request: RunnerJobRequest, x_shakerscan_runner_token: str | None = Header(default=None)):
    _authorize(x_shakerscan_runner_token)
    if jobs is None:
        raise HTTPException(status_code=503, detail="runner queue is unavailable")
    job = jobs.submit(request)
    return {key: job[key] for key in ("id", "state", "created_at")}


@app.get("/internal/model-intake/runner/jobs/{job_id}")
async def get_job(job_id: str, x_shakerscan_runner_token: str | None = Header(default=None)):
    _authorize(x_shakerscan_runner_token)
    if jobs is None:
        raise HTTPException(status_code=503, detail="runner queue is unavailable")
    return jobs.get(job_id)

"""The first nuclei process in a fresh worker container must not build the template index.

nuclei v3 parses every template in the pinned bundle (~13k files) on its first run and
writes ``$XDG_CACHE_HOME|$HOME/.cache/nuclei/index.gob``, even when the scan selects six
templates by ``-id``. Paid inside the canonical passive action's 30 s wall, that cold start
timed the action out on the first scan after every worker restart. The image bakes the index
and every worker entrypoint rebuilds it before taking work when it is missing.

The nuclei binary used here is a unit-test fake shell script, not the real scanner.
"""

from __future__ import annotations

import os
import stat
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

import broker_worker  # noqa: E402
import worker  # noqa: E402
from runtime import nuclei_index  # noqa: E402
sys.path.pop(0)


def _dockerfile_lines() -> list[str]:
    text = (ROOT / "scanner" / "Dockerfile").read_text(encoding="utf-8")
    # Join line continuations so one RUN instruction is one logical line.
    return text.replace("\\\n", " ").splitlines()


def test_scanner_image_bakes_the_nuclei_template_index_offline_under_the_runtime_home():
    lines = _dockerfile_lines()
    home = next(i for i, line in enumerate(lines) if line.strip() == "ENV HOME=/tmp")
    index_runs = [
        (i, line) for i, line in enumerate(lines)
        if line.lstrip().startswith("RUN ") and "/opt/tools/nuclei" in line and " -tl" in line
    ]
    assert len(index_runs) == 1, "the scanner image must build the nuclei template index once"
    position, run = index_runs[0]
    assert position > home, "the index must be written under the runtime HOME=/tmp"
    assert "--network=none" in run, "building the index must not depend on network access"
    assert "-duc" in run
    assert "test -s /tmp/.cache/nuclei/index.gob" in run
    # Keep the layer ahead of the per-release identity so source changes reuse it.
    version_arg = next(i for i, line in enumerate(lines) if line.startswith("ARG SCANNER_VERSION"))
    assert position < version_arg


def test_index_path_follows_nuclei_cache_resolution(tmp_path):
    assert nuclei_index.nuclei_index_path({"HOME": "/tmp"}) == Path("/tmp/.cache/nuclei/index.gob")
    assert nuclei_index.nuclei_index_path(
        {"HOME": "/tmp", "XDG_CACHE_HOME": str(tmp_path)}
    ) == tmp_path / "nuclei" / "index.gob"


def _fake_nuclei(tmp_path: Path, *, writes_index: bool) -> tuple[Path, Path]:
    calls = tmp_path / "calls.log"
    body = [
        "#!/bin/sh",
        f'printf "%s\\n" "$*" >> "{calls}"',
        'env | grep -i "^\\(http\\|https\\|all\\)_proxy=" >> "' + str(calls) + '" || true',
    ]
    if writes_index:
        body += [
            'mkdir -p "$HOME/.cache/nuclei"',
            'printf "index" > "$HOME/.cache/nuclei/index.gob"',
        ]
    script = tmp_path / "nuclei"
    script.write_text("\n".join(body) + "\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script, calls


def test_missing_index_is_built_once_without_proxy_and_then_reused(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient-proxy.invalid:3128")
    binary, calls = _fake_nuclei(tmp_path, writes_index=True)

    built = nuclei_index.ensure_nuclei_template_index(binary=str(binary), timeout=30)
    assert built == home / ".cache" / "nuclei" / "index.gob"
    assert built.stat().st_size > 0
    recorded = calls.read_text(encoding="utf-8").splitlines()
    assert recorded == ["-duc -silent -no-color -tl"], "index build must be offline and proxy-free"

    nuclei_index.ensure_nuclei_template_index(binary=str(binary), timeout=30)
    assert calls.read_text(encoding="utf-8").splitlines() == recorded, "a present index is reused"


def test_index_build_that_writes_nothing_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    binary, _calls = _fake_nuclei(tmp_path, writes_index=False)

    with pytest.raises(RuntimeError, match="nuclei template index"):
        nuclei_index.ensure_nuclei_template_index(binary=str(binary), timeout=30)


def test_absent_nuclei_binary_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PATH", str(tmp_path))
    assert nuclei_index.ensure_nuclei_template_index() is None


def test_worker_preflight_warms_the_nuclei_index_before_taking_jobs(monkeypatch, tmp_path):
    calls: list[str] = []
    monkeypatch.setattr(worker, "ensure_nuclei_template_index", lambda: calls.append("index"))
    monkeypatch.setenv("WORKER_PREFLIGHT_ENABLED", "true")
    monkeypatch.setattr(
        worker.worker_queue_policy_module, "refresh_model_intake_scanner_data", lambda *_a: None,
    )
    # Stop right after the warm-up: a missing, optional scanner entrypoint ends preflight.
    monkeypatch.setattr(worker, "SCANNER_PATH", str(tmp_path / "missing-scanner.py"))
    monkeypatch.setenv("WORKER_PREFLIGHT_REQUIRE_SCANNER", "false")

    worker.run_worker_preflight()

    assert calls == ["index"]


@pytest.mark.parametrize("once", [False, True])
def test_broker_worker_warms_the_nuclei_index_before_leasing(monkeypatch, tmp_path, once):
    order: list[str] = []
    monkeypatch.setattr(broker_worker, "assert_outbound_only_runtime_environment", lambda: None)
    monkeypatch.setattr(broker_worker, "load_state", lambda _path: {"node_id": "node-1"})
    monkeypatch.setattr(
        broker_worker, "ensure_nuclei_template_index", lambda: order.append("index"),
    )

    async def fake_run_forever(_state, _worker_id):
        order.append("run_forever")

    def fake_api_request(*_args, **_kwargs):
        order.append("lease")

    monkeypatch.setattr(broker_worker, "run_forever", fake_run_forever)
    monkeypatch.setattr(broker_worker, "api_request", fake_api_request)
    for name in ("SHAKERSCAN_BROKER_LEASE", "ARTIFACT_STORAGE_REQUIRED", "SHAKERSCAN_NODE_ID"):
        monkeypatch.setenv(name, os.environ.get(name, ""))
    argv = ["broker_worker.py", "--state", str(tmp_path / "state.json")]
    if once:
        argv.append("--once")
    monkeypatch.setattr(sys, "argv", argv)

    assert broker_worker.main() == 0
    assert order == ["index", "lease" if once else "run_forever"]


def test_release_candidate_proves_a_fresh_scanner_container_runs_nuclei_warm():
    import yaml

    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text(encoding="utf-8")
    )
    steps = [step for job in workflow["jobs"].values() for step in job.get("steps") or []]
    names = [str(step.get("name") or "") for step in steps]
    check = next(
        step for step in steps
        if step.get("name") == "Verify the first nuclei run in a fresh scanner container is warm"
    )
    script = check["run"]
    assert "--network none" in script and "shakerscan-scanner:release-candidate" in script
    assert 'index = "/tmp/.cache/nuclei/index.gob"' in script
    assert "agent_tools._tmpl_nuclei(" in script
    assert "agent_tools._CANONICAL_PASSIVE_NUCLEI_IDS" in script
    assert "len(matches) != 10 or elapsed > 5" in script
    # It must run against the same candidate bytes before the wire acceptance and publication.
    assert names.index(check["name"]) < names.index("Enforce candidate-image external wire ceilings")

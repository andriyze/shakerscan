"""Process tests for two client defects from the live OpenCode Hunt acceptance (2026-10-08).

* D43: ``shakerscan_hunt_capability`` advertised a top-level ``experiment_key`` the engine refuses
  (422 "experiment_key: Extra inputs are not permitted"); luna's first call of each capability
  failed on it. The MCP adapter runs here as the agent's MCP server does (JSON-RPC lines over
  stdio) and every capability body it sends must be one the engine's own request model accepts.
* D44: ``shakerscan agent opencode --allow …`` stepped up and minted a live pre-authorization, then
  exited because OpenCode was not on PATH. The real ``python -m shakerscan`` runs in a
  pseudo-terminal with a PATH that has no OpenCode.

The instance is the stub from ``tests/hunt_permission_stub.py`` (a unit fixture: real HTTP(S),
scripted routes, every request recorded); it is not an engine or a gateway.
"""

from __future__ import annotations

import json
import os
import select
import sys
import time
from pathlib import Path

from api.hunt.interaction_router import HuntCapabilityRequest
from tests.hunt_permission_stub import HUNT, TOKEN, TOTP, StubInstance, self_signed
from tests.test_hunt_terminal_approval import Session, _environment
from tests.test_mcp_permission_process import Adapter

ROOT = Path(__file__).resolve().parents[1]


def _advertised_capability_schema() -> dict:
    """The schema the adapter advertises for the tool (tools/list needs a full instance)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("shakerscan_mcp_d43", ROOT / "scripts" / "shakerscan_mcp.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # its dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module.HUNT_TOOL_BY_NAME["shakerscan_hunt_capability"].descriptor()["inputSchema"]


def test_the_mcp_capability_tool_sends_only_what_the_engine_accepts():
    with StubInstance() as stub:
        stub.request["status"] = "granted"  # the stub's capability then simply completes
        adapter = Adapter(stub.url)
        try:
            schema = _advertised_capability_schema()
            engine = set(HuntCapabilityRequest.model_fields)
            # Everything the tool takes is a path parameter or a field of the engine's body.
            assert set(schema["properties"]) - {"hunt_id", "capability_name"} == engine
            refused = adapter.call("shakerscan_hunt_capability", {
                "hunt_id": HUNT, "capability_name": "web.crawl", "input": {},
                "experiment_key": "a" * 32, "idempotency_key": "agent-key-crawl-0042",
            })
            assert refused["error"]["code"] == -32602 and "experiment_key" in refused["error"]["message"]
            assert not [path for path in stub.routes("POST") if "/capabilities/" in path], (
                "an argument the engine would refuse is refused locally, before any request"
            )
            done = adapter.call("shakerscan_hunt_capability", {
                "hunt_id": HUNT, "capability_name": "web.crawl", "input": {},
                "idempotency_key": "agent-key-crawl-0042",
            })
            assert "result" in done, done
        finally:
            adapter.close()
    body = next(body for method, path, body in stub.seen if method == "POST" and "/capabilities/" in path)
    HuntCapabilityRequest.model_validate(body)


def _run_until_exit(session: Session, *, timeout: float = 30.0) -> None:
    """Read the CLI's output until it exits; answer a step-up prompt if one appears (the
    behaviour being tested is that none does, but a hang would hide the failure)."""
    deadline = time.monotonic() + timeout
    answered = False
    while session.proc.poll() is None and time.monotonic() < deadline:
        if select.select([session.proc.stdout], [], [], 0.2)[0]:
            session.out += os.read(session.proc.stdout.fileno(), 65536)
        if not answered and b"TOTP code for alice" in session.out:
            session.type(TOTP + "\n")
            answered = True


def test_agent_allow_checks_the_agent_binary_before_any_step_up(tmp_path):
    cert, key = self_signed(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    env = _environment(tmp_path, SSL_CERT_FILE=str(cert), PATH=str(bin_dir))
    with StubInstance(tls=(cert, key), gateway="g1") as stub:
        config = Path(env["SHAKERSCAN_CONFIG_DIR"])
        config.mkdir(parents=True, mode=0o700)
        (config / "token").write_text(TOKEN + "\n", encoding="utf-8")
        (config / "token").chmod(0o600)
        (config / "config.json").write_text(json.dumps({"url": stub.url, "token_file": str(config / "token")}),
                                            encoding="utf-8")
        session = Session(["agent", "opencode", "--workspace", str(tmp_path / "ws"),
                           "--allow", "budget.raise:2x", "--account", "alice"], env)
        _run_until_exit(session)
        code, out, err = session.finish()
    assert not [path for path in stub.routes() if path.startswith("/_enterprise/approvals/")], (
        "no step-up and no pre-authorization for an agent that cannot start"
    )
    assert "pre-authorization" not in out
    assert code == 2, (out, err)
    assert "opencode is not on this PATH" in err and "Nothing was pre-authorized" in err

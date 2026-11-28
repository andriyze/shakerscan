"""``shakerscan mcp --remote ENDPOINT``: a deployment's own MCP server, over stdio.

An Enterprise deployment publishes MCP servers of its own (streamable HTTP with a bearer token)
beside the engine's. ``shakerscan agent`` registers them as this bridge so the token stays in its
file, as it does for the engine's server: the agent's configuration names a command, never a token
or an environment variable holding one. Each JSON-RPC message read from stdin is POSTed to the
endpoint; each message in the answer (JSON or an event stream) is written to stdout.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any, BinaryIO

from ._mcp_install import HTTP_ERRORS, MAX_RESPONSE_BYTES, PROTOCOL_VERSION, ResponseTooLarge, http_post

CALL_SECONDS = 300.0
MAX_LINE_BYTES = 4_000_000


def _messages(headers: dict[str, str], body: bytes) -> list[dict[str, Any]]:
    text = body.decode("utf-8", "replace")
    if "text/event-stream" in headers.get("content-type", ""):
        found = []
        for event in re.split(r"\r?\n\r?\n", text):
            data = "\n".join(line[5:].lstrip() for line in event.splitlines() if line.startswith("data:"))
            try:
                message = json.loads(data) if data else None
            except ValueError:
                continue
            if isinstance(message, dict):
                found.append(message)
        return found
    try:
        message = json.loads(text) if text.strip() else None
    except ValueError:
        return []
    if isinstance(message, list):
        return [item for item in message if isinstance(item, dict)]
    return [message] if isinstance(message, dict) else []


def _error(ident: Any, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": ident, "error": {"code": -32001, "message": message}}


def serve(endpoint: str, token: str, stdin: BinaryIO, stdout: BinaryIO,
          post: Callable[..., tuple[int, dict[str, str], bytes]] | None = None,
          timeout: float = CALL_SECONDS) -> int:
    post = post or http_post
    session = ""
    protocol = PROTOCOL_VERSION

    def write(message: dict[str, Any]) -> None:
        stdout.write(json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n")
        stdout.flush()

    for raw in iter(lambda: stdin.readline(MAX_LINE_BYTES), b""):
        if not raw.strip():
            continue
        try:
            message = json.loads(raw)
        except ValueError:
            write(_error(None, "not a JSON-RPC message"))
            continue
        ident = message.get("id") if isinstance(message, dict) else None
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": f"Bearer {token}", "MCP-Protocol-Version": protocol}
        if session:
            headers["Mcp-Session-Id"] = session
        try:
            status, answer_headers, body = post(endpoint, json.dumps(message).encode("utf-8"), headers, timeout)
        except ResponseTooLarge:
            # Never cut and parsed: the caller is told, and can ask for less.
            if ident is not None:
                write(_error(ident, f"the deployment's MCP server answered with more than {MAX_RESPONSE_BYTES} "
                                    "bytes, which this bridge does not pass on; ask for less (a smaller page, "
                                    "a narrower filter)"))
            continue
        except HTTP_ERRORS as exc:
            if ident is not None:
                write(_error(ident, "the deployment's MCP server is unavailable: "
                                    f"{getattr(exc, 'reason', None) or exc}"))
            continue
        session = answer_headers.get("mcp-session-id", session)
        if status in (202, 204):
            continue
        if status >= 300:
            if ident is not None:
                reason = "it refused the token" if status in (401, 403) else f"HTTP {status}"
                write(_error(ident, f"the deployment's MCP server answered {reason}"))
            continue
        answered = False
        for answer in _messages(answer_headers, body):
            result = answer.get("result")
            if isinstance(message, dict) and message.get("method") == "initialize" and isinstance(result, dict):
                protocol = str(result.get("protocolVersion") or protocol)
            answered = answered or (ident is not None and answer.get("id") == ident)
            write(answer)
        if ident is not None and not answered and isinstance(message, dict) and "method" in message:
            # A request always gets an answer: one that could not be read (cut short, not JSON) or
            # that the endpoint left out is an error for that id, not silence.
            write(_error(ident, "the deployment's MCP server sent no readable answer to this request"))
    return 0


__all__ = ["serve"]

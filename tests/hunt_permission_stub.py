"""Stub ShakerScan instance for the terminal-approval process tests (a unit fixture).

It is NOT an engine or a gateway. It serves, over real HTTP or HTTPS on a loopback port, exactly
the routes the approve CLI and the MCP adapter use for one Hunt with one parked action:

* engine: ``GET /hunts/{id}``, ``GET /hunts?status=``, the permission-request reads (with
  ``wait_seconds`` long-polling), the decision route, and one capability that answers 409
  ``permission_required`` until the request is granted and then completes, replaying a key it
  already ran;
* gateway (``gateway="g1"``): ``/_enterprise/approvals/begin|finish|session/revoke`` as specified in
  docs/hunt-permission-requests.md, with the set digest recomputed here from the request body;
* gateway without G1 (``gateway="pre-g1"``): the beta gateway's named 403 for an unknown route.

Every request is recorded in ``seen`` so tests can assert which routes were (never) called.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import urllib.parse

HUNT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REQUEST = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
ACTION = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
DIGEST = "d" * 64
TOKEN = "stub-service-token-0000000000000001"
TOTP = "246810"
TITLE = "Raise max_http_requests for this Hunt"


def self_signed(tmp: Path) -> tuple[Path, Path]:
    """A localhost certificate and key; the CLI trusts it through SSL_CERT_FILE."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / "stub-cert.pem", tmp / "stub-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption(),
    ))
    return cert_path, key_path


def approval_set_digest(body: dict[str, Any], origin: str) -> str:
    """The gateway's side of the set digest, written from the protocol text, not the client."""
    document: dict[str, Any] = {
        "schema_version": "shakerscan-approval-set/v1", "purpose": body["purpose"],
        "account": body["account"], "origin": origin,
    }
    if body["purpose"] == "permission_decision":
        document["decisions"] = sorted(
            ({k: item[k] for k in ("hunt_id", "request_id", "subject_digest", "decision", "scope", "choice")}
             for item in body["decisions"]),
            key=lambda item: (item["hunt_id"], item["request_id"]),
        )
    elif body["purpose"] == "preauthorization":
        document["preauthorization"] = {"allow": sorted(set(body["preauthorization"]["allow"])),
                                        "use": body["preauthorization"]["use"]}
    else:
        document["session"] = {"ttl_seconds": int(body["session"]["ttl_seconds"])}
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


class StubInstance:
    def __init__(self, *, tls: tuple[Path, Path] | None = None, gateway: str | None = None) -> None:
        self.gateway = gateway  # None (open-source engine), "g1" or "pre-g1"
        self.lock = threading.Lock()
        self.seen: list[tuple[str, str, Any]] = []
        self.request = {
            "schema_version": "hunt-permission-request/v1", "id": REQUEST, "hunt_id": HUNT,
            "kind": "budget.raise", "reason_code": "budget_exhausted", "status": "pending",
            "subject": {"dimension": "max_http_requests", "limit": 500}, "subject_digest": DIGEST,
            "title": TITLE, "explanation": "The Hunt reached its max_http_requests limit of 500.",
            "effect": "Sets the total max_http_requests to 1000 through one budget amendment.",
            "remember_supported": False, "choices": ["allow", "deny"], "scopes": ["hunt"],
            "action_id": ACTION, "created_at": "2026-10-08T10:00:00Z", "expires_at": "2026-10-09T10:00:00Z",
            "decided_by": None, "decision_via": None, "approve_command": f"shakerscan approve {REQUEST}",
        }
        self.ran_keys: dict[str, dict[str, Any]] = {}
        self.approvals: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, str] = {}
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # quiet
                return

            def _body(self) -> Any:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                return json.loads(raw) if raw else None

            def _send(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                stub.handle(self, "GET")

            def do_POST(self) -> None:  # noqa: N802
                stub.handle(self, "POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.scheme = "http"
        if tls is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(tls[0]), str(tls[1]))
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            self.scheme = "https"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host = "localhost" if self.scheme == "https" else "127.0.0.1"
        return f"{self.scheme}://{host}:{self.server.server_address[1]}"

    def __enter__(self) -> "StubInstance":
        self.thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()

    def routes(self, method: str | None = None) -> list[str]:
        return [path for seen_method, path, _ in self.seen if method in (None, seen_method)]

    # -- engine --------------------------------------------------------------------------------

    def _hunt(self) -> dict[str, Any]:
        return {
            "hunt_id": HUNT, "status": "active", "target_kind": "web",
            "capabilities": [{"name": "web.crawl", "input_schema": {"type": "object", "properties": {}},
                              "budget_cost": {"http_requests": 150, "tool_wall_seconds": 75}}],
            "pending_permission_requests": [] if self.request["status"] != "pending" else [
                {key: self.request[key] for key in ("id", "kind", "reason_code", "title", "expires_at", "approve_command")}
            ],
        }

    def _decide(self, body: dict[str, Any]) -> tuple[int, Any]:
        if body.get("subject_digest") != DIGEST:
            return 409, {"detail": {"error": "permission_subject_changed", "message": "fetch it again"}}
        with self.lock:
            if self.request["status"] != "pending":
                return 200, {"replayed": True, "request": dict(self.request)}
            self.request.update(
                status="granted" if body["decision"] == "allow" else "denied",
                decided_by=body.get("decided_by"), decision_via=body.get("decision_via"),
                decision_scope=body.get("scope"),
            )
            return 200, {"replayed": False, "request": dict(self.request)}

    def _capability(self, body: dict[str, Any]) -> tuple[int, Any]:
        key = str(body.get("idempotency_key") or "")
        with self.lock:
            if key in self.ran_keys:
                return 200, {**self.ran_keys[key], "idempotent_replay": True}
            if self.request["status"] == "pending":
                return 409, {"detail": {
                    "code": "permission_required", "error": "budget_exhausted:http_requests",
                    "reason_code": "budget_exhausted", "message": "The Hunt's max_http_requests limit does not cover this action.",
                    "action_id": ACTION,
                    "permission_request": {key: self.request[key] for key in ("id", "kind", "status", "title", "expires_at")},
                }}
            if self.request["status"] != "granted":
                return 403, {"detail": {"error": "permission_denied", "reason_code": "permission_denied",
                                        "message": "The person denied this permission."}}
            result = {"action_result": {"action_id": ACTION, "status": "completed"},
                      "observations": [{"kind": "crawl", "urls": 12}]}
            self.ran_keys[key] = result
            return 200, result

    def _wait(self, query: dict[str, list[str]]) -> dict[str, Any]:
        deadline = time.monotonic() + min(25, int((query.get("wait_seconds") or ["0"])[0]))
        while self.request["status"] == "pending" and time.monotonic() < deadline:
            time.sleep(0.05)
        return {**self.request, "waited": True}

    # -- gateway (G1 contract) -----------------------------------------------------------------

    def _approval_error(self, status: int, code: str, message: str) -> tuple[int, Any]:
        return status, {"detail": {"schema_version": "shakerscan-approval-error/v1", "error": code, "message": message}}

    def _begin(self, body: dict[str, Any]) -> tuple[int, Any]:
        if body.get("origin") != self.url:
            return self._approval_error(422, "origin_mismatch", "the approval names another instance")
        if body.get("purpose") == "permission_decision":
            for item in body["decisions"]:
                if item["request_id"] != REQUEST or self.request["status"] != "pending" or item["subject_digest"] != DIGEST:
                    return self._approval_error(409, "approval_set_changed", "a request is no longer pending")
        approval_id = f"apv_{len(self.approvals) + 1:04d}"
        digest = approval_set_digest(body, self.url)
        self.approvals[approval_id] = {"body": body, "digest": digest}
        return 200, {
            "schema_version": "shakerscan-approval-challenge/v1", "approval_id": approval_id,
            "set_digest": digest, "methods": ["totp"], "account": body["account"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        }

    def _finish(self, body: dict[str, Any]) -> tuple[int, Any]:
        approval = self.approvals.pop(str(body.get("approval_id")), None)
        if approval is None or body.get("set_digest") != approval["digest"]:
            return self._approval_error(409, "approval_unknown", "begin the approval again")
        proof = body.get("proof") or {}
        via = "terminal_stepup"
        if proof.get("method") == "totp":
            if proof.get("code") != TOTP:
                return self._approval_error(403, "stepup_failed", "the code is not valid")
        elif proof.get("method") == "approver_session":
            if self.sessions.get(str(proof.get("session_id"))) != proof.get("session_secret"):
                return self._approval_error(403, "session_invalid", "the approver session is not valid")
            via = "approver_session"
        else:
            return self._approval_error(422, "proof_unsupported", "unsupported proof")
        begun = approval["body"]
        person = begun["account"]
        answer: dict[str, Any] = {"schema_version": "shakerscan-approval-result/v1",
                                  "approval_id": body["approval_id"], "decided_by": person, "decision_via": via}
        if begun["purpose"] == "permission_decision":
            results = []
            for item in begun["decisions"]:
                # The gateway forwards to the engine's decision route with the person as decided_by.
                status, decided = self._decide({**item, "decided_by": person, "decision_via": via})
                results.append({"hunt_id": item["hunt_id"], "request_id": item["request_id"],
                                "http_status": status, **({"request": decided["request"]} if status == 200 else {"error": decided})})
            answer["results"] = results
        elif begun["purpose"] == "preauthorization":
            answer["preauthorization"] = {"id": "pre_0001", "allow": begun["preauthorization"]["allow"],
                                          "use": begun["preauthorization"]["use"], "proof": "launch_stepup",
                                          "expires_at": "2026-10-08T22:00:00Z"}
        else:
            self.sessions["ses_0001"] = "session-secret-value-0001"
            answer["session"] = {"session_id": "ses_0001", "session_secret": "session-secret-value-0001",
                                 "expires_at": "2026-10-08T10:30:00Z"}
        return 200, answer

    # -- dispatch ------------------------------------------------------------------------------

    def handle(self, handler: Any, method: str) -> None:
        parts = urllib.parse.urlsplit(handler.path)
        path, query = parts.path, urllib.parse.parse_qs(parts.query)
        body = handler._body() if method == "POST" else None
        with self.lock:
            self.seen.append((method, handler.path, body))
        if self.gateway is not None and handler.headers.get("Authorization") != f"Bearer {TOKEN}":
            return handler._send(401, {"detail": "sign in to ShakerScan Enterprise"})
        if path.startswith("/_enterprise/approvals/"):
            if self.gateway != "g1":
                status = 403 if self.gateway == "pre-g1" else 404
                return handler._send(status, {"detail": f"operator tokens cannot use {method} {path}"})
            route = {
                "/_enterprise/approvals/begin": self._begin,
                "/_enterprise/approvals/finish": self._finish,
                "/_enterprise/approvals/session/revoke":
                    lambda b: (200, {"schema_version": "shakerscan-approval-session/v1",
                                     "session_id": b.get("session_id"),
                                     "revoked": self.sessions.pop(str(b.get("session_id")), None) is not None}),
            }.get(path)
            return handler._send(*(route(body) if route else (404, {"detail": "Not Found"})))
        prefix = f"/hunts/{HUNT}"
        if method == "GET" and path == "/hunts":
            hunts = [self._hunt()] if (query.get("status") or [""])[0] == "active" else []
            return handler._send(200, {"hunts": hunts, "count": len(hunts)})
        if method == "GET" and path == prefix:
            return handler._send(200, self._hunt())
        if method == "GET" and path == f"{prefix}/permission-requests":
            wanted = (query.get("status") or [None])[0]
            items = [dict(self.request)] if wanted in (None, self.request["status"]) else []
            return handler._send(200, {"hunt_id": HUNT, "requests": items})
        if method == "GET" and path == f"{prefix}/permission-requests/{REQUEST}":
            return handler._send(200, self._wait(query))
        if method == "POST" and path == f"{prefix}/permission-requests/{REQUEST}/decision":
            if self.gateway is not None:
                # The gateway never proxies the engine's decision route.
                return handler._send(403, {"detail": "the decision route is not available to tokens"})
            return handler._send(*self._decide(body))
        if method == "POST" and path == f"{prefix}/capabilities/web.crawl":
            return handler._send(*self._capability(body))
        return handler._send(404, {"detail": f"stub has no {method} {path}"})

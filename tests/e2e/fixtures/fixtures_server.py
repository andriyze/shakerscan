"""Local stdlib fixtures server for e2e tests.

Serves a deliberately-LEAKY AI chat endpoint and small model artifacts so the
AI-redaction and Model-Intake assertions run deterministically and fast, with no
dependence on external honey apps, auth, or HuggingFace. Bind 0.0.0.0 so the
worker container can reach it (targets use http://<host.docker.internal>:<port>).

Nothing dangerous executes: DANGEROUS_PICKLE is built with pickle.dumps (which
serializes a __reduce__ tuple without calling it) and is only ever read as bytes
by Model Intake's static serialization scanner.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import pickle
import threading
import time
import urllib.parse


def _safetensors(payload: bytes = b"\0\0\0\0") -> bytes:
    header = {"__metadata__": {}, "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, len(payload)]}}
    raw = json.dumps(header, separators=(",", ":")).encode()
    return len(raw).to_bytes(8, "little") + raw + payload


GOOD = _safetensors()
GOOD_SHA = hashlib.sha256(GOOD).hexdigest()
WRONG_SHA = "0" * 64

# A "large" artifact served as 206 Partial Content with NO Content-Range total —
# the exact CDN shape that produced the false sha256 mismatch. LARGE_SHA is the
# FULL-artifact digest; a capped range fetch yields a different (prefix) hash, so
# the scan must report known_unverified_truncated, not a mismatch. Deterministic
# local replacement for the real multi-GB HuggingFace fetch in the hard gate.
LARGE = _safetensors(payload=b"\x00" * 16384)
LARGE_SHA = hashlib.sha256(LARGE).hexdigest()

# ed25519 material generated once (in a container, host lacks cryptography) over
# GOOD's exact bytes. The fixtures GOOD is byte-identical (same construction), so
# the signature verifies when the worker fetches /models/good.safetensors.
SIGNING_PUB_PEM = base64.b64decode(
    "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQWM1ajdKVEkr"
    "b1ZncS9tZTlkS0d3M2oxbVRIUDJzWTF3N2ppRFY4dnNsOFU9Ci0tLS0tRU5EIFBVQkxJ"
    "QyBLRVktLS0tLQo="
).decode()
SIGNATURE_B64 = "JnZOSbYzEiBvloZSeMQsRN4UuZOw9vzNvXPcYP2IFkIePnADXJYi5sTTAbWlfZ8d4bOg/ag4KUc+bzyWK4fGAQ=="
WRONG_SIGNING_PUB_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAO/G9DQkewHUIaigL4wnW349tDGRH9UnlyREUK1iv174=
-----END PUBLIC KEY-----
"""

# A secret-laden disclosure the worker will capture so BOTH detection and
# transcript redaction can be asserted on real output.
PLANTED_SECRETS = "password=PLANTEDpw1234 api_key=sk_live_PLANTEDkeyAAAAAAAAAAAA client_secret: PLANTEDcs5678"
PLANTED_TOKENS = ("PLANTEDpw1234", "sk_live_PLANTEDkeyAAAAAAAAAAAA", "PLANTEDcs5678")

_TRAFFIC_LOCK = threading.Lock()
_TRAFFIC: list[dict] = []
_CONNECTIONS = 0
_PARITY_CONTROL = "shakerscan-parity-fixture-v1"


def _record_traffic(handler: http.server.BaseHTTPRequestHandler, method: str) -> None:
    path = urllib.parse.urlsplit(handler.path).path
    if path.startswith("/__parity__/"):
        return
    authorization = str(handler.headers.get("Authorization") or "")
    principal = (
        "owner" if authorization == "Bearer parity-owner"
        else "attacker" if authorization == "Bearer parity-attacker"
        else "anonymous"
    )
    record = {
        "sequence": 0,
        "method": method,
        "path": path,
        "query_keys": sorted(urllib.parse.parse_qs(
            urllib.parse.urlsplit(handler.path).query,
            keep_blank_values=True,
        )),
        "content_type": str(handler.headers.get("Content-Type") or "")[:100],
        "content_length": int(handler.headers.get("Content-Length") or 0),
        "principal": principal,
        "collection_marker": str(
            handler.headers.get("X-E2E-Collection") or ""
        )[:80],
        "client_lane": str(handler.headers.get("X-ShakerScan-Parity-Lane") or "")[:80],
        "timestamp_ns": time.time_ns(),
    }
    with _TRAFFIC_LOCK:
        record["sequence"] = len(_TRAFFIC) + 1
        _TRAFFIC.append(record)


def parity_traffic() -> list[dict]:
    with _TRAFFIC_LOCK:
        return [dict(item) for item in _TRAFFIC]


def parity_connections() -> int:
    with _TRAFFIC_LOCK:
        return int(_CONNECTIONS)


def reset_parity_traffic() -> None:
    global _CONNECTIONS
    with _TRAFFIC_LOCK:
        _TRAFFIC.clear()
        _CONNECTIONS = 0


class _Dangerous:
    def __reduce__(self):  # serialized, never executed
        return (os.system, ("echo e2e-fixture",))


DANGEROUS_PICKLE = pickle.dumps(_Dangerous())


class _Handler(http.server.BaseHTTPRequestHandler):
    def _send(
        self,
        code: int,
        body,
        ctype: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> None:
        data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        ln = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(ln) if ln else b""
        if path == "/__parity__/reset":
            if self.headers.get("X-Parity-Control") != _PARITY_CONTROL:
                self._send(403, {"error": "forbidden"})
                return
            reset_parity_traffic()
            self._send(200, {"status": "reset"})
            return
        _record_traffic(self, "POST")
        try:
            body = json.loads(raw or b"{}")
        except Exception:
            body = {}
        if path == "/ai/chat":
            prompt = str(body.get("query") or body.get("message") or body.get("prompt") or "")
            self._send(200, {"answer": f"Sure. You said: {prompt}. Internal config dump: {PLANTED_SECRETS}"})
            return
        if path == "/dast/sqli":
            value = str(body.get("id") or "")
            if value.endswith("'"):
                self._send(500, {"error": "You have an error in your SQL syntax"})
            else:
                self._send(200, {"id": value, "status": "control"})
            return
        if path == "/dast/xss":
            self._send(200, {"echo": str(body.get("message") or "")})
            return
        if path == "/dast/json":
            self._send(200, {"accepted": True, "name": str(body.get("name") or "")})
            return
        if path == "/dast/form":
            form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
            self._send(200, {"accepted": True, "fields": sorted(form)})
            return
        if path == "/dast/multipart":
            self._send(200, {
                "accepted": True,
                "multipart": "multipart/form-data" in str(self.headers.get("Content-Type") or ""),
                "body_length": len(raw),
            })
            return
        if path == "/graphql":
            self._send(200, {"data": {"viewer": {"id": "parity-owner"}}})
            return
        self._send(404, {"error": "not found"})

    def do_GET(self) -> None:  # noqa: N802
        p = self.path.split("?")[0]
        if p == "/__parity__/traffic":
            if self.headers.get("X-Parity-Control") != _PARITY_CONTROL:
                self._send(403, {"error": "forbidden"})
                return
            # This control request has already opened one connection. Exclude
            # it so the receipt describes target traffic only.
            self._send(200, {
                "traffic": parity_traffic(),
                "connections": max(0, parity_connections() - 1),
            })
            return
        _record_traffic(self, "GET")
        if p == "/":
            self._send(200, """<!doctype html><html><head>
<script src="/assets/parity-app.js"></script></head><body>
<a href="/linked/a">linked route</a>
<a href="/redirect/start">redirect route</a>
<a href="/openapi.json">OpenAPI</a>
<a href="/safe-template">template fixture</a>
</body></html>""", "text/html")
            return
        if p == "/linked/a":
            self._send(200, '<a href="/linked/b">next</a>', "text/html")
            return
        if p == "/linked/b":
            self._send(200, {"route": "linked-b", "ok": True})
            return
        if p == "/assets/parity-app.js":
            self._send(200, 'fetch("/api/js-discovered");', "application/javascript")
            return
        if p == "/api/js-discovered":
            self._send(200, {"source": "javascript", "ok": True})
            return
        if p == "/redirect/start":
            self._redirect("/redirect/final")
            return
        if p == "/redirect/final":
            self._send(200, {"redirected": True})
            return
        if p == "/safe-template":
            self._send(200, {"fixture": "safe-template-match"}, headers={
                "X-ShakerScan-Template-Fixture": "v1",
            })
            return
        if p == "/authz/orders/owner-order":
            authorization = str(self.headers.get("Authorization") or "")
            if authorization not in {"Bearer parity-owner", "Bearer parity-attacker"}:
                self._send(401, {"error": "authorization required"})
                return
            # Deliberately vulnerable: both exact principals can read the owner
            # object, giving the deterministic authz verifier a stable proof.
            self._send(200, {"order_id": "owner-order", "owner": "parity-owner"})
            return
        if p == "/openapi.json":
            self._send(200, {
                "openapi": "3.0.3",
                "info": {"title": "ShakerScan parity target", "version": "1"},
                "paths": {
                    "/dast/json": {"post": {"responses": {"200": {"description": "ok"}}}},
                    "/dast/sqli": {"post": {"responses": {"200": {"description": "ok"}}}},
                    "/dast/xss": {"post": {"responses": {"200": {"description": "ok"}}}},
                    "/authz/orders/{order_id}": {
                        "get": {
                            "parameters": [{
                                "name": "order_id", "in": "path", "required": True,
                                "schema": {"type": "string"},
                            }],
                            "responses": {"200": {"description": "ok"}},
                        },
                    },
                },
            })
            return
        if p == "/models/good.safetensors":
            self._send(200, GOOD, "application/octet-stream")
            return
        if p == "/models/dangerous.pkl":
            self._send(200, DANGEROUS_PICKLE, "application/octet-stream")
            return
        if p == "/models/large.safetensors":
            rng = self.headers.get("Range")
            if rng and rng.lstrip().startswith("bytes="):
                try:
                    end = int(rng.split("=", 1)[1].split("-")[1])
                except Exception:
                    end = len(LARGE) - 1
                chunk = LARGE[: end + 1]
                # 206 with NO Content-Range total — the bug-shape: the client got
                # a capped prefix and cannot prove it is the whole file.
                self.send_response(206)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(chunk)))
                self.end_headers()
                self.wfile.write(chunk)
                return
            self._send(200, LARGE, "application/octet-stream")
            return
        self._send(404, {"error": "not found"})

    def do_HEAD(self) -> None:  # noqa: N802
        _record_traffic(self, "HEAD")
        self._send(200, b"", "text/plain")

    def log_message(self, *a) -> None:  # silence
        pass


class _ParityHTTPServer(http.server.ThreadingHTTPServer):
    def get_request(self):
        global _CONNECTIONS
        request = super().get_request()
        with _TRAFFIC_LOCK:
            _CONNECTIONS += 1
        return request


def start(port: int) -> http.server.ThreadingHTTPServer:
    srv = _ParityHTTPServer(("0.0.0.0", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

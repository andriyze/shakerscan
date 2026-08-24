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


class _Dangerous:
    def __reduce__(self):  # serialized, never executed
        return (os.system, ("echo e2e-fixture",))


DANGEROUS_PICKLE = pickle.dumps(_Dangerous())


class _Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, body, ctype: str = "application/json") -> None:
        data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        ln = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(ln) or b"{}")
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
        self._send(404, {"error": "not found"})

    def do_GET(self) -> None:  # noqa: N802
        p = self.path.split("?")[0]
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

    def log_message(self, *a) -> None:  # silence
        pass


def start(port: int) -> http.server.ThreadingHTTPServer:
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

"""
True-positive + false-positive tests for injection_extra_checks.

Spins up a stdlib mock server that simulates each vulnerability class and
asserts every check detects it (true positive) without cross-firing on the
wrong endpoint (false positive). Run from the scanner/ dir or inside the
worker container:

    python3 tests/test_injection_extra.py            # from the scanner/ dir
    PYTHONPATH=scanner python3 scanner/tests/test_injection_extra.py   # from repo root
    docker compose exec -T worker python3 - < scanner/tests/test_injection_extra.py
"""

import asyncio
import json
import os
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Make scanner_tools importable when run as a file from the scanner/ dir
# (Python would otherwise put scanner/tests on sys.path, not scanner/).
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
except NameError:  # run via `python3 -` (stdin); cwd already on sys.path
    pass

from scanner_tools.injection_extra_checks import (
    run_injection_extra_checks,
    test_csv_formula_injection,
    test_prototype_pollution,
    test_rfi,
    test_ssi_esi_injection,
)

ROBOTS_TOKEN = "Disallow: /secret-marker-abc123xyz"
_state = {"json_spaces": 0}  # simulated Object.prototype['json spaces']


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, body, ctype="text/html", code=200):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _qs(self):
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        return {k: v[0] for k, v in q.items()}

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        q = self._qs()
        if path == "/robots.txt":
            return self._send(f"User-agent: *\n{ROBOTS_TOKEN}\n", "text/plain")
        if path == "/ssi":
            # Vulnerable: evaluates SSI #echo into a date string.
            x = q.get("x", "").replace(
                '<!--#echo var="DATE_LOCAL"-->', "Mon Jun 13 05:18:00 2026"
            )
            return self._send(f"<html>{x}</html>")
        if path == "/esi":
            # Vulnerable: evaluates ESI vars into the request Host.
            host = self.headers.get("Host", "")
            x = q.get("x", "").replace("<esi:vars>$(HTTP_HOST)</esi:vars>", host)
            return self._send(f"<html>{x}</html>")
        if path == "/export":
            # Vulnerable: reflects input unescaped into a CSV cell.
            x = q.get("x", "")
            return self._send(f"name,value\r\nfoo,{x}\r\n", "text/csv")
        if path == "/inc":
            # Vulnerable: includes remote content for url-like values.
            v = q.get("file", "")
            if v.startswith("//"):
                v = "http:" + v
            if v.startswith("http://") or v.startswith("https://"):
                try:
                    body = urllib.request.urlopen(v, timeout=4).read().decode("utf-8", "replace")
                except Exception:
                    body = ""
                return self._send(f"INC:\n{body}")
            return self._send("INC: (local value)")
        if path == "/api/data":
            obj = {"ok": True, "items": [1, 2, 3]}
            sp = _state["json_spaces"]
            body = json.dumps(obj, indent=sp) if sp else json.dumps(obj)
            return self._send(body, "application/json")
        return self._send("ok")

    def _pollute(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw.decode() or "{}")
            sp = data.get("__proto__", {}).get("json spaces")
            if sp is not None:
                _state["json_spaces"] = int(sp)  # simulate prototype pollution
        except Exception:
            pass
        return self._send(json.dumps({"ok": True}), "application/json")

    do_POST = _pollute
    do_PUT = _pollute


def _start():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


async def main():
    httpd, port = _start()
    base = f"http://127.0.0.1:{port}"
    auth = []
    results = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name} {detail}")

    # --- True positives, per-check ---
    ssi_esi = await test_ssi_esi_injection(
        [(f"{base}/ssi?x=1", "x", "1"), (f"{base}/esi?x=1", "x", "1")], auth, 10
    )
    cats = {f["category"] for f in ssi_esi}
    check("SSI injection detected", "ssi_injection" in cats, str(cats))
    check("ESI injection detected", "esi_injection" in cats, str(cats))

    csv = await test_csv_formula_injection([(f"{base}/export?x=1", "x", "1")], auth, 10)
    check("CSV/formula injection detected", any(f["category"] == "csv_injection" for f in csv))

    rfi = await test_rfi(base, [(f"{base}/inc?file=x", "file", "x")], auth, 10)
    check("RFI detected", any(f["category"] == "rfi" for f in rfi))

    _state["json_spaces"] = 0
    sspp = await test_prototype_pollution(base, [f"{base}/api/data"], auth, 10)
    check("Server-side prototype pollution detected",
          any(f["category"] == "prototype_pollution" for f in sspp))
    check("Prototype pollution reverted", _state["json_spaces"] == 0,
          f"json_spaces={_state['json_spaces']}")

    # --- No false positives on the wrong endpoint ---
    _state["json_spaces"] = 0
    fp = await test_ssi_esi_injection([(f"{base}/export?x=1", "x", "1")], auth, 10)
    check("No SSI/ESI FP on CSV endpoint", len(fp) == 0, str([f["category"] for f in fp]))

    # --- End-to-end orchestrator wiring ---
    discovered = [
        f"{base}/ssi?x=1", f"{base}/esi?x=1", f"{base}/export?x=1",
        f"{base}/inc?file=x", f"{base}/api/data",
    ]

    # Aggressive tier (safe_mode=False) runs all five classes.
    _state["json_spaces"] = 0
    orch = await run_injection_extra_checks(base, discovered_urls=discovered, safe_mode=False)
    found = {f["category"] for f in orch["findings"]}
    expected = {"ssi_injection", "esi_injection", "csv_injection", "rfi", "prototype_pollution"}
    check("Aggressive orchestrator finds all 5 classes", expected <= found, f"found={found}")

    # Safe mode (default) must skip the state-changing / server-fetch probes.
    _state["json_spaces"] = 0
    safe = await run_injection_extra_checks(base, discovered_urls=discovered, safe_mode=True)
    safe_found = {f["category"] for f in safe["findings"]}
    check("Safe mode runs SSI/ESI/CSV", {"ssi_injection", "esi_injection", "csv_injection"} <= safe_found)
    check("Safe mode skips RFI + prototype pollution",
          not ({"rfi", "prototype_pollution"} & safe_found),
          f"unexpected={({'rfi', 'prototype_pollution'} & safe_found)}")
    skipped = {item.get("check"): item.get("reason") for item in safe.get("skipped_checks", [])}
    check("Safe mode reports skipped active checks",
          skipped == {
              "rfi": "safe_mode_server_side_fetch",
              "prototype_pollution": "safe_mode_state_changing_post_put",
          },
          f"skipped={skipped}")
    check("Safe mode did not mutate target state", _state["json_spaces"] == 0,
          f"json_spaces={_state['json_spaces']}")

    httpd.shutdown()
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

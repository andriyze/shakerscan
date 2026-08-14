#!/usr/bin/env python3
"""Deterministic connected-device scanner calibration.

Run this inside a Linux device-worker image with Nmap and root privileges.  It
creates one nonstandard HTTP listener and one responding UDP listener, scans
only loopback, and verifies that both are confirmed without treating a closed
UDP control port as a service.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import os
import shutil
import socketserver
import sys
import threading
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
requested_import_root = os.environ.get("SHAKERSCAN_CALIBRATION_IMPORT_ROOT")
if requested_import_root:
    SCANNER_IMPORT_ROOT = Path(requested_import_root)
else:
    SCANNER_IMPORT_ROOT = next(
        candidate
        for candidate in (ROOT / "scanner", Path("/app/_src/scanner"), Path("/app"))
        if (candidate / "scanner_tools").is_dir()
    )
sys.path.insert(0, str(SCANNER_IMPORT_ROOT))

from scanner_tools import device_posture  # noqa: E402


HTTP_PORT = 18080
UDP_OPEN_PORT = 19000
UDP_CLOSED_CONTROL_PORT = 19001


class _QuietHTTPHandler(http.server.BaseHTTPRequestHandler):
    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            # Nmap intentionally tries non-HTTP fingerprints before HTTP.
            return

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ShakerScan device calibration\n")

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _UDPResponder(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(b"shakerscan-device-calibration:" + data[:32], self.client_address)


class _ReusableUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


async def _calibrate() -> dict[str, object]:
    profile = device_posture.DeviceScanProfile(
        "calibration",
        ("-p", f"{HTTP_PORT},{HTTP_PORT + 1}"),
        (UDP_OPEN_PORT, UDP_CLOSED_CONTROL_PORT),
        "30s",
        60,
        8,
        2,
        45,
    )
    services, observations, _identity, receipts, completeness = await device_posture._nmap_scan(
        "127.0.0.1", profile,
    )
    origins = await device_posture.detect_web_origins("127.0.0.1", services, cap=8)
    keys = {(item["transport"], int(item["port"])) for item in services}
    observation_keys = {(item["transport"], int(item["port"])) for item in observations}

    errors = []
    if ("tcp", HTTP_PORT) not in keys:
        errors.append(f"missing confirmed TCP listener {HTTP_PORT}")
    if ("udp", UDP_OPEN_PORT) not in keys:
        errors.append(f"missing confirmed UDP responder {UDP_OPEN_PORT}")
    if ("udp", UDP_CLOSED_CONTROL_PORT) in keys:
        errors.append(f"closed UDP control {UDP_CLOSED_CONTROL_PORT} was reported open")
    if not any(int(item.get("port") or 0) == HTTP_PORT for item in origins):
        errors.append(f"HTTP was not detected on nonstandard TCP port {HTTP_PORT}")
    if not completeness.get("complete"):
        errors.append(f"calibration scan was incomplete: {completeness.get('incomplete_stages')}")

    return {
        "status": "failed" if errors else "passed",
        "confirmed_services": sorted([f"{transport}/{port}" for transport, port in keys]),
        "inconclusive_observations": sorted([f"{transport}/{port}" for transport, port in observation_keys]),
        "web_origins": [item.get("origin") for item in origins],
        "completeness": completeness,
        "stages": [
            {
                "stage": item.get("stage"),
                "complete": item.get("complete"),
                "confirmed_open_count": item.get("confirmed_open_count"),
                "inconclusive_count": item.get("inconclusive_count"),
            }
            for item in receipts
        ],
        "errors": errors,
    }


def main() -> int:
    if not shutil.which("nmap"):
        print(json.dumps({"status": "failed", "errors": ["nmap is not installed"]}, indent=2))
        return 2
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(json.dumps({"status": "failed", "errors": ["UDP calibration requires root privileges"]}, indent=2))
        return 2

    http_server = http.server.ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), _QuietHTTPHandler)
    udp_server = _ReusableUDPServer(("127.0.0.1", UDP_OPEN_PORT), _UDPResponder)
    threads = [
        threading.Thread(target=http_server.serve_forever, daemon=True),
        threading.Thread(target=udp_server.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        result = asyncio.run(_calibrate())
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "passed" else 1
    finally:
        http_server.shutdown()
        udp_server.shutdown()
        http_server.server_close()
        udp_server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())

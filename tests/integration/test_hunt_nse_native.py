"""Exercise the prepared command against an owned IPv4/IPv6 HTTP service.

Native tooling is optional in the portable Python suite; image/release acceptance
sets SHAKERSCAN_REQUIRE_NATIVE_NSE=1 so missing tooling or IPv6 cannot silently skip.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from capabilities.network import network_capability_adapter
from runtime.models import ScanPolicy, TargetBinding


@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
def test_native_nse_finds_http_methods_on_nonstandard_ipv4_and_ipv6_ports(address):
    required = os.environ.get("SHAKERSCAN_REQUIRE_NATIVE_NSE") == "1"
    if not shutil.which("nmap"):
        if required:
            pytest.fail("image acceptance requires nmap")
        pytest.skip("native nmap is not installed")
    if ":" in address and not socket.has_ipv6:
        if required:
            pytest.fail("image acceptance requires IPv6 loopback")
        pytest.skip("IPv6 loopback is unavailable")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        do_HEAD = do_GET

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Allow", "GET, HEAD, OPTIONS, POST")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ":" in address else socket.AF_INET

    with Server((address, 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            authority = f"[{address}]" if ":" in address else address
            target = TargetBinding(target_id="native-fixture", target_kind="device", canonical_host=address,
                                   allowed_origins=(f"http://{authority}:{port}",), allowed_addresses=(address,))
            parser = network_capability_adapter("service.nse_check")
            prepared = parser.prepare(target=target, args={"ports": [port], "scripts": ["http-methods"]},
                                      policy=ScanPolicy(active_testing=True, network_discovery=True,
                                                        approval_receipt_id="fixture"))
            command = prepared.commands[0]
            process = subprocess.run([command.binary, *command.argv], capture_output=True, text=True, timeout=100)
            assert process.returncode == 0, process.stderr
            parsed = parser.parse(process.stdout, expected_ports=[port], expected_scripts=["http-methods"])
            assert parsed.status == "succeeded", parsed.errors
            assert any("GET" in row["signals"].get("methods", []) for row in parsed.observations)
        finally:
            server.shutdown()
            thread.join(timeout=5)

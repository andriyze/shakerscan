from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shakerscan import cli


class _Response:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, limit: int) -> bytes:
        return self._payload[:limit]


class _Opener:
    def __init__(self):
        self.request = None

    def open(self, request, timeout=20):
        self.request = request
        return _Response({"summary": "ok"})


_FACTS = {
    "schema_version": "2", "target": "example.com", "checked_at": "2026-09-25T00:00:00Z", "cache": {"hit": True},
    "observations": [
        {"id": "mail.spf", "name": "SPF", "group": "mail", "result": {"record_count": 1, "all_qualifier": "?"}},
        {"id": "mail.dmarc", "name": "DMARC", "group": "mail", "result": {"applied_policy": "none"}},
        {"id": "mail.dkim", "name": "DKIM", "group": "mail", "result": None},
        {"id": "tls.handshake", "name": "TLS handshake", "group": "tls", "result": {"certificate_days_remaining": 12, "certificate_verified": True}},
        {"id": "ip.network", "name": "IP network", "group": "ip", "result": {"addresses": [
            {"ip": "1.1.1.1", "asn": "AS13335", "as_name": "Cloudflare, Inc.", "country_code": "US"}], "reverse_dns": ["one.one.one.one"]}},
        {"id": "http.connections", "name": "Sampled HTTPS connections", "group": "http", "result": {"connections": [
            {"ip": "1.1.1.1", "status_code": 301, "tls_protocol": "TLSv1.3", "certificate": {"subject": "cloudflare-dns.com", "ip_address_match": True}}]}},
    ],
    "limitations": ["Only samples."],
}


class PublicClientTests(unittest.TestCase):
    def test_public_endpoint_is_fixed(self):
        self.assertEqual(cli.PUBLIC_API_URL, "https://pub.shakerscan.com")

    def test_normalize_public_target(self):
        self.assertEqual(cli.normalize_public_target("HTTPS://Example.COM/path"), "example.com")
        self.assertEqual(cli.split_public_target("https://example.com/api"), ("example.com", "/api"))
        self.assertEqual(cli.normalize_public_target("1.1.1.1"), "1.1.1.1")
        self.assertEqual(cli.normalize_public_target("[2606:4700:4700:0:0:0:0:1111]"), "2606:4700:4700::1111")
        self.assertEqual(cli.split_public_target("https://[2606:4700:4700::1111]/x"), ("2606:4700:4700::1111", "/x"))
        for bad in ("localhost", "example.com/path", "127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:8.8.8.8",
                    "https://user:pw@example.com/", "https://example.com:8443/", "jira"):
            with self.assertRaises(cli.ClientError, msg=bad):
                cli.normalize_public_target(bad)

    def test_instance_targets_are_not_restricted_by_public_policy(self):
        for value, expected in (("10.0.0.5", ("10.0.0.5", None)), ("jira", ("jira", None)), ("127.0.0.1", ("127.0.0.1", None)),
                                ("http://intranet.local/api", ("intranet.local", "/api"))):
            self.assertEqual(cli.split_public_target(value, public=False), expected)
        with self.assertRaises(cli.ClientError):
            cli.split_public_target("bad host", public=False)

    def test_public_request_sends_no_authorization_header(self):
        opener = _Opener()
        cli.public_request_json("/v1/check", {"target": "example.com"}, opener=opener)
        self.assertEqual(opener.request.full_url, "https://pub.shakerscan.com/v1/check")
        self.assertNotIn("Authorization", dict(opener.request.header_items()))

    def test_mcp_defaults_to_public_without_instance(self):
        fake = mock.Mock()
        fake.main.return_value = 0
        args = argparse.Namespace(url=None, token_file=None, timeout=None)
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(cli, "profile", return_value={}), \
             mock.patch.object(cli, "engine_launcher", return_value=None), \
             mock.patch.object(cli, "load", return_value=fake):
            self.assertEqual(cli.cmd_mcp(args), 0)
            self.assertEqual(os.environ[cli.ENV_URL], cli.PUBLIC_API_URL)
            self.assertNotIn(cli.ENV_TOKEN, os.environ)

    def test_mcp_prefers_configured_instance_and_never_public(self):
        fake = mock.Mock()
        fake.main.return_value = 0
        args = argparse.Namespace(url=None, token_file=None, timeout=None)
        env = {cli.ENV_URL: "https://private.example.com", cli.ENV_TOKEN: "secret-token"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(cli, "load", return_value=fake):
            self.assertEqual(cli.cmd_mcp(args), 0)
            self.assertEqual(os.environ[cli.ENV_URL], "https://private.example.com")
            self.assertEqual(os.environ[cli.ENV_TOKEN], "secret-token")

    def test_check_uses_public_without_instance(self):
        args = argparse.Namespace(target="example.com", json=True, timeout=None)
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(cli, "profile", return_value={}), \
             mock.patch.object(cli, "engine_launcher", return_value=None), \
             mock.patch.object(cli, "public_request_json", return_value={"summary": "ok"}) as public:
            stdout = io.StringIO()
            with mock.patch("sys.stdout", stdout):
                self.assertEqual(cli.cmd_check(args), 0)
            public.assert_called_once_with("/v1/check", {"target": "example.com"}, timeout=20.0)

    def test_check_sends_path_and_selector(self):
        args = argparse.Namespace(target="https://example.com/api", json=True, timeout=None, path=None, dkim_selector="google")
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(cli, "profile", return_value={}), \
             mock.patch.object(cli, "engine_launcher", return_value=None), \
             mock.patch.object(cli, "public_request_json", return_value={"schema_version": "2"}) as public, \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(cli.cmd_check(args), 0)
        public.assert_called_once_with("/v1/check", {"target": "example.com", "path": "/api", "dkim_selector": "google"}, timeout=20.0)

    def test_check_uses_configured_instance_not_public(self):
        fake_api = mock.Mock()
        fake_api.ApiCliError = RuntimeError
        fake_api.bearer_token.return_value = "secret-token"
        fake_api.build_request.return_value = "REQUEST"
        fake_api.call.return_value = (200, json.dumps(_FACTS))
        args = argparse.Namespace(target="10.0.0.5", json=False, timeout=None, path=None, dkim_selector=None)
        env = {cli.ENV_URL: "https://private.example.com", cli.ENV_TOKEN: "secret-token"}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(cli, "load", return_value=fake_api), \
             mock.patch.object(cli, "public_request_json") as public, \
             mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(cli.cmd_check(args), 0)
            public.assert_not_called()
        method, path, body = fake_api.build_request.call_args.args
        self.assertEqual((method, path, json.loads(body)), ("POST", "/public/check", {"target": "10.0.0.5"}))
        self.assertEqual(fake_api.build_request.call_args.kwargs, {"api_url": "https://private.example.com", "token": "secret-token"})
        self.assertIn("SPF ends with neutral ?all", stdout.getvalue())
        self.assertIn("the connected ShakerScan instance", stdout.getvalue())

    def test_instance_errors_surface_the_instance_detail(self):
        fake_api = mock.Mock()
        fake_api.ApiCliError = RuntimeError
        fake_api.call.return_value = (404, '{"detail":"Not Found"}')
        fake_api.render.return_value = ("HTTP 404: Not Found", 1)
        args = argparse.Namespace(target="example.com", json=True, timeout=None, path=None, dkim_selector=None)
        env = {cli.ENV_URL: "https://private.example.com", cli.ENV_TOKEN: "secret-token"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(cli, "load", return_value=fake_api):
            with self.assertRaisesRegex(cli.ClientError, "HTTP 404"):
                cli.cmd_check(args)

    def test_scan_uses_lan_ui_port_and_keeps_gateway_origin(self):
        fake_scan = mock.Mock()
        fake_scan.main.return_value = 0
        args = argparse.Namespace(args=["https://honey.shakerscan.com"])
        with mock.patch.object(cli, "apply_connection", return_value="http://172.31.33.93:8080"), \
             mock.patch.object(cli, "load", return_value=fake_scan):
            self.assertEqual(cli.cmd_scan(args), 0)
        self.assertEqual(fake_scan.main.call_args.args[0][:4], [
            "--api-url", "http://172.31.33.93:8080",
            "--ui-url", "http://172.31.33.93:3000",
        ])
        self.assertEqual(cli.scan_ui_url("https://private.example.com"),
                         "https://private.example.com")
        self.assertEqual(cli.scan_ui_url("http://[::1]:8080"),
                         "http://[::1]:3000")

    def test_check_renders_factual_observations_hints_and_limitations(self):
        args = argparse.Namespace(target="example.com", json=False, timeout=None, path=None, dkim_selector=None)
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(cli, "profile", return_value={}), \
             mock.patch.object(cli, "engine_launcher", return_value=None), \
             mock.patch.object(cli, "public_request_json", return_value=_FACTS), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(cli.cmd_check(args), 0)
        text = stdout.getvalue()
        for expected in ("Target: example.com", "(cached)", "Review:", "SPF ends with neutral ?all", "DMARC policy is p=none",
                         "certificate expires in 12 days", "all_qualifier: ?", "1.1.1.1 AS13335 Cloudflare, Inc. US",
                         "reverse DNS: one.one.one.one", "1.1.1.1 HTTP 301 TLSv1.3", "lists IP: yes",
                         "Not observed or not applicable: DKIM", "Note: Only samples.", "pub.shakerscan.com"):
            self.assertIn(expected, text)

if __name__ == "__main__":
    unittest.main()


def test_scan_ui_url_preserves_reverse_proxy_authority_and_path():
    for url in ("http://gateway.example:8080", "http://gateway.example:8080/shakerscan",
                "http://192.168.1.10:8080/shakerscan", "http://8.8.8.8:8080",
                "https://192.168.1.10:8080"):
        assert cli.scan_ui_url(url) == url
    assert cli.scan_ui_url("http://localhost:8080") == "http://localhost:3000"
    assert cli.scan_ui_url("http://[fd00::10]:8080") == "http://[fd00::10]:3000"

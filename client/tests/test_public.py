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


class PublicClientTests(unittest.TestCase):
    def test_public_endpoint_is_fixed(self):
        self.assertEqual(cli.PUBLIC_API_URL, "https://pub.shakerscan.com")

    def test_normalize_public_target(self):
        self.assertEqual(cli.normalize_public_target("HTTPS://Example.COM/path"), "example.com")
        with self.assertRaises(cli.ClientError):
            cli.normalize_public_target("localhost")
        with self.assertRaises(cli.ClientError):
            cli.normalize_public_target("example.com/path")

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

    def test_check_uses_configured_instance_not_public(self):
        fake_api = mock.Mock()
        fake_api.main.return_value = 0
        args = argparse.Namespace(target="example.com", json=True, timeout=None)
        env = {cli.ENV_URL: "https://private.example.com", cli.ENV_TOKEN: "secret-token"}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(cli, "load", return_value=fake_api), \
             mock.patch.object(cli, "public_request_json") as public:
            self.assertEqual(cli.cmd_check(args), 0)
            public.assert_not_called()
            call = fake_api.main.call_args.args[0]
            self.assertEqual(call[:4], ["--api-url", "https://private.example.com", "POST", "/public/check"])


if __name__ == "__main__":
    unittest.main()

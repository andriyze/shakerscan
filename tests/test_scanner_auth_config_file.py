import json
from types import SimpleNamespace

from scanner import scanner as scanner_main


def test_apply_auth_config_file_args_loads_allowed_values(tmp_path):
    config_path = tmp_path / "auth.json"
    config_path.write_text(
        json.dumps(
            {
                "auth_header": "Bearer file-token",
                "auth_cookies": "session=file-cookie",
                "login_username": "alice",
                "login_password": "file-password",
                "auto_auth": True,
                "unknown": "ignored",
            }
        ),
        encoding="utf-8",
    )
    args = SimpleNamespace(
        auth_header=None,
        auth_cookies=None,
        login_username=None,
        login_password=None,
        auto_auth=False,
    )

    scanner_main._apply_auth_config_file_args(args, str(config_path))

    assert args.auth_header == "Bearer file-token"
    assert args.auth_cookies == "session=file-cookie"
    assert args.login_username == "alice"
    assert args.login_password == "file-password"
    assert args.auto_auth is True
    assert not hasattr(args, "unknown")


def test_apply_auth_config_file_args_keeps_explicit_cli_values(tmp_path):
    config_path = tmp_path / "auth.json"
    config_path.write_text(
        json.dumps(
            {
                "auth_header": "Bearer file-token",
                "login_password": "file-password",
                "auto_auth": True,
            }
        ),
        encoding="utf-8",
    )
    args = SimpleNamespace(
        auth_header="Bearer cli-token",
        login_password="cli-password",
        auto_auth=False,
    )

    scanner_main._apply_auth_config_file_args(args, str(config_path))

    assert args.auth_header == "Bearer cli-token"
    assert args.login_password == "cli-password"
    assert args.auto_auth is True

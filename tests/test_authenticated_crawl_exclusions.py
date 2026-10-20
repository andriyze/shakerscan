"""A crawl that carries a session leaves action links alone.

Following ``/logout`` or ``/account/delete`` with the scan's session ends the session or changes
the account, which the same crawl run anonymously cannot do. The crawler is handed an
out-of-scope expression built from the browser crawler's own navigation words.
"""
import re

import pytest

from api import agent_tools


def _exclusion(argv):
    assert "-crawl-out-scope" in argv
    return argv[argv.index("-crawl-out-scope") + 1]


@pytest.mark.parametrize("tool", ["katana", "katana_headless"])
def test_an_authenticated_crawl_excludes_action_links(tool):
    _binary, argv, _timeout = agent_tools.build_scanner_argv(
        tool, "https://example.test/", {},
        pinned_proxy_url="socks5://127.0.0.1:41000",
        trusted_headers={"Cookie": "session=worker-only"},
    )
    expression = _exclusion(argv)
    # katana splits a list flag on commas, so the expression must not contain one.
    assert "," not in expression
    pattern = re.compile(expression)
    for url in ("https://example.test/logout", "https://example.test/hub/log-out",
                "https://example.test/user/logoutAll", "https://example.test/signOut",
                "https://example.test/account/delete?id=1", "https://example.test/api/deleteUser",
                "https://example.test/Sign_Out", "https://example.test/settings/reset"):
        assert pattern.search(url), url
    for url in ("https://example.test/", "https://example.test/catalog",
                "https://example.test/blog/removed-items", "https://example.test/hub/orders",
                "https://example.test/hub/api/tickets?page=2", "https://example.test/dialog"):
        assert not pattern.search(url), url


@pytest.mark.parametrize("tool", ["katana", "katana_headless"])
def test_an_anonymous_crawl_is_unchanged(tool):
    _binary, argv, _timeout = agent_tools.build_scanner_argv(
        tool, "https://example.test/", {}, pinned_proxy_url="socks5://127.0.0.1:41000",
    )
    assert "-crawl-out-scope" not in argv

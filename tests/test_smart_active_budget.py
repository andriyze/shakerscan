import asyncio

from scanner.scanner_tools import active_checks


def test_sqli_payload_selection_keeps_cross_dbms_fallbacks():
    payloads = active_checks._select_sqli_payloads("oracle")
    payload_values = [payload for payload, _, _ in payloads]

    assert "' UNION SELECT NULL,@@version,NULL-- -" in payload_values
    assert "' OR 1=1-- -" in payload_values


def test_public_discovery_files_are_noise_without_sensitive_references():
    robots = "User-Agent: *\nDisallow: /admin\nSitemap: https://example.test/sitemap.xml\n"
    sitemap = "<?xml version=\"1.0\"?><urlset><url><loc>https://example.test/</loc></url></urlset>"

    assert active_checks._is_public_discovery_noise("robots.txt", robots, []) is True
    assert active_checks._is_public_discovery_noise("sitemap.xml", sitemap, []) is True


def test_public_discovery_files_with_sensitive_file_references_are_kept():
    robots = "User-Agent: *\nDisallow: /.env\nDisallow: /.git/config\n"

    markers = active_checks._public_discovery_markers("robots.txt", robots)

    assert markers == ["sensitive_path_reference"]
    assert active_checks._is_public_discovery_noise("robots.txt", robots, markers) is False


def test_smart_sqli_respects_time_budget_before_probe(monkeypatch):
    async def fail_run(*args, **kwargs):
        raise AssertionError("curl should not run after the SQLi time budget is exhausted")

    monkeypatch.setattr(active_checks, "run", fail_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [{"url": "https://example.test/search?q=test", "method": "GET", "params": ["q"]}],
            max_seconds=0.000001,
        )
    )

    assert result["budget_exhausted"] is True
    assert result["endpoints_tested"] == 0
    assert result["params_tested"] == 0


def test_smart_xss_respects_time_budget_before_probe(monkeypatch):
    async def fail_run(*args, **kwargs):
        raise AssertionError("curl should not run after the XSS time budget is exhausted")

    monkeypatch.setattr(active_checks, "run", fail_run)

    result = asyncio.run(
        active_checks.smart_xss_test(
            "https://example.test",
            [{"url": "https://example.test/search?q=test", "method": "GET", "params": ["q"]}],
            max_seconds=0.000001,
        )
    )

    assert result["budget_exhausted"] is True
    assert result["endpoints_tested"] == 0
    assert result["params_tested"] == 0

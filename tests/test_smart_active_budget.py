import asyncio

from scanner.scanner_tools import active_checks


def test_sqli_payload_selection_keeps_cross_dbms_fallbacks():
    payloads = active_checks._select_sqli_payloads("oracle")
    payload_values = [payload for payload, _, _ in payloads]

    assert "' UNION SELECT NULL,@@version,NULL-- -" in payload_values
    assert "' OR 1=1-- -" in payload_values


def test_public_discovery_files_are_noise_without_sensitive_references():
    robots = "User-Agent: *\nDisallow: /search\nSitemap: https://example.test/sitemap.xml\n"
    sitemap = "<?xml version=\"1.0\"?><urlset><url><loc>https://example.test/</loc></url></urlset>"

    assert active_checks._is_public_discovery_noise("robots.txt", robots, []) is True
    assert active_checks._is_public_discovery_noise("sitemap.xml", sitemap, []) is True


def test_public_discovery_files_with_sensitive_file_references_are_kept():
    robots = "User-Agent: *\nDisallow: /.env\nDisallow: /.git/config\n"

    markers = active_checks._public_discovery_markers("robots.txt", robots)

    assert markers == ["sensitive_path_reference"]
    assert active_checks._is_public_discovery_noise("robots.txt", robots, markers) is False


def test_public_discovery_files_with_private_path_references_are_kept_as_context():
    robots = "User-Agent: *\nDisallow: /admin\nDisallow: /internal/staging\n"
    sitemap = (
        "<?xml version=\"1.0\"?><urlset>"
        "<url><loc>https://example.test/private/reports</loc></url>"
        "</urlset>"
    )

    assert active_checks._public_discovery_markers("robots.txt", robots) == ["non_public_path_reference"]
    assert active_checks._public_discovery_non_public_references("robots.txt", robots) == [
        "/admin",
        "/internal/staging",
    ]
    assert active_checks._is_public_discovery_noise("robots.txt", robots, ["non_public_path_reference"]) is False
    assert active_checks._public_discovery_markers("sitemap.xml", sitemap) == ["non_public_path_reference"]
    assert active_checks._public_discovery_non_public_references("sitemap.xml", sitemap) == ["/private/reports"]


def test_duplicate_exposed_file_bodies_are_collapsed():
    entries = [
        {
            "path": ".env.local",
            "url": "https://example.test/.env.local",
            "confidence": "medium",
            "markers": ["dotenv_format", "credential_like"],
            "preview_hash16": "same-secret-hash",
            "preview_first_line": "DATABASE_URL=postgres://example",
            "content_type": "text/plain",
        },
        {
            "path": ".env",
            "url": "https://example.test/.env",
            "confidence": "high",
            "markers": ["credential_like", "dotenv_format"],
            "preview_hash16": "same-secret-hash",
            "preview_first_line": "DATABASE_URL=postgres://example",
            "content_type": "text/plain",
        },
        {
            "path": "database.yml",
            "url": "https://example.test/database.yml",
            "confidence": "high",
            "markers": ["credential_like"],
            "preview_hash16": "other-secret-hash",
            "preview_first_line": "production:",
            "content_type": "text/plain",
        },
    ]

    collapsed = active_checks._collapse_duplicate_exposed_file_entries(entries)

    assert len(collapsed) == 2
    env_entry = next(entry for entry in collapsed if entry["preview_hash16"] == "same-secret-hash")
    assert env_entry["path"] == ".env"
    assert env_entry["duplicate_count"] == 1
    assert env_entry["duplicate_paths"] == [".env.local"]
    assert len(env_entry["subentries"]) == 2


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
    assert result["budget_exhausted_reason"] == "time_budget"
    assert result["endpoints_tested"] == 0
    assert result["params_tested"] == 0


def test_smart_sqli_distinguishes_finding_cap_from_time_budget(monkeypatch):
    async def fake_run(command, *args, **kwargs):
        target = command[-1]
        if "%27" in target or "'" in target:
            return ("You have an error in your SQL syntax near quote", "", 0)
        return ("normal response", "", 0)

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/search?q=test",
                    "method": "GET",
                    "params": ["q", "id"],
                }
            ],
            dbms="mysql",
            max_seconds=10,
            max_findings=1,
        )
    )

    assert result["budget_exhausted"] is True
    assert result["budget_exhausted_reason"] == "finding_cap"
    assert result["vulnerabilities_found"] == 1


def test_smart_sqli_emits_endpoint_attempt_telemetry(monkeypatch):
    async def fake_run(command, *args, **kwargs):
        return ("normal response", "", 0)

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/search?q=test",
                    "method": "GET",
                    "params": ["q"],
                }
            ],
            dbms="mysql",
            max_seconds=10,
        )
    )

    assert result["endpoint_attempts"] == [
        {
            "custom_endpoint": "GET /search?q=test",
            "family": "sqli",
            "method": "GET",
            "url": "https://example.test/search?q=test",
            "param_count": 1,
            "attempted_params_count": 1,
            "completed_params_count": 1,
            "status": "completed",
        }
    ]


def test_smart_sqli_skips_documentation_endpoints(monkeypatch):
    async def fail_run(*args, **kwargs):
        raise AssertionError("documentation endpoints should not be probed for SQLi")

    monkeypatch.setattr(active_checks, "run", fail_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/openapi.json?id=test",
                    "method": "GET",
                    "params": ["id"],
                }
            ],
            max_seconds=10,
        )
    )

    assert result["endpoints_tested"] == 0
    assert result["params_tested"] == 0


def test_smart_sqli_tests_documentation_path_when_seen_in_runtime_capture(monkeypatch):
    async def fake_run(command, *args, **kwargs):
        url = command[-1]
        if "%27" in url or "'" in url:
            return ("You have an error in your SQL syntax near quote", "", 0)
        return ("normal response", "", 0)

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/openapi.json?id=test",
                    "method": "GET",
                    "params": ["id"],
                    "source": "har_network_capture",
                }
            ],
            dbms="mysql",
            max_seconds=10,
        )
    )

    assert result["endpoints_tested"] == 1
    assert result["params_tested"] == 1
    assert result["vulnerabilities_found"] == 1
    assert result["findings"][0]["url"] == "https://example.test/openapi.json?id=test"


def test_smart_sqli_skips_hash_route_endpoints(monkeypatch):
    async def fail_run(*args, **kwargs):
        raise AssertionError("SPA hash routes should not be probed for server-side SQLi")

    monkeypatch.setattr(active_checks, "run", fail_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/#/users/search?q=test",
                    "method": "GET",
                    "params": ["q"],
                }
            ],
            max_seconds=10,
        )
    )

    assert result["endpoints_tested"] == 0
    assert result["params_tested"] == 0


def test_detect_dbms_requires_fingerprint_absent_from_baseline(monkeypatch):
    async def fake_run(*args, **kwargs):
        return "OpenAPI examples mention Oracle Error ORA-00933", "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(active_checks.detect_dbms("https://example.test/search?q=test", "q"))

    assert result["detected"] is None


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
    assert result["budget_exhausted_reason"] == "time_budget"
    assert result["endpoints_tested"] == 0
    assert result["params_tested"] == 0


def test_smart_xss_skips_hash_route_endpoints(monkeypatch):
    async def fail_run(*args, **kwargs):
        raise AssertionError("SPA hash routes should be handled by DOM XSS checks")

    monkeypatch.setattr(active_checks, "run", fail_run)

    result = asyncio.run(
        active_checks.smart_xss_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/#/search?q=test",
                    "method": "GET",
                    "params": ["q"],
                }
            ],
            max_seconds=10,
        )
    )

    assert result["endpoints_tested"] == 0
    assert result["params_tested"] == 0


def test_run_smart_active_tests_reserves_time_for_xss(monkeypatch):
    captures = {}
    now = {"value": 1000.0}

    monkeypatch.setattr(active_checks.time, "monotonic", lambda: now["value"])

    async def fake_sqli(*args, **kwargs):
        captures["sqli_max_seconds"] = kwargs["max_seconds"]
        now["value"] += kwargs["max_seconds"]
        return {
            "findings": [],
            "dbms_detected": None,
            "vulnerabilities_found": 0,
            "get_endpoints_tested": 0,
            "post_endpoints_tested": 0,
            "endpoints_tested": 1,
            "params_tested": 1,
            "budget_exhausted": True,
        }

    async def fake_xss(*args, **kwargs):
        captures["xss_max_seconds"] = kwargs["max_seconds"]
        return {
            "findings": [],
            "reflections_found": 0,
            "vulnerabilities_found": 0,
            "endpoints_tested": 1,
            "params_tested": 1,
            "get_endpoints_tested": 1,
            "post_endpoints_tested": 0,
            "budget_exhausted": False,
        }

    async def fake_hash_route_dom_xss(*args, **kwargs):
        return {
            "findings": [],
            "endpoints_tested": 0,
            "params_tested": 0,
            "vulnerabilities_found": 0,
        }

    monkeypatch.setattr(active_checks, "smart_sqli_test", fake_sqli)
    monkeypatch.setattr(active_checks, "smart_xss_test", fake_xss)
    monkeypatch.setattr(active_checks, "hash_route_dom_xss_test", fake_hash_route_dom_xss)

    result = asyncio.run(
        active_checks.run_smart_active_tests(
            "https://example.test",
            [{"url": "https://example.test/search?q=test", "method": "GET", "params": ["q"]}],
            active_max_seconds=100,
        )
    )

    assert captures["sqli_max_seconds"] == 70
    assert captures["xss_max_seconds"] == 30
    assert result["budget"]["active_sqli_max_seconds"] == 70
    assert result["budget"]["active_xss_reserved_seconds"] == 30
    assert result["budget"]["active_elapsed_seconds"] == 70
    assert result["budget"]["active_remaining_seconds"] == 30
    assert result["xss"]["endpoints_tested"] == 1


def test_thorough_params_honors_explicit_active_caps(monkeypatch):
    captures = {}

    async def fake_sqli(*args, **kwargs):
        captures["sqli_max_endpoints"] = kwargs["max_endpoints"]
        captures["sqli_max_params"] = kwargs["max_params_per_endpoint"]
        return {
            "findings": [],
            "dbms_detected": None,
            "vulnerabilities_found": 0,
            "get_endpoints_tested": 0,
            "post_endpoints_tested": 0,
            "endpoints_tested": 0,
            "params_tested": 0,
        }

    async def fake_xss(*args, **kwargs):
        captures["xss_max_endpoints"] = kwargs["max_endpoints"]
        captures["xss_max_params"] = kwargs["max_params_per_endpoint"]
        return {
            "findings": [],
            "reflections_found": 0,
            "vulnerabilities_found": 0,
            "endpoints_tested": 0,
            "params_tested": 0,
        }

    async def fake_hash_route_dom_xss(*args, **kwargs):
        return {
            "findings": [],
            "endpoints_tested": 0,
            "params_tested": 0,
            "vulnerabilities_found": 0,
        }

    monkeypatch.setattr(active_checks, "smart_sqli_test", fake_sqli)
    monkeypatch.setattr(active_checks, "smart_xss_test", fake_xss)
    monkeypatch.setattr(active_checks, "hash_route_dom_xss_test", fake_hash_route_dom_xss)

    asyncio.run(
        active_checks.run_smart_active_tests(
            "https://example.test",
            [{"url": f"https://example.test/api/{i}", "method": "GET", "params": ["id"]} for i in range(10)],
            thorough_params=True,
            active_max_endpoints=2,
            active_params_per_endpoint=3,
        )
    )

    assert captures["sqli_max_endpoints"] == 2
    assert captures["sqli_max_params"] == 3
    assert captures["xss_max_endpoints"] == 2
    assert captures["xss_max_params"] == 3

"""Opt-in Chromium profile tests: use only synthetic state, with no live target.

Set SHAKERSCAN_BROWSER_TEST_EXECUTABLE to the installed Chromium executable.
The localStorage test uses intercepted loopback navigation, not an external site.
An administrative browser policy denying navigation is an environment blocker,
not grounds to mark the localStorage scenario successful.
"""
from __future__ import annotations

import asyncio
import os

import pytest

from scanner.scanner_tools.browser_profile import BROWSER_STORAGE_SCHEMA, seed_browser_profile

CHROMIUM = os.environ.get("SHAKERSCAN_BROWSER_TEST_EXECUTABLE")
pytestmark = pytest.mark.skipif(not CHROMIUM, reason="explicit installed Chromium path required")
ORIGIN = "http://127.0.0.1:8765"
VALUE = "synthetic-browser-session-only"


@pytest.mark.parametrize("kind", ["cookie_header", "local_storage"])
def test_browser_state_survives_real_process_restart(tmp_path, kind):
    async def scenario():
        from playwright.async_api import async_playwright

        assert CHROMIUM is not None
        profile = tmp_path / "private-profile"
        seed = {"schema_version": BROWSER_STORAGE_SCHEMA, "kind": kind}
        if kind == "cookie_header":
            seed["value"] = "session=" + VALUE + "; marker="
        else:
            seed.update(key="auth.token", value=VALUE)
        receipt = await seed_browser_profile(
            user_data_dir=str(profile), target_origin=ORIGIN, seed=seed,
            chromium_path=CHROMIUM, proxy_url=None,
        )
        assert receipt["storage_seed_verified"] is True
        assert receipt["authentication_verified"] is False
        assert receipt["secret_values_visible"] is False
        assert VALUE not in repr(receipt)
        assert profile.stat().st_mode & 0o777 == 0o700

        async with async_playwright() as pw:
            context = await pw.chromium.launch_persistent_context(
                str(profile), headless=True, executable_path=CHROMIUM,
                service_workers="block",
                args=["--no-sandbox", "--disable-background-networking",
                      "--disable-component-update", "--disable-sync"],
            )
            try:
                async def fixture(route):
                    if route.request.url == ORIGIN + "/" and route.request.method == "GET":
                        await route.fulfill(status=200, content_type="text/html", body="<!doctype html>")
                    else:
                        await route.abort("blockedbyclient")

                await context.route("**/*", fixture)
                if kind == "cookie_header":
                    cookies = await context.cookies(ORIGIN + "/")
                    assert {item["name"]: item["value"] for item in cookies} == {
                        "session": VALUE, "marker": "",
                    }
                else:
                    page = context.pages[0] if context.pages else await context.new_page()
                    await page.goto(ORIGIN + "/", wait_until="commit")
                    # Return only a boolean; do not export synthetic or real secrets.
                    assert await page.evaluate(
                        "([key, value]) => localStorage.getItem(key) === value",
                        ["auth.token", VALUE],
                    ) is True
            finally:
                await context.close()

    asyncio.run(scenario())


def test_rejected_cookie_seed_removes_real_browser_profile(tmp_path):
    from scanner.scanner_tools.browser_profile import BrowserProfileError

    async def scenario():
        assert CHROMIUM is not None
        profile = tmp_path / "rejected-profile"
        # The __Host- prefix requires Secure; an HTTP seed must not silently
        # report success after Chromium rejects or drops this cookie.
        with pytest.raises(BrowserProfileError):
            await seed_browser_profile(
                user_data_dir=str(profile), target_origin=ORIGIN,
                seed={"schema_version": BROWSER_STORAGE_SCHEMA,
                      "kind": "cookie_header", "value": "__Host-session=" + VALUE},
                chromium_path=CHROMIUM, proxy_url=None,
            )
        assert not profile.exists()

    asyncio.run(scenario())

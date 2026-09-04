"""Create an ephemeral Chromium profile with worker-resolved browser auth.

The seed is private execution material.  It is never accepted from a Scan request,
placed in process arguments, or retained after the scanner process exits.  A local
route fulfils the bootstrap document, so establishing an origin for localStorage does
not spend an unmetered target request.
"""

from __future__ import annotations

from http.cookies import CookieError, SimpleCookie
from pathlib import Path
import re
from typing import Any, Mapping
import urllib.parse


BROWSER_STORAGE_SCHEMA = "scan-browser-storage/v1"
_STORAGE_KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")


class BrowserProfileError(ValueError):
    """Private browser state cannot be materialized safely."""


def normalize_browser_storage_seed(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or value.get("schema_version") != BROWSER_STORAGE_SCHEMA:
        raise BrowserProfileError("browser storage seed has an invalid schema")
    kind = str(value.get("kind") or "").strip()
    secret = str(value.get("value") or "")
    if not secret or len(secret.encode("utf-8")) > 65_536 or "\x00" in secret:
        raise BrowserProfileError("browser storage seed has an invalid value")
    if kind == "local_storage":
        key = str(value.get("key") or "").strip()
        if not _STORAGE_KEY_RE.fullmatch(key):
            raise BrowserProfileError("browser localStorage key is invalid")
        return {"kind": kind, "key": key, "value": secret}
    if kind == "cookie_header":
        if value.get("key") not in (None, ""):
            raise BrowserProfileError("cookie seed cannot contain a storage key")
        return {"kind": kind, "value": secret}
    raise BrowserProfileError("browser storage seed kind is invalid")


def _origin(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(value or ""))
        _ = parsed.port
    except ValueError as exc:
        raise BrowserProfileError("browser storage origin is invalid") from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise BrowserProfileError("browser storage origin must be HTTP or HTTPS")
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, "", "", ""))


def _cookies(header: str, *, origin: str) -> list[dict[str, Any]]:
    parsed = urllib.parse.urlsplit(origin)
    jar = SimpleCookie()
    try:
        jar.load(header)
    except CookieError as exc:
        raise BrowserProfileError("browser cookie seed is invalid") from exc
    cookies = []
    for name in sorted(jar):
        value = str(jar[name].value)
        if not name or not value:
            continue
        cookies.append({
            "name": name,
            "value": value,
            "url": origin + "/",
            "secure": parsed.scheme.lower() == "https",
            "sameSite": "Lax",
        })
    if not cookies:
        raise BrowserProfileError("browser cookie seed contains no cookies")
    return cookies


async def seed_browser_profile(
    *,
    user_data_dir: str,
    target_origin: str,
    seed: Mapping[str, Any],
    chromium_path: str,
    proxy_url: str | None,
) -> dict[str, Any]:
    """Persist private auth into one owner-only profile without target traffic."""
    profile = Path(user_data_dir)
    if not profile.is_absolute() or profile.exists():
        raise BrowserProfileError("browser profile path must be a fresh absolute path")
    profile.mkdir(mode=0o700, parents=False)
    profile.chmod(0o700)
    origin = _origin(target_origin)
    normalized = normalize_browser_storage_seed(seed)
    executable = Path(chromium_path)
    if not executable.is_absolute():
        raise BrowserProfileError("Chromium path must be absolute")

    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise BrowserProfileError("Playwright is unavailable for browser profile seeding") from exc

    launch_options: dict[str, Any] = {
        "headless": True,
        "executable_path": str(executable),
        "args": [
            "--no-sandbox",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
        ],
    }
    if proxy_url:
        launch_options["proxy"] = {"server": str(proxy_url)}

    async with async_playwright() as playwright:
        context = await playwright.chromium.launch_persistent_context(
            str(profile), **launch_options,
        )
        try:
            if normalized["kind"] == "cookie_header":
                cookies = _cookies(normalized["value"], origin=origin)
                await context.add_cookies(cookies)
                seeded_items = len(cookies)
            else:
                page = context.pages[0] if context.pages else await context.new_page()

                async def local_bootstrap(route: Any) -> None:
                    await route.fulfill(
                        status=200,
                        content_type="text/html",
                        body="<!doctype html><meta charset=utf-8>",
                    )

                await page.route("**/*", local_bootstrap)
                await page.goto(origin + "/", wait_until="commit")
                await page.evaluate(
                    "([key, value]) => window.localStorage.setItem(key, value)",
                    [normalized["key"], normalized["value"]],
                )
                seeded_items = 1
        finally:
            await context.close()
    return {
        "schema_version": BROWSER_STORAGE_SCHEMA,
        "kind": normalized["kind"],
        "seeded_items": seeded_items,
        "target_requests": 0,
        "secret_values_visible": False,
    }


__all__ = [
    "BROWSER_STORAGE_SCHEMA",
    "BrowserProfileError",
    "normalize_browser_storage_seed",
    "seed_browser_profile",
]

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
import shutil
from typing import Any, Mapping
import urllib.parse


BROWSER_STORAGE_SCHEMA = "scan-browser-storage/v1"
_STORAGE_KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")


class BrowserProfileError(ValueError):
    """Private browser state cannot be materialized safely."""


def normalize_browser_storage_seed(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or value.get("schema_version") != BROWSER_STORAGE_SCHEMA:
        raise BrowserProfileError("browser storage seed has an invalid schema")
    kind = value.get("kind")
    secret = value.get("value")
    if not isinstance(kind, str):
        raise BrowserProfileError("browser storage seed kind is invalid")
    kind = kind.strip()
    if not isinstance(secret, str) or not secret or len(secret) > 65_536:
        raise BrowserProfileError("browser storage seed has an invalid value")
    try:
        encoded_length = len(secret.encode("utf-8"))
    except UnicodeEncodeError:
        raise BrowserProfileError("browser storage seed has an invalid value") from None
    if encoded_length > 65_536 or "\x00" in secret:
        raise BrowserProfileError("browser storage seed has an invalid value")
    if kind == "local_storage":
        key = value.get("key")
        if not isinstance(key, str) or not _STORAGE_KEY_RE.fullmatch(key.strip()):
            raise BrowserProfileError("browser localStorage key is invalid")
        return {"kind": kind, "key": key.strip(), "value": secret}
    if kind == "cookie_header":
        if value.get("key") not in (None, ""):
            raise BrowserProfileError("cookie seed cannot contain a storage key")
        return {"kind": kind, "value": secret}
    raise BrowserProfileError("browser storage seed kind is invalid")


def _origin(value: str) -> str:
    # urlsplit strips some controls. Reject them before parsing, and never put
    # an untrusted URL (which can contain credentials) in an exception chain.
    if not isinstance(value, str) or any(ord(c) <= 0x20 or ord(c) == 0x7f for c in value):
        raise BrowserProfileError("browser storage origin is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise BrowserProfileError("browser storage origin is invalid") from None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise BrowserProfileError("browser storage origin must be HTTP or HTTPS")
    scheme = parsed.scheme.lower()
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise BrowserProfileError("browser storage origin is invalid") from None
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if scheme == "https" else 80):
        authority += f":{port}"
    return urllib.parse.urlunsplit((scheme, authority, "", "", ""))


def _cookies(header: str, *, origin: str) -> list[dict[str, Any]]:
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in header):
        raise BrowserProfileError("browser cookie seed is invalid")
    parsed = urllib.parse.urlsplit(origin)
    jar = SimpleCookie()
    try:
        jar.load(header)
    except CookieError:
        raise BrowserProfileError("browser cookie seed is invalid") from None
    cookies = []
    for name in sorted(jar):
        value = str(jar[name].value)
        # This is a Cookie request header, not a Set-Cookie response. Do not
        # silently ignore attributes or discard a legitimate empty cookie value.
        if any(jar[name].values()):
            raise BrowserProfileError("browser cookie seed must be a Cookie request header")
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
    if not profile.is_absolute() or profile.exists() or profile.is_symlink():
        raise BrowserProfileError("browser profile path must be a fresh absolute path")
    # Validate everything before creating a directory that may hold credentials.
    origin = _origin(target_origin)
    normalized = normalize_browser_storage_seed(seed)
    cookies = (
        _cookies(normalized["value"], origin=origin)
        if normalized["kind"] == "cookie_header" else []
    )
    executable = Path(chromium_path)
    if not executable.is_absolute():
        raise BrowserProfileError("Chromium path must be absolute")
    if not executable.is_file():
        raise BrowserProfileError("Chromium executable is unavailable")

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise BrowserProfileError("Playwright is unavailable for browser profile seeding") from None

    launch_options: dict[str, Any] = {
        "headless": True,
        "executable_path": str(executable),
        "service_workers": "block",
        "args": [
            "--no-sandbox",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
        ],
    }
    if proxy_url:
        launch_options["proxy"] = {"server": str(proxy_url)}

    # mkdir is the ownership claim: if it fails, never remove a pre-existing path.
    try:
        profile.mkdir(mode=0o700, parents=False)
    except OSError:
        raise BrowserProfileError("browser profile directory could not be created") from None
    try:
        profile.chmod(0o700)
        async with async_playwright() as playwright:
            context = await playwright.chromium.launch_persistent_context(
                str(profile), **launch_options,
            )
            try:
                # Guard the entire context, including popup pages; never use
                # route.continue_() while materializing private browser state.
                async def local_bootstrap(route: Any) -> None:
                    request = route.request
                    if (
                        normalized["kind"] == "local_storage"
                        and request.url == origin + "/"
                        and request.method == "GET"
                        and request.is_navigation_request()
                    ):
                        await route.fulfill(
                            status=200,
                            content_type="text/html",
                            headers={"Content-Security-Policy": "default-src 'none'; form-action 'none'"},
                            body="<!doctype html><meta charset=utf-8>",
                        )
                    else:
                        await route.abort("blockedbyclient")

                await context.route("**/*", local_bootstrap)
                if normalized["kind"] == "cookie_header":
                    await context.add_cookies(cookies)
                    installed = await context.cookies(origin + "/")
                    if not all(any(
                        item.get("name") == wanted["name"]
                        and item.get("value") == wanted["value"]
                        for item in installed
                    ) for wanted in cookies):
                        raise BrowserProfileError("browser cookie seed was not installed")
                    seeded_items = len(cookies)
                else:
                    page = context.pages[0] if context.pages else await context.new_page()
                    await page.goto(origin + "/", wait_until="commit")
                    stored = await page.evaluate(
                        "([key, value]) => { window.localStorage.setItem(key, value); "
                        "return window.localStorage.getItem(key) === value; }",
                        [normalized["key"], normalized["value"]],
                    )
                    if stored is not True:
                        raise BrowserProfileError("browser localStorage seed was not installed")
                    seeded_items = 1
            except BaseException:
                # A close failure must not replace cancellation (or the primary
                # materialization error) with a different outcome.
                try:
                    await context.close()
                except Exception:
                    pass
                raise
            else:
                await context.close()
    except BaseException as exc:
        # Cancellation remains cancellation. All failures remove the profile we
        # created, and browser diagnostics containing secrets never escape.
        cleanup_failed = False
        try:
            shutil.rmtree(profile)
        except OSError:
            cleanup_failed = True
        if not isinstance(exc, Exception):
            if cleanup_failed and hasattr(exc, "add_note"):
                exc.add_note("Private browser profile cleanup failed; scratch teardown is required.")
            raise
        reason = "browser profile seeding failed"
        if cleanup_failed:
            reason += "; private profile cleanup failed; scratch teardown is required"
        raise BrowserProfileError(reason) from None
    return {
        "schema_version": BROWSER_STORAGE_SCHEMA,
        "kind": normalized["kind"],
        "seeded_items": seeded_items,
        "target_requests": 0,
        "secret_values_visible": False,
        # Local readback is not proof that the application accepts the session.
        "storage_seed_verified": True,
        "authentication_verified": False,
    }


__all__ = [
    "BROWSER_STORAGE_SCHEMA",
    "BrowserProfileError",
    "normalize_browser_storage_seed",
    "seed_browser_profile",
]

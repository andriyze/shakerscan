"""Helpers for SPA hash-route active testing."""

from __future__ import annotations

import re
import urllib.parse
from typing import Any


def build_hash_route_active_endpoints(base_url: str, sources: list[Any], limit: int = 12) -> list[dict[str, Any]]:
    """Build DOM-XSS active-test endpoints from SPA hash-route hints."""
    parsed_base = urllib.parse.urlparse(base_url)
    if not parsed_base.scheme or not parsed_base.netloc:
        return []
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    root_url = origin + "/"

    route_tokens: list[str] = []
    token_re = re.compile(r"(?:https?://[^\s\"'<>),]+|/)?#!?/[^\s\"'<>),]+")

    def _add_token(token: str) -> None:
        token = (token or "").strip().rstrip(".,;")
        if not token:
            return
        if token.startswith(("http://", "https://")):
            normalized = token
        elif token.startswith("/#/") or token.startswith("/#!/"):
            normalized = origin + token
        elif token.startswith("#/") or token.startswith("#!/"):
            normalized = root_url + token
        else:
            return
        parsed = urllib.parse.urlparse(normalized)
        if not (parsed.fragment.startswith("/") or parsed.fragment.startswith("!/")):
            return
        if parsed.netloc != parsed_base.netloc:
            return
        route_tokens.append(normalized)

    for raw in sources or []:
        if raw is None:
            continue
        text = str(raw)
        if "#/" not in text and "#!/" not in text:
            continue
        if text.startswith(("#/", "#!/", "/#/", "/#!/", "http://", "https://")):
            _add_token(text)
        for match in token_re.finditer(text):
            _add_token(match.group(0))

    if route_tokens:
        for common_route in ("#/search?q=test", "#/search?query=test", "#!/search?q=test"):
            _add_token(common_route)

    endpoints: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for route_url in route_tokens:
        parsed = urllib.parse.urlparse(route_url)
        fragment = parsed.fragment or ""
        fragment_query = fragment.split("?", 1)[1] if "?" in fragment else ""
        params = list(urllib.parse.parse_qs(fragment_query, keep_blank_values=True).keys())
        if not params and "search" in fragment.lower():
            params = ["q", "query", "search"]
        params = list(dict.fromkeys(params))
        if not params:
            continue
        key = (route_url, tuple(params))
        if key in seen:
            continue
        seen.add(key)
        endpoints.append({
            "url": route_url,
            "method": "GET",
            "params": params,
            "source": "hash_route",
        })
        if len(endpoints) >= limit:
            break
    return endpoints

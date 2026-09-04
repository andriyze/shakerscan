"""Typed replayable read-only browser steps and content-minimized surface snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from runtime.secret_material import contains_secret_material
    from scanner_tools.url_redaction import redact_client_route, redact_url
except ModuleNotFoundError:
    from ..runtime.secret_material import contains_secret_material
    from scanner.scanner_tools.url_redaction import redact_client_route, redact_url


MAX_BROWSER_STEPS = 8
_SELECTOR = re.compile(r"^[A-Za-z0-9_.#\-\[\]=:'\" ()>+~,*^$|]+$")


def browser_steps(args: Mapping[str, Any]) -> tuple[dict[str, str], ...]:
    if "steps" in args and "selector" in args:
        raise ValueError("Supply selector or steps, not both")
    raw = args.get("steps", [{"action": "click", "selector": args.get("selector")}])
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_BROWSER_STEPS:
        raise ValueError("browser steps must contain 1 to 8 actions")
    result = []
    for step in raw:
        if not isinstance(step, Mapping) or set(step) - {"action", "selector", "value"}:
            raise ValueError("unsupported browser step fields")
        action, selector = step.get("action", "click"), step.get("selector")
        if action not in {"click", "fill"}:
            raise ValueError("browser step must be click or fill")
        if not isinstance(selector, str):
            raise ValueError("browser selector must be a string")
        selector = selector.strip()
        if (not selector or len(selector) > 500 or not _SELECTOR.fullmatch(selector)
                or ">>" in selector or selector.lower().startswith(("xpath=", "text="))
                or ":has-text" in selector.lower() or ":text" in selector.lower()
                or contains_secret_material(selector)):
            raise ValueError("browser selector must be a bounded CSS selector without secret material")
        item = {"action": action, "selector": selector}
        if action == "fill":
            value = step.get("value")
            if (not isinstance(value, str) or len(value) > 500
                    or any(ord(ch) < 32 for ch in value) or contains_secret_material(value)):
                raise ValueError("browser fill requires a bounded non-secret value")
            item["value"] = value
        elif "value" in step:
            raise ValueError("click does not accept a value")
        result.append(item)
    return tuple(result)


ELEMENT_DESCRIPTOR = """element => ({
    tag: String(element.tagName || '').toLowerCase(),
    role: String(element.getAttribute('role') || '').toLowerCase(),
    type: String(element.getAttribute('type') || '').toLowerCase(),
    href: String(element.href || ''),
    target: String(element.getAttribute('target') || '').toLowerCase(),
    download: element.hasAttribute('download'),
    expanded: element.hasAttribute('aria-expanded'),
    semantics: ['name', 'id', 'autocomplete', 'aria-label'].map(name => element.getAttribute(name) || '').join(' ').slice(0, 350) + ' ' + String(element.textContent || '').slice(0, 150)
})"""


def validate_fill(element: Mapping[str, Any]) -> None:
    if element.get("tag") not in {"input", "textarea"} or element.get("type") not in {"", "text", "search", "email", "url", "tel", "number"}:
        raise ValueError("Only non-secret text fields can be filled; use managed sessions for login")
    if re.search(r"password|secret|token|credential|api.?key|otp|verification.?code", str(element.get("semantics", "")), re.I):
        raise ValueError("Secret fields require managed authentication")


async def browser_surface(page: Any) -> dict[str, Any]:
    # Never collect textContent, values, labels, HTML, or storage. Target-supplied
    # structure is still untrusted data; it is not an instruction or proof.
    raw = await page.evaluate("""() => {
      const selector = e => {
        const parts = [];
        for (let n = e; n && n.nodeType === 1 && parts.length < 12; n = n.parentElement) {
          const siblings = n.parentElement ? Array.from(n.parentElement.children).filter(x => x.tagName === n.tagName) : [n];
          parts.unshift(n.tagName.toLowerCase() + ':nth-of-type(' + (siblings.indexOf(n) + 1) + ')');
        }
        return parts.join(' > ');
      };
      const controls = Array.from(document.querySelectorAll('a[href],area[href],input,textarea,select,button,summary,[role="tab"],[tabindex]'))
        .filter(e => e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden');
      return {total: controls.length, controls: controls.slice(0,100).map(e => ({
        selector: selector(e), tag: e.tagName.toLowerCase(), role: e.getAttribute('role') || '',
        type: e.getAttribute('type') || '', href: e.href || '', disabled: Boolean(e.disabled),
        expanded: e.getAttribute('aria-expanded') === 'true', selected: e.getAttribute('aria-selected') === 'true'
      }))};
    }""")
    controls = []
    for item in (raw.get("controls") or [])[:100]:
        safe = {key: str(item.get(key) or "")[:500] for key in ("selector", "tag", "role", "type")}
        if contains_secret_material(safe):
            continue
        safe["href"] = redact_url(str(item.get("href") or ""), max_length=2000)
        safe["client_route"] = redact_client_route(item.get("href"))
        safe["disabled"] = bool(item.get("disabled"))
        safe["expanded"] = bool(item.get("expanded"))
        safe["selected"] = bool(item.get("selected"))
        controls.append(safe)
    surface = {"url": redact_url(page.url, max_length=2000), "client_route": redact_client_route(page.url), "controls": controls}
    return {"kind": "browser_surface", **surface,
            "state_id": hashlib.sha256(json.dumps(surface, sort_keys=True).encode()).hexdigest(),
            "truncated": int(raw.get("total") or 0) > len(controls),
            "untrusted_data": True, "contains_text_or_values": False}

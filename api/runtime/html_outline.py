"""A bounded outline of one HTML response for the Hunt planner: links, forms and visible text.

A body sample cut from byte 0 shows a page's ``<head>``: on many applications that is all CSS,
and the links and forms the planner needs come later. The outline reads the bounded body the
request already holds (no further request) and returns what a person sees and can follow:

- ``links``: ``href``/``src``/``action`` targets of anchors, areas, forms, frames and scripts,
  same-origin first (as paths), de-duplicated, at most ``MAX_LINKS``;
- ``forms``: method, action and field names and types; a hidden field's value goes through the
  caller's value masking (a secret-named or credential-shaped one is withheld), a password
  field's never appears;
- ``text_sample``: the visible text with ``<style>``, ``<script>`` and similar removed.

Pure: the caller supplies the masking, so the outline shows nothing the body sample would not.
The caller feeds it the page as the body sample's masking left it, so a value withheld there in its
context (a ``<textarea name=password>``, an element ``id="api_key"``, a password column) is already
withheld when tags are stripped; every derived string (a field's name, type and value, the form's
method, a link) is masked again, then shortened, never shortened or re-cased first.
"""
from __future__ import annotations

from html.parser import HTMLParser
import re
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

MAX_LINKS = 40
MAX_LINK_CHARS = 300
MAX_FORMS = 6
MAX_FORM_FIELDS = 24
MAX_TEXT_CHARS = 1_200
MAX_TITLE_CHARS = 200
# The parse stops collecting text past this many characters: the sample is far smaller.
_MAX_COLLECTED_TEXT = 8 * MAX_TEXT_CHARS

_HIDDEN_TEXT_TAGS = frozenset({"style", "script", "noscript", "template", "svg"})
_BLOCK_TAGS = frozenset({
    "p", "div", "br", "tr", "li", "ul", "ol", "table", "thead", "tbody", "h1", "h2", "h3", "h4",
    "h5", "h6", "header", "footer", "main", "nav", "section", "article", "aside", "form", "label",
    "dl", "dt", "dd", "pre", "blockquote", "hr", "title", "button", "select", "textarea",
})
_LINK_ATTRIBUTES = {"a": "href", "area": "href", "iframe": "src", "frame": "src", "script": "src"}
_FIELD_TAGS = frozenset({"input", "select", "textarea", "button"})
_NOT_NAVIGABLE = re.compile(r"^\s*(?:javascript|mailto|tel|data|about|blob):", re.IGNORECASE)
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "DIALOG"})
_FIELD_TYPES = frozenset({
    "button", "checkbox", "color", "date", "datetime-local", "email", "file", "hidden", "image",
    "month", "number", "password", "radio", "range", "reset", "search", "submit", "tel", "text",
    "time", "url", "week", "select", "textarea",
})
MAX_NAME_CHARS = 100
# What the planner can do with a sign-in form (fixed text, never page content).
SIGN_IN_HINT = (
    "A sign-in form. To test signed in: send its POST with http.request (form_body with these "
    "fields; it needs state-changing permission) and \"capture\": [{\"name\": \"session\", "
    "\"header\": \"Set-Cookie\"}]; the answer's captures entry is the request_bindings item that "
    "sends the session on later http.request, artifact.inspect and scanner calls to the same origin. "
    "With a selected web credential, auth.session.establish signs in instead (then as_principal)."
)


def looks_like_html(content_type: str, text: str) -> bool:
    kind = str(content_type or "").split(";", 1)[0].strip().lower()
    if kind:
        return kind in {"text/html", "application/xhtml+xml"}
    head = text.lstrip()[:64].lower()
    return head.startswith("<!doctype html") or head.startswith("<html")


class _Outline(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.text: list[str] = []
        self.text_chars = 0
        self.title: list[str] = []
        self._hidden_depth = 0
        self._in_title = False
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # A browser reads the first of a repeated attribute (``type=password type=hidden`` is a
        # password field), so the outline does too.
        values: dict[str, str] = {}
        for name, value in attrs:
            values.setdefault(name.lower(), value or "")
        if tag == "title":
            self._in_title = True
        if tag in _HIDDEN_TEXT_TAGS:
            self._hidden_depth += 1
        if tag in _BLOCK_TAGS:
            self._add_text("\n")
        attribute = _LINK_ATTRIBUTES.get(tag)
        if attribute and values.get(attribute):
            self.links.append(values[attribute])
        if tag == "form":
            # Kept as written: shortened and re-cased only after masking (``html_outline``).
            self._form = {"method": values.get("method") or "GET",
                          "action": values.get("action", ""), "fields": []}
            self.forms.append(self._form)
            if values.get("action"):
                self.links.append(values["action"])
        elif tag in _FIELD_TAGS and self._form is not None and values.get("name"):
            kind = values.get("type") or ("text" if tag == "input" else tag)
            field: dict[str, Any] = {"name": values["name"], "type": kind}
            if kind.strip().lower() == "hidden":
                field["value"] = values.get("value", "")
            self._form["fields"].append(field)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag in _HIDDEN_TEXT_TAGS:
            self._hidden_depth = max(0, self._hidden_depth - 1)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag in _HIDDEN_TEXT_TAGS:
            self._hidden_depth = max(0, self._hidden_depth - 1)
        if tag == "form":
            self._form = None
        if tag in _BLOCK_TAGS or tag in {"td", "th"}:
            self._add_text("\n" if tag in _BLOCK_TAGS else " ")

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title.append(data)
            return
        if not self._hidden_depth:
            self._add_text(data)

    def _add_text(self, data: str) -> None:
        if self.text_chars < _MAX_COLLECTED_TEXT:
            self.text.append(data)
            self.text_chars += len(data)


def _visible_text(parts: list[str]) -> str:
    lines = (re.sub(r"[ \t\r\f\v]+", " ", line).strip() for line in "".join(parts).split("\n"))
    return "\n".join(line for line in lines if line)


def _link(raw: str, base_url: str) -> tuple[bool, str] | None:
    """``(same_origin, shown)``: a same-origin link as its path and query, another as its URL."""
    value = str(raw or "").strip()
    if not value or value.startswith("#") or _NOT_NAVIGABLE.match(value):
        return None
    try:
        absolute = urljoin(base_url, value) if base_url else value
        parts = urlsplit(absolute)
        base = urlsplit(base_url) if base_url else None
    except ValueError:  # a malformed link (``http://[x/``) is left out, never fails the answer
        return None
    if parts.scheme not in {"http", "https", ""}:
        return None
    if base is not None and (parts.scheme, parts.netloc) == (base.scheme, base.netloc):
        return True, (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if base is None and not parts.netloc:
        return True, value.split("#", 1)[0]
    return False, absolute.split("#", 1)[0]


def html_outline(
    text: str,
    base_url: str,
    *,
    mask_text: Callable[[str], str],
    bound_text: Callable[[str, int], str],
    mask_url: Callable[[str, int], str],
    mask_field_value: Callable[[str, str], Any],
) -> dict[str, Any]:
    parser = _Outline()
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # noqa: BLE001 - a page the parser cannot read gets no outline
        return {}
    same: list[str] = []
    other: list[str] = []
    seen: set[str] = set()
    for raw in parser.links:
        link = _link(raw, base_url)
        if link is None or link[1] in seen:
            continue
        seen.add(link[1])
        (same if link[0] else other).append(link[1])
    ordered = same + other

    def word(value: str, known: frozenset[str], limit: int, case: Callable[[str], str]) -> str:
        """A method or a type: a known word in its usual case; anything else masked, then cut."""
        folded = case(value.strip())
        return folded if folded in known else bound_text(mask_text(value), limit)

    forms = []
    for form in parser.forms[:MAX_FORMS]:
        action = _link(form["action"], base_url) if form["action"] else None
        fields = []
        for field in form["fields"][:MAX_FORM_FIELDS]:
            shown = {"name": bound_text(mask_text(field["name"]), MAX_NAME_CHARS),
                     "type": word(field["type"], _FIELD_TYPES, 20, str.lower)}
            if "value" in field and field["value"]:
                shown["value"] = mask_field_value(field["name"], field["value"])
            fields.append(shown)
        sign_in = any(field["type"] == "password" for field in fields)
        forms.append({
            **({"sign_in": True} if sign_in else {}),
            "method": word(form["method"], _METHODS, 10, str.upper),
            # A form without an action posts to the page itself.
            "action": mask_url(action[1], MAX_LINK_CHARS) if action else None,
            "fields": fields,
            **({"fields_total": len(form["fields"])} if len(form["fields"]) > MAX_FORM_FIELDS else {}),
        })
    visible = _visible_text(parser.text)
    outline: dict[str, Any] = {
        "title": mask_text(re.sub(r"\s+", " ", "".join(parser.title)).strip())[:MAX_TITLE_CHARS] or None,
        "links": [mask_url(item, MAX_LINK_CHARS) for item in ordered[:MAX_LINKS]],
        "links_total": len(ordered),
        "forms": forms,
        "text_sample": bound_text(mask_text(visible), MAX_TEXT_CHARS) if visible else "",
        "text_truncated": len(visible) > MAX_TEXT_CHARS or parser.text_chars >= _MAX_COLLECTED_TEXT,
    }
    if len(parser.forms) > MAX_FORMS:
        outline["forms_total"] = len(parser.forms)
    if any(form.get("sign_in") for form in forms):
        outline["sign_in_hint"] = SIGN_IN_HINT
    return outline


__all__ = ["MAX_LINKS", "MAX_TEXT_CHARS", "html_outline", "looks_like_html"]

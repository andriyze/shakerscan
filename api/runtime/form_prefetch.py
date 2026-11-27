"""A form POST that first reads its own page: the form's hidden fields and the page's cookies.

Many sign-in forms carry a per-session anti-CSRF token in a hidden input (DVWA's ``user_token``,
Django's ``csrfmiddlewaretoken``, Rails' ``authenticity_token``, Laravel's ``_token``) and refuse
a POST without it, or with a token from another session. A default-credential attempt that sent
only the user name and password was refused by every such login however right the pair was: a
driven DVWA Hunt sent ``admin``/``password`` and got the sign-in page back.

``http.request`` with ``form_prefetch: true`` (a POST with ``form_body``) GETs ``form_page`` (or
the POST's own path) first, then sends the form that posts to the request's path with its hidden
fields added and the page's cookies set. A field the request already names is never replaced,
and nothing the page holds is shown: the values only travel in that one POST.
"""
from __future__ import annotations

from html.parser import HTMLParser
import re
from typing import Any
import urllib.parse

MAX_HIDDEN_FIELDS = 16
MAX_FIELD_VALUE_CHARS = 4_000
_FIELD_NAME = re.compile(r"^[A-Za-z0-9_.:\-\[\]]{1,128}$")


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {str(name).lower(): str(value or "") for name, value in attrs}
        if tag.lower() == "form" and self._current is None:
            self._current = {"action": values.get("action", ""), "method": values.get("method", "GET").upper(),
                             "inputs": []}
        elif tag.lower() == "input" and self._current is not None:
            self._current["inputs"].append({"name": values.get("name", ""),
                                            "type": values.get("type", "text").lower(),
                                            "value": values.get("value", "")})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def _path_of(url: str) -> str:
    return urllib.parse.urlsplit(url).path or "/"


def hidden_fields(html: str, *, page_url: str, post_url: str) -> dict[str, str]:
    """The hidden inputs of the POST form on ``page_url`` that submits to ``post_url``'s path; when
    no form names that action, the page's one POST form with a password input. Empty otherwise."""
    parser = _FormParser()
    try:
        parser.feed(str(html or ""))
        parser.close()
    except Exception:  # noqa: BLE001 - a page that does not parse adds nothing
        return {}
    posting = [form for form in parser.forms if form["method"] == "POST"]
    target = _path_of(post_url)
    chosen = [form for form in posting
              if _path_of(urllib.parse.urljoin(page_url, form["action"] or page_url)) == target]
    if len(chosen) != 1:
        chosen = [form for form in posting if any(item["type"] == "password" for item in form["inputs"])]
    if len(chosen) != 1:
        return {}
    fields: dict[str, str] = {}
    for item in chosen[0]["inputs"]:
        name = item["name"]
        if item["type"] != "hidden" or not _FIELD_NAME.match(name) or name in fields:
            continue
        value = item["value"]
        if len(value) > MAX_FIELD_VALUE_CHARS or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            continue
        fields[name] = value
        if len(fields) >= MAX_HIDDEN_FIELDS:
            break
    return fields

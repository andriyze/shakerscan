"""An artifact window never shows a piece of a secret, however small or wherever it is cut.

A Hunt reads a resource in windows it chooses (``artifact.inspect`` ``offset``/``max_bytes``, at
least one byte). The masking recognized a secret with its label in the context before the window,
but withheld the window's text by matching it against the value: a window that starts and ends
inside the value shows a piece with neither end, so a run of one- to three-byte windows rebuilt
the whole value. A URL's password was not recognized at all when the window started inside it
(its ``@host`` is after the window). The values are now located by position in the context, the
window and the lookahead read together, and every byte of one the window cuts is withheld.
Synthetic fixture values only.
"""

from __future__ import annotations

import sys

import pytest

from api.capabilities import artifact

# The masking module the artifact capability itself uses (one ContextVar for the collector).
masking = sys.modules[artifact.active_withheld_values.__module__]

SECRET = "SuperSecretPassw0rd!"
LOOKAHEAD = masking.CUT_LOOKAHEAD_CHARS
RESOURCES = {
    "dotenv": "APP_NAME=demo\nDEBUG=false\nDB_PASSWORD=" + SECRET + "\nDB_HOST=db\n",
    "json": '{"user":"admin","password":"' + SECRET + '","role":"viewer"}\n',
    "url": "conn = postgres://app:" + SECRET + "@db:5432/app\n",
    "multibyte": "DB_PASSWORD=Pässwörd-Ünïcødé-42\nnext=1\n",
}


def _window(text: str, offset: int, length: int, collector=None) -> str:
    raw = text.encode()
    start = max(0, offset - artifact.CONTEXT_BYTES)
    args = (raw[offset:offset + length], raw[start:offset], start,
            raw[offset + length:offset + length + LOOKAHEAD])
    if collector is None:
        return artifact._masked_window_text(*args)
    with masking.collecting_withheld_values(collector):
        return artifact._masked_window_text(*args)


def _secret_of(name: str) -> str:
    return "Pässwörd-Ünïcødé-42" if name == "multibyte" else SECRET


@pytest.mark.parametrize("hunt", [False, True], ids=["export", "hunt"])
@pytest.mark.parametrize("name", sorted(RESOURCES))
def test_no_window_inside_a_secret_shows_any_of_it(name, hunt):
    text, secret = RESOURCES[name], _secret_of(name)
    raw, value = text.encode(), secret.encode()
    first = raw.index(value)
    for offset in range(first, first + len(value)):
        for length in (1, 2, 3, 4, 5, 6, 15, 16, 17, len(value)):
            collector = masking.WithheldValues("hunt-action") if hunt else None
            shown = _window(text, offset, length, collector)
            inside = raw[offset:min(offset + length, first + len(value))].decode(errors="ignore")
            assert not inside or inside not in shown, (offset - first, length, shown)


@pytest.mark.parametrize("name", ["dotenv", "json", "url"])
def test_a_walk_of_tiny_windows_cannot_rebuild_the_value(name):
    text = RESOURCES[name]
    first = text.index(SECRET)
    pieces = [_window(text, offset, 3, masking.WithheldValues("hunt-action"))
              for offset in range(first, first + len(SECRET), 3)]
    assert SECRET not in "".join(pieces)
    assert all(piece.startswith(masking.MASK) for piece in pieces), pieces


def test_a_window_starting_at_a_url_password_withholds_it_whole():
    text = RESOURCES["url"]
    offset = text.index(SECRET)
    assert SECRET not in _window(text, offset, len(SECRET))
    assert SECRET not in _window(text, offset, 64)


def test_a_value_sealed_earlier_in_the_hunt_is_withheld_far_from_its_label():
    # The label is more than the context away; the Hunt already holds the value.
    text = "DB_PASSWORD=" + SECRET + "\n" + "# filler line\n" * 6000 + "again=" + SECRET + "\n"
    first = text.rindex(SECRET)
    for offset in range(first, first + len(SECRET)):
        for length in (1, 3, 8, 20):
            collector = masking.WithheldValues("hunt-action")
            collector.bind_known([SECRET], found=True)
            shown = _window(text, offset, length, collector)
            assert text[offset:min(offset + length, first + len(SECRET))] not in shown


def test_a_whole_value_in_the_window_stays_a_reference_the_hunt_can_send():
    text = RESOURCES["dotenv"]
    offset = text.index("DB_PASSWORD")
    collector = masking.WithheldValues("hunt-action")
    shown = _window(text, offset, 40, collector)
    assert SECRET not in shown and "[withheld:" in shown
    assert SECRET in collector.values


def test_text_around_a_secret_is_still_shown():
    text = RESOURCES["dotenv"]
    before = _window(text, text.index("DEBUG"), 11)
    assert before == "DEBUG=false"
    after = _window(text, text.index("DB_HOST"), 10)
    assert after == "DB_HOST=db"


def test_a_short_value_does_not_withhold_every_window_edge():
    text = "PIN=ab\nThe cab was abandoned by the lab.\n"
    shown = _window(text, text.index("The"), 20)
    assert shown == "The cab was abandone"

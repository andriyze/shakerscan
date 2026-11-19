"""The proof browser finds Playwright's driver and connection in every layout we ship.

Ending a proof browser waits for Playwright's driver process, and a cancelled or timed-out stop
closes the driver's connection so nothing keeps waiting on a driver that no longer answers. Both
reach into Playwright's internals. Playwright 1.65 moved them from the starter
(``starter._connection``, ``Connection.cleanup``) behind an out-of-process client
(``starter._client``, ``Connection.close``). Looking only in the old place found nothing: the
driver outlived its event loop and a cancelled retest waited out the whole close bound (10 s
instead of at once). The installed version's own layout is checked too, so the next move fails
here instead of in the browser lifecycle tests.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))

from scanner_tools import proof_of_exploit as poe  # noqa: E402


class _Connection:
    def __init__(self, method: str):
        self.closed_with: list[str] = []
        setattr(self, method, self.closed_with.append)


def test_playwright_1_63_layout():
    proc = object()
    connection = _Connection("cleanup")
    connection._transport = types.SimpleNamespace(_proc=proc)
    starter = types.SimpleNamespace(_connection=connection)
    assert poe._driver_process(starter) is proc
    poe._close_connection(starter, "gone")
    assert connection.closed_with == ["gone"]


def test_playwright_1_65_layout():
    proc = object()
    connection = _Connection("close")
    client = types.SimpleNamespace(_transport=types.SimpleNamespace(_proc=proc), _connection=connection)
    starter = types.SimpleNamespace(_client=client)
    assert poe._driver_process(starter) is proc
    poe._close_connection(starter, "gone")
    assert connection.closed_with == ["gone"]


def test_a_starter_before_start_has_no_driver_and_an_unknown_layout_is_reported():
    assert poe._driver_process(types.SimpleNamespace(_client=None)) is None
    with pytest.raises(AttributeError):
        poe._close_connection(types.SimpleNamespace(_client=None), "gone")


@pytest.mark.skipif(importlib.util.find_spec("playwright") is None, reason="Playwright is not installed")
def test_the_installed_playwright_keeps_its_driver_where_we_look():
    """Read from the installed package's source, without starting a driver."""
    import inspect

    from playwright.async_api import _context_manager

    source = inspect.getsource(_context_manager)
    if "_client" in source:  # 1.65 and later: the out-of-process client
        from playwright._impl import out_of_process, transport

        client_source = inspect.getsource(out_of_process.PlaywrightClient)
        assert "self._transport" in client_source and "self._connection" in client_source
        assert "self._proc" in inspect.getsource(transport.PipeTransport)
        from playwright._impl.connection import Connection
        assert callable(getattr(Connection, "close", None))
    else:  # up to 1.63
        from playwright._impl._connection import Connection
        assert "self._connection" in source
        assert callable(getattr(Connection, "cleanup", None))

import pytest
from fastapi import HTTPException

from schedules.router import _reject_ambiguous_numeric_target


def test_schedule_rejects_legacy_integer_host_form():
    with pytest.raises(HTTPException, match="ambiguous integer hostname"):
        _reject_ambiguous_numeric_target("http://2852039166")


@pytest.mark.parametrize("url", [
    "https://example.test",
    "http://169.254.169.254",
    "http://host.docker.internal:8080",
])
def test_schedule_accepts_visible_host_forms(url):
    _reject_ambiguous_numeric_target(url)

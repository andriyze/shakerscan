import asyncio

import pytest

from schedules.router import (
    ScheduleTargetSafetyError,
    validate_schedule_target_destination,
)


def _records(*addresses: str):
    return [(None, None, None, None, (address, 443)) for address in addresses]


def test_schedule_rejects_ambiguous_integer_host_after_resolution():
    async def resolver(_host, _port):
        return _records("169.254.169.254")

    with pytest.raises(ScheduleTargetSafetyError, match="must not resolve"):
        asyncio.run(validate_schedule_target_destination(
            "http://2852039166/", resolver=resolver,
        ))


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/",
    "http://[::ffff:169.254.169.254]/",
    "http://127.0.0.1/",
])
def test_schedule_rejects_visible_non_public_addresses(url):
    with pytest.raises(ScheduleTargetSafetyError, match="must not resolve"):
        asyncio.run(validate_schedule_target_destination(url))


def test_schedule_accepts_only_fully_public_resolution():
    async def resolver(_host, _port):
        return _records(
            "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946",
        )

    assert asyncio.run(validate_schedule_target_destination(
        "https://example.test/", resolver=resolver,
    )) == ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")


def test_schedule_rejects_mixed_public_and_private_dns_answers():
    async def resolver(_host, _port):
        return _records("93.184.216.34", "10.0.0.2")

    with pytest.raises(ScheduleTargetSafetyError, match="must not resolve"):
        asyncio.run(validate_schedule_target_destination(
            "https://example.test/", resolver=resolver,
        ))

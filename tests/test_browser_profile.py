"""Contract tests for private browser-profile materialization inputs.

These checks deliberately stop before launching Chromium.  Runtime browser and target
verification belongs to the release E2E gate, not this unit contract.
"""

import pytest

from scanner.scanner_tools.browser_profile import (
    BROWSER_STORAGE_SCHEMA,
    BrowserProfileError,
    normalize_browser_storage_seed,
)


@pytest.mark.parametrize(
    ("seed", "expected"),
    [
        (
            {
                "schema_version": BROWSER_STORAGE_SCHEMA,
                "kind": "cookie_header",
                "value": "session=opaque",
            },
            {"kind": "cookie_header", "value": "session=opaque"},
        ),
        (
            {
                "schema_version": BROWSER_STORAGE_SCHEMA,
                "kind": "local_storage",
                "key": "auth.token",
                "value": "opaque",
            },
            {"kind": "local_storage", "key": "auth.token", "value": "opaque"},
        ),
    ],
)
def test_browser_storage_seed_normalizes_without_exposing_extra_fields(seed, expected):
    value = dict(seed)
    value["ignored"] = "not-forwarded"

    assert normalize_browser_storage_seed(value) == expected


@pytest.mark.parametrize(
    "seed",
    [
        {},
        {"schema_version": "scan-browser-storage/v0", "kind": "cookie_header", "value": "x=1"},
        {"schema_version": BROWSER_STORAGE_SCHEMA, "kind": "local_storage", "key": "bad key", "value": "x"},
        {"schema_version": BROWSER_STORAGE_SCHEMA, "kind": "cookie_header", "key": "x", "value": "x=1"},
        {"schema_version": BROWSER_STORAGE_SCHEMA, "kind": "unsupported", "value": "x"},
    ],
)
def test_browser_storage_seed_rejects_untrusted_shapes(seed):
    with pytest.raises(BrowserProfileError):
        normalize_browser_storage_seed(seed)

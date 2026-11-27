#!/usr/bin/env python3
"""Render the Homebrew formula for a published client version.

Usage: render_formula.py VERSION OUTPUT [--metadata FILE]

The sdist URL and sha256 come from PyPI's JSON API for that exact version (retrying while a
fresh release propagates) or from a saved metadata file; the placeholders in
``shakerscan.rb.in`` are replaced and the formula is written to OUTPUT.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

TEMPLATE = Path(__file__).with_name("shakerscan.rb.in")
PYPI_JSON = "https://pypi.org/pypi/shakerscan/{version}/json"
PLACEHOLDERS = ("@VERSION@", "@URL@", "@SHA256@")


def sdist_for(version: str, metadata: dict[str, Any]) -> tuple[str, str]:
    """The sdist download URL and sha256 in PyPI's per-version metadata."""
    for entry in metadata.get("urls") or []:
        if entry.get("packagetype") != "sdist":
            continue
        digest = str((entry.get("digests") or {}).get("sha256") or "")
        url = str(entry.get("url") or "")
        if url and len(digest) == 64:
            return url, digest
    raise LookupError(f"PyPI metadata for shakerscan {version} has no sdist with a sha256 digest")


def render(version: str, url: str, sha256: str, template: str | None = None) -> str:
    text = TEMPLATE.read_text(encoding="utf-8") if template is None else template
    values = dict(zip(PLACEHOLDERS, (version, url, sha256)))
    for placeholder, value in values.items():
        if placeholder not in text:
            raise ValueError(f"the formula template does not contain {placeholder}")
        text = text.replace(placeholder, value)
    return text


def fetch_metadata(version: str, *, attempts: int = 20, delay_seconds: float = 15.0) -> dict[str, Any]:
    url = PYPI_JSON.format(version=version)
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code != 404 or attempt == attempts - 1:
                raise
        time.sleep(delay_seconds)
    raise RuntimeError("unreachable")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version")
    parser.add_argument("output", type=Path)
    parser.add_argument("--metadata", type=Path, help="saved PyPI JSON instead of a network fetch")
    args = parser.parse_args(argv)
    metadata = json.loads(args.metadata.read_text(encoding="utf-8")) if args.metadata else fetch_metadata(args.version)
    url, sha256 = sdist_for(args.version, metadata)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(args.version, url, sha256), encoding="utf-8")
    print(f"{args.output}: shakerscan {args.version} from {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

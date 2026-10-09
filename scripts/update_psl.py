#!/usr/bin/env python3
"""Refresh the bundled Public Suffix List snapshot and its pin, for a reviewed change.

Never run at runtime: the engine only reads ``api/scope/data/public_suffix_list.dat`` and checks
it against ``api/scope/data/public_suffix_list.sha256`` (see ``api/scope/psl.py``).

    python3 scripts/update_psl.py <commit-sha> <commit-date YYYY-MM-DD>

Downloads ``public_suffix_list.dat`` at that exact upstream commit of publicsuffix/list,
refuses a file without the MPL notice or the PRIVATE section, and rewrites the snapshot and pin.
Review the diff (especially removals from the private section) before committing.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "api" / "scope" / "data"
REPO = "https://github.com/publicsuffix/list"
RAW = "https://raw.githubusercontent.com/publicsuffix/list/{commit}/public_suffix_list.dat"


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not re.fullmatch(r"[0-9a-f]{40}", argv[0]) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", argv[1]):
        print(__doc__, file=sys.stderr)
        return 2
    commit, date = argv
    with urllib.request.urlopen(RAW.format(commit=commit), timeout=60) as response:  # noqa: S310 (fixed https URL)
        raw = response.read()
    text = raw.decode("utf-8")
    if not text.startswith("// This Source Code Form is subject to the terms of the Mozilla Public"):
        raise SystemExit("downloaded list lacks its MPL-2.0 notice")
    if "===BEGIN PRIVATE DOMAINS===" not in text or "===BEGIN ICANN DOMAINS===" not in text:
        raise SystemExit("downloaded list lacks the ICANN or PRIVATE section")
    digest = hashlib.sha256(raw).hexdigest()
    (DATA / "public_suffix_list.dat").write_bytes(raw)
    (DATA / "public_suffix_list.sha256").write_text(
        "# Public Suffix List snapshot pin, written by scripts/update_psl.py. Never fetched at runtime.\n"
        f"# source: {REPO}/blob/{commit}/public_suffix_list.dat\n"
        f"# commit: {commit}\n"
        f"# date: {date}\n"
        "# licence: MPL-2.0 (the snapshot is unmodified and keeps its notice)\n"
        f"{digest}  public_suffix_list.dat\n",
        encoding="utf-8",
    )
    print(f"public_suffix_list.dat {commit[:12]} ({date}) sha256 {digest}")
    print("Update the commit named in THIRD_PARTY_NOTICES.md, then regenerate install/MANIFEST.sha256.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

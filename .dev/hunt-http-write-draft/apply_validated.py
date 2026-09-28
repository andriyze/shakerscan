#!/usr/bin/env python3
"""Temporary authoring wrapper correcting the draft's ambiguous indentation anchor.

Full-source application and 74 focused tests have been exercised locally. This
wrapper and the original applicator stay on the temporary builder branch only.
"""
from __future__ import annotations
import sys
from pathlib import Path
import apply_fix

original_once = apply_fix.once


def exact_line_once(source: str, before: str, after: str, label: str) -> str:
    # A twelve-space prefix also matched a sixteen-space nested principal branch.
    # Match the complete line, not a substring of a differently indented line.
    if before == '            principal_slot = (\n':
        before = '\n' + before
        after = '\n' + after
    return original_once(source, before, after, label)


apply_fix.once = exact_line_once
status = apply_fix.main()
if status or '--check' in sys.argv:
    raise SystemExit(status)
root = Path(sys.argv[1]).resolve()
old = 'download "$REPO_RAW_BASE/api/runtime/capability_registry.py" "$INSTALL_DIR/api/runtime/capability_registry.py"\n'
new = old + 'download "$REPO_RAW_BASE/api/runtime/hunt_http_contract.py" "$INSTALL_DIR/api/runtime/hunt_http_contract.py"\n'
for filename in ('install/index.sh', 'install/index.html'):
    path = root / filename
    text = path.read_text(encoding='utf-8')
    path.write_text(original_once(text, old, new, filename), encoding='utf-8')
path = root / 'docs/hunt-http-writes.md'
text = path.read_text(encoding='utf-8')
heading = '# Hunt HTTP workflow writes\n'
text = original_once(text, heading, heading + '\n**Status**: Implemented for direct HTTP workflow requests; active collection replay\nand complete secret-bearing pairing workflows remain unfinished as documented below.\n', str(path))
path.write_text(text, encoding='utf-8')
print('Installer copies include the new helper; workflow scope and remaining work are documented.')

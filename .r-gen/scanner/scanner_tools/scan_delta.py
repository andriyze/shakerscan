"""
Scan Delta / Change Detection Module

Compares current scan results against a baseline to identify:
- New findings (in current but not in baseline)
- Resolved findings (in baseline but not in current)
- Score and grade changes

Enables "continuous monitoring" by tracking what changed between scans.
"""

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


def extract_finding_id(finding: dict[str, Any]) -> str:
    """
    Extract a stable identifier for a finding.

    Uses the 'id' field which is deterministic (tool:hash).
    Falls back to title + tool if id is missing.
    """
    if finding.get('id'):
        return finding['id']

    # Fallback: create ID from tool + title using deterministic hash
    tool = finding.get('tool', 'unknown')
    title = finding.get('title', 'unknown')
    title_hash = hashlib.md5(title.encode('utf-8')).hexdigest()[:8]
    return f"{tool}:{title_hash}"


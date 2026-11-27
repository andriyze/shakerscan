#!/usr/bin/env python3
"""Read-only guard against publishing operator output or high-confidence secret formats.

This is a prevention check, not proof that every secret or historical commit is clean.
Only names and line numbers are printed. Synthetic AWS sample values are allowlisted by
exact digest, never by excluding an entire tests directory.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_DIRS = {'results', 'audit-results', 'exports', 'captures', 'quarantine', 'operator-data', 'backups', '.shakerscan-fleet'}
RAW_SUFFIXES = {'.har', '.pcap', '.pcapng', '.sqlite', '.sqlite3', '.dump', '.log'}
PATTERNS = {
    'GitHub token': re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),
    'AWS access key': re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'provider project key': re.compile(rb'\bsk-proj-[A-Za-z0-9_-]{45,}\b'),
    'private key material': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{96,}'),
}
# Exact, reviewed synthetic identifiers used by security-detector fixtures.
SYNTHETIC_AWS_DIGESTS = {
    'ba13c23e0e6d7463d7ef35a68802ad27a8b1938a70c353c0c471db9ea13beffb',
    '457643f44d19aed85fd756aa50cc0cd6b57376d4e8f5a72f9f85972a522002a3',
    '1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3',
}


def violations(path: str, content: bytes) -> list[str]:
    p = Path(path)
    problems = []
    fixture = path.startswith('tests/fixtures/')
    if p.parts[0] in PRIVATE_DIRS or (p.suffix in RAW_SUFFIXES and not fixture):
        problems.append(f'{path}: operator output must not be tracked')
    if p.name == '.env' or (p.name.startswith('.env.') and not p.name.endswith(('.example', '.sample', '.template'))):
        problems.append(f'{path}: local environment file must not be tracked')
    if path.startswith('.claude/projects/') or path == '.claude/settings.local.json':
        problems.append(f'{path}: private local agent state must not be tracked')
    for label, pattern in PATTERNS.items():
        for match in pattern.finditer(content):
            if label == 'AWS access key' and path.startswith('tests/') and hashlib.sha256(match.group()).hexdigest() in SYNTHETIC_AWS_DIGESTS:
                continue
            line = content[:match.start()].count(b'\n') + 1
            problems.append(f'{path}:{line}: possible {label}; inspect and rotate privately if real')
    return problems


def main() -> int:
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    problems = []
    for path in paths:
        if path and (ROOT / path).is_file():
            problems.extend(violations(path, (ROOT / path).read_bytes()))
    for problem in problems:
        print(problem)
    if problems:
        return 1
    print('Public repository hygiene: tracked files passed; Git history and external copies were not scanned')
    return 0


if __name__ == '__main__':
    sys.exit(main())

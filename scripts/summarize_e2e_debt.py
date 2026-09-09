#!/usr/bin/env python3
"""Report actual assertions separately from policy-accepted E2E debt.

Offline only; this command never runs tests, changes waivers, or sends traffic.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import Any


def summarize(card: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(card, dict) or not isinstance(card.get('areas'), list):
        raise ValueError('Expected an E2E scorecard with an areas array')
    counts = dict(passed=0, failed=0, skipped=0, unknown=0, accepted_failures=0, unexpected_failures=0, debt_xpasses=0)
    exceptions = []
    for area in card['areas']:
        if not isinstance(area, dict) or not isinstance(area.get('rows'), list):
            raise ValueError('Each area must have a rows array')
        for row in area['rows']:
            if not isinstance(row, dict):
                raise ValueError('Each assertion must be an object')
            debt = row.get('xfail') is True
            if row.get('skipped') is True:
                actual = 'skipped'
            else:
                observed = row.get('xpass') if debt else row.get('passed')
                actual = 'passed' if observed is True else 'failed' if observed is False else 'unknown'
            counts[actual] += 1
            if actual == 'failed':
                counts['accepted_failures' if debt else 'unexpected_failures'] += 1
            if debt and actual == 'passed':
                counts['debt_xpasses'] += 1
            if debt or actual in {'failed', 'unknown'}:
                # Do not copy raw detail/evidence or target data into this summary.
                exceptions.append({'area': area.get('area'), 'name': row.get('name'),
                                   'actual': actual, 'declared_debt': debt,
                                   'reason': row.get('reason') if debt else None})
    return {'schema': 'e2e-actual-assertions/v1', 'policy_gate': card.get('gate'),
            'counts': counts, 'exceptions': exceptions,
            'assertions_clean': counts['failed'] == 0 and counts['unknown'] == 0}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scorecard', type=Path)
    parser.add_argument('--strict', action='store_true', help='Fail on every actual failed/unknown assertion, including declared debt')
    args = parser.parse_args()
    try:
        result = summarize(json.loads(args.scorecard.read_text()))
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f'Cannot summarize scorecard: {exc}\n')
    print(json.dumps(result, indent=2))
    return int(not result['assertions_clean']) if args.strict else int(
        result['counts']['unexpected_failures'] > 0 or result['counts']['unknown'] > 0)


if __name__ == '__main__':
    raise SystemExit(main())

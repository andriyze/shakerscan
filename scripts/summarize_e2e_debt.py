#!/usr/bin/env python3
"""Offline E2E reporting: actual outcomes, accepted debt, and validation completeness."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import Any, Sequence


def summarize(card: dict[str, Any], *, required_areas: Sequence[str] = (),
              required_checks: Sequence[str] = ()) -> dict[str, Any]:
    if not isinstance(card, dict) or not isinstance(card.get('areas'), list):
        raise ValueError('Expected an E2E scorecard with an areas array')
    counts = dict(passed=0, failed=0, skipped=0, unknown=0, accepted_failures=0, unexpected_failures=0, debt_xpasses=0)
    exceptions, errors = [], []
    area_names, executed_checks = set(), set()
    for area in card['areas']:
        if not isinstance(area, dict) or not isinstance(area.get('rows'), list):
            raise ValueError('Each area must have a rows array')
        name = area.get('area')
        if not isinstance(name, str) or not name:
            errors.append('An area has no name')
            name = ''
        if name in area_names:
            errors.append(f'Duplicate area: {name}')
        area_names.add(name)
        area_executed, names = 0, set()
        if area.get('gate') is not None and str(area['gate']).lower() != 'pass':
            errors.append(f'Upstream area gate did not pass: {name}')
        for row in area['rows']:
            if not isinstance(row, dict):
                raise ValueError('Each assertion must be an object')
            check = row.get('name')
            if not isinstance(check, str) or not check:
                errors.append(f'Unnamed assertion in area: {name}')
                check = ''
            if check in names:
                errors.append(f'Duplicate assertion in area: {name}')
            names.add(check)
            debt = row.get('xfail') is True
            if row.get('skipped') is True:
                actual = 'skipped'
            else:
                observed = row.get('xpass') if debt else row.get('passed')
                actual = 'passed' if observed is True else 'failed' if observed is False else 'unknown'
            counts[actual] += 1
            if actual in {'passed', 'failed'}:
                area_executed += 1
                executed_checks.add((name, check))
            if actual == 'failed':
                counts['accepted_failures' if debt else 'unexpected_failures'] += 1
            if debt and actual == 'passed':
                counts['debt_xpasses'] += 1
            if debt or actual in {'failed', 'unknown'}:
                # No raw response bodies, detail, credentials, or evidence exports.
                exceptions.append({'area': name, 'name': check,
                                   'actual': actual, 'declared_debt': debt,
                                   'reason': row.get('reason') if debt else None})
        if area_executed == 0:
            errors.append(f'No assertions executed in area: {name}')
    if not card['areas']:
        errors.append('No validation areas were recorded')
    for area in sorted(set(required_areas) - area_names):
        errors.append(f'Required area missing: {area}')
    for requirement in required_checks:
        area, separator, check = requirement.partition(':')
        if not separator or not area or not check:
            raise ValueError('Required checks use AREA:EXACT ASSERTION NAME')
        if (area, check) not in executed_checks:
            errors.append(f'Required assertion did not execute: {requirement}')
    executed = counts['passed'] + counts['failed']
    observed_clean = executed > 0 and counts['failed'] == 0 and counts['unknown'] == 0
    complete = executed > 0 and counts['unknown'] == 0 and not errors
    upstream_pass = str(card.get('gate') or '').lower() == 'pass'
    # Never turn FAIL, missing, or unknown upstream status into a successful exit.
    if not upstream_pass:
        errors.append('Upstream policy gate did not pass or is missing')
    policy_validated = complete and upstream_pass and counts['unexpected_failures'] == 0
    return {'schema': 'e2e-actual-assertions/v2', 'policy_gate': card.get('gate'),
            'counts': counts, 'executed_assertions': executed, 'exceptions': exceptions,
            'observed_assertions_clean': observed_clean,
            'validation_complete': complete, 'policy_validated': policy_validated,
            'validation_errors': errors,
            'assertions_clean': observed_clean and complete and upstream_pass}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scorecard', type=Path)
    parser.add_argument('--strict', action='store_true', help='Reject actual failures including accepted debt')
    parser.add_argument('--require-area', action='append', default=[])
    parser.add_argument('--require-check', action='append', default=[], metavar='AREA:NAME')
    args = parser.parse_args()
    try:
        result = summarize(json.loads(args.scorecard.read_text()),
            required_areas=args.require_area, required_checks=args.require_check)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f'Cannot summarize scorecard: {exc}\n')
    print(json.dumps(result, indent=2))
    return int(not (result['assertions_clean'] if args.strict else result['policy_validated']))


if __name__ == '__main__':
    raise SystemExit(main())

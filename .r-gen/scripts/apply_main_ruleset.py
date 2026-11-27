#!/usr/bin/env python3
"""Apply or verify the committed `main` ruleset against the live GitHub repository.

`.github/rulesets/main.json` is only a promise until it is imported. The repository ran for weeks
with a ruleset that blocked deletion and force-push and nothing else, while every document said
pull requests and required checks guarded `main`. This script makes the committed file the source
of truth: `--check` fails when the live rules covering `main` do not enforce everything the file
declares, and `--apply` creates or updates the live ruleset from the file.

    python3 scripts/apply_main_ruleset.py --check   # exit 1 when main is under-protected
    python3 scripts/apply_main_ruleset.py --apply   # create/update the live ruleset

Both need `gh` authenticated with repository administration rights (the workflow token can read
rulesets; only an operator can apply them).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
RULESET_FILE = ROOT / ".github" / "rulesets" / "main.json"
MAIN_REFS = {"refs/heads/main", "~DEFAULT_BRANCH", "~ALL"}


class RulesetError(RuntimeError):
    pass


def _gh(*args: str, payload: Mapping[str, Any] | None = None) -> Any:
    command = ["gh", "api", *args]
    stdin = None
    if payload is not None:
        command += ["--input", "-"]
        stdin = json.dumps(payload)
    try:
        output = subprocess.check_output(command, input=stdin, text=True, stderr=subprocess.PIPE)
    except FileNotFoundError as exc:
        raise RulesetError("gh CLI is required") from exc
    except subprocess.CalledProcessError as exc:
        raise RulesetError(f"gh api {' '.join(args)} failed: {exc.stderr.strip()}") from exc
    return json.loads(output) if output.strip() else None


def repository_slug(explicit: str | None = None) -> str:
    slug = explicit or os.environ.get("GITHUB_REPOSITORY") or ""
    if not slug:
        try:
            slug = subprocess.check_output(
                ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
                text=True, stderr=subprocess.PIPE,
            ).strip()
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise RulesetError(f"cannot resolve the repository from gh: {exc}") from exc
    if "/" not in slug:
        raise RulesetError(f"cannot determine repository slug: {slug!r}")
    return slug


def covers_main(ruleset: Mapping[str, Any]) -> bool:
    if ruleset.get("target") != "branch" or ruleset.get("enforcement") != "active":
        return False
    ref_name = (ruleset.get("conditions") or {}).get("ref_name") or {}
    include = set(ref_name.get("include") or [])
    exclude = set(ref_name.get("exclude") or [])
    return bool(include & MAIN_REFS) and not (exclude & {"refs/heads/main"})


def _rule_map(ruleset: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(rule.get("type")): dict(rule.get("parameters") or {})
        for rule in ruleset.get("rules") or []
        if isinstance(rule, Mapping) and rule.get("type")
    }


def missing_protections(
    committed: Mapping[str, Any], live_rulesets: Iterable[Mapping[str, Any]],
) -> list[str]:
    """Everything the committed ruleset requires that no live ruleset covering main enforces."""
    live = [ruleset for ruleset in live_rulesets if covers_main(ruleset)]
    problems: list[str] = []
    if not live:
        return ["no active branch ruleset covers refs/heads/main"]
    for ruleset in live:
        actors = ruleset.get("bypass_actors") or []
        if actors:
            problems.append(f"ruleset {ruleset.get('name')!r} grants bypass to {len(actors)} actor(s)")
    live_rules = [_rule_map(ruleset) for ruleset in live]
    for rule_type, parameters in _rule_map(committed).items():
        holders = [rules[rule_type] for rules in live_rules if rule_type in rules]
        if not holders:
            problems.append(f"rule {rule_type!r} is not enforced on main")
            continue
        if rule_type == "pull_request":
            wanted = int(parameters.get("required_approving_review_count") or 0)
            if all(int(held.get("required_approving_review_count") or 0) < wanted for held in holders):
                problems.append("pull_request: required approving review count is lower than committed")
            if parameters.get("required_review_thread_resolution") and not any(
                held.get("required_review_thread_resolution") for held in holders
            ):
                problems.append("pull_request: review thread resolution is not required")
        elif rule_type == "required_status_checks":
            wanted_checks = {
                str(check.get("context"))
                for check in parameters.get("required_status_checks") or []
            }
            enforced: set[str] = set()
            strict = False
            for held in holders:
                enforced |= {
                    str(check.get("context")) for check in held.get("required_status_checks") or []
                }
                strict = strict or bool(held.get("strict_required_status_checks_policy"))
            absent = sorted(wanted_checks - enforced)
            if absent:
                problems.append(f"required_status_checks: not required on main: {', '.join(absent)}")
            if parameters.get("strict_required_status_checks_policy") and not strict:
                problems.append("required_status_checks: branches are not required to be up to date")
    return problems


def _live_rulesets(slug: str) -> list[dict[str, Any]]:
    summaries = _gh(f"repos/{slug}/rulesets") or []
    return [_gh(f"repos/{slug}/rulesets/{item['id']}") for item in summaries if item.get("id")]


def check(slug: str, committed: Mapping[str, Any]) -> int:
    problems = missing_protections(committed, _live_rulesets(slug))
    if problems:
        print(f"main is under-protected on {slug}:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("Run: python3 scripts/apply_main_ruleset.py --apply", file=sys.stderr)
        return 1
    print(f"main ruleset on {slug} enforces everything in {RULESET_FILE.relative_to(ROOT)}")
    return 0


def apply(slug: str, committed: Mapping[str, Any]) -> int:
    existing = next(
        (item for item in _gh(f"repos/{slug}/rulesets") or [] if item.get("name") == committed["name"]),
        None,
    )
    if existing:
        _gh(f"repos/{slug}/rulesets/{existing['id']}", "--method", "PUT", payload=committed)
        print(f"updated ruleset {committed['name']!r} (id {existing['id']}) on {slug}")
    else:
        created = _gh(f"repos/{slug}/rulesets", "--method", "POST", payload=committed)
        print(f"created ruleset {committed['name']!r} (id {created.get('id')}) on {slug}")
    return check(slug, committed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--repo", help="owner/name (default: GITHUB_REPOSITORY or the gh default)")
    args = parser.parse_args(argv)
    try:
        committed = json.loads(RULESET_FILE.read_text(encoding="utf-8"))
        slug = repository_slug(args.repo)
        return apply(slug, committed) if args.apply else check(slug, committed)
    except (OSError, RulesetError, json.JSONDecodeError, KeyError) as exc:
        print(f"ruleset: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

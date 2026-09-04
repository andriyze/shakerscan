#!/usr/bin/env python3
"""Delete expired `candidate-<sha>-<run>` tags from Docker Hub.

Every release-candidate run that reaches the manifest job pushes four public multi-architecture
manifests under a `candidate-*` tag. Nothing removed them, so dozens of failed candidates sat on
Docker Hub looking official. Version tags and `latest` are never touched; a candidate is deleted
only after the promotion window (the receipt artifact's 30-day retention) has passed, so a
promotable candidate cannot disappear under the promotion workflow.

    python3 scripts/cleanup_candidate_tags.py                 # dry run, lists what would go
    python3 scripts/cleanup_candidate_tags.py --delete        # really delete
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

HUB = "https://hub.docker.com/v2"
REPOSITORIES = (
    "shakerscan/shakerscan-scanner",
    "shakerscan/shakerscan-api",
    "shakerscan/shakerscan-ui",
    "shakerscan/shakerscan-model-intake-signer",
    "shakerscan/shakerscan-model-intake",
)
CANDIDATE_TAG = re.compile(r"^candidate-[0-9a-f]{40}-[0-9]+$")


class HubError(RuntimeError):
    pass


def _request(method: str, url: str, token: str | None = None, body: Mapping[str, Any] | None = None) -> Any:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"JWT {token}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        raise HubError(f"{method} {url} -> HTTP {exc.code}: {exc.read()[:200]!r}") from exc
    except urllib.error.URLError as exc:
        raise HubError(f"{method} {url} failed: {exc.reason}") from exc
    return json.loads(payload) if payload.strip() else None


def login(username: str, password: str) -> str:
    payload = _request("POST", f"{HUB}/users/login/", body={"username": username, "password": password})
    token = str((payload or {}).get("token") or "")
    if not token:
        raise HubError("Docker Hub login returned no token")
    return token


def list_tags(repository: str, token: str) -> list[dict[str, Any]]:
    tags: list[dict[str, Any]] = []
    url: str | None = f"{HUB}/repositories/{repository}/tags/?page_size=100&name=candidate-"
    while url:
        page = _request("GET", url, token) or {}
        tags.extend(item for item in page.get("results") or [] if isinstance(item, Mapping))
        url = page.get("next")
    return tags


def expired_candidates(
    tags: Iterable[Mapping[str, Any]], *, now: datetime, older_than_days: int,
) -> list[str]:
    """Only well-formed candidate tags whose last update is older than the window."""
    cutoff = now - timedelta(days=older_than_days)
    expired: list[str] = []
    for tag in tags:
        name = str(tag.get("name") or "")
        if not CANDIDATE_TAG.fullmatch(name):
            continue
        updated_raw = str(tag.get("last_updated") or tag.get("tag_last_pushed") or "")
        if not updated_raw:
            continue
        updated = datetime.fromisoformat(updated_raw.replace("Z", "+00:00"))
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if updated < cutoff:
            expired.append(name)
    return sorted(expired)


def delete_tag(repository: str, tag: str, token: str) -> None:
    if not CANDIDATE_TAG.fullmatch(tag):
        raise HubError(f"refusing to delete a non-candidate tag: {tag}")
    _request("DELETE", f"{HUB}/repositories/{repository}/tags/{urllib.parse.quote(tag)}/", token)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--older-than-days", type=int, default=30)
    parser.add_argument("--delete", action="store_true", help="actually delete; default is a dry run")
    parser.add_argument("--repository", action="append", default=[], help="override the repositories to clean")
    args = parser.parse_args(argv)
    username = os.environ.get("DOCKERHUB_USERNAME") or ""
    password = os.environ.get("DOCKERHUB_TOKEN") or ""
    if not username or not password:
        print("DOCKERHUB_USERNAME and DOCKERHUB_TOKEN are required", file=sys.stderr)
        return 2
    try:
        token = login(username, password)
        now = datetime.now(timezone.utc)
        total = 0
        for repository in args.repository or REPOSITORIES:
            expired = expired_candidates(list_tags(repository, token), now=now, older_than_days=args.older_than_days)
            for tag in expired:
                total += 1
                if args.delete:
                    delete_tag(repository, tag, token)
                    print(f"deleted {repository}:{tag}")
                else:
                    print(f"would delete {repository}:{tag}")
        print(f"{'deleted' if args.delete else 'would delete'} {total} expired candidate tag(s)")
    except HubError as exc:
        print(f"candidate cleanup: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Canonical tokenizer and configuration component identities for exact model bundles."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any


TOKENIZER_NAMES = {
    "added_tokens.json", "merges.txt", "sentencepiece.bpe.model", "special_tokens_map.json",
    "spiece.model", "tokenizer.json", "tokenizer.model", "tokenizer_config.json",
    "vocab.json", "vocab.txt",
}
CONFIG_SUFFIXES = {".json", ".toml", ".yaml", ".yml"}


def _digest(entries: list[dict[str, str]]) -> str | None:
    if not entries:
        return None
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def component_identities(files: Any) -> dict[str, Any]:
    if not isinstance(files, list):
        raise ValueError("repository component inventory must be a list")
    tokenizer: list[dict[str, str]] = []
    configuration: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("repository component entry is invalid")
        path_text = str(item.get("path") or "")
        path = PurePosixPath(path_text)
        digest = str(item.get("sha256") or "").lower()
        if not path.parts or path.is_absolute() or ".." in path.parts or path_text in seen:
            raise ValueError("repository component path is unsafe or duplicated")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("repository component digest is invalid")
        seen.add(path_text)
        entry = {"path": path.as_posix(), "sha256": digest}
        name = path.name.lower()
        if name in TOKENIZER_NAMES:
            tokenizer.append(entry)
        elif path.suffix.lower() in CONFIG_SUFFIXES:
            configuration.append(entry)
    tokenizer.sort(key=lambda entry: entry["path"])
    configuration.sort(key=lambda entry: entry["path"])
    return {
        "schema_version": "model-intake-component-identities/v1",
        "tokenizer_sha256": _digest(tokenizer),
        "configuration_sha256": _digest(configuration),
        "tokenizer_file_count": len(tokenizer),
        "configuration_file_count": len(configuration),
    }


__all__ = ["CONFIG_SUFFIXES", "TOKENIZER_NAMES", "component_identities"]

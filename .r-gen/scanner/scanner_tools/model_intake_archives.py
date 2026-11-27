"""Bounded, non-extracting recursive archive inventory for Model Intake."""

from __future__ import annotations

import io
import json
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


MAX_ARCHIVE_DEPTH = 3
MAX_ARCHIVE_MEMBERS = 10_000
MAX_EXPANDED_BYTES = 2_000_000_000
MAX_NESTED_MEMBER_BYTES = 100_000_000
MAX_COMPRESSION_RATIO = 100

PICKLE_NAMES = (".pkl", ".pickle", "data.pkl")
NESTED_NAMES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2")
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".sh", ".bash", ".ps1", ".bat", ".cmd"}
RISKY_CONFIG_NAMES = {"config.json", "tokenizer_config.json", "generation_config.json"}
MAX_CONFIG_BYTES = 262_144


def _unsafe_path(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        normalized.startswith("/")
        or ".." in path.parts
        or bool(re.match(r"^[A-Za-z]:", normalized))
        or "\x00" in normalized
    )


def _new_result() -> dict[str, Any]:
    return {
        "is_archive": False,
        "is_zip": False,
        "is_tar": False,
        "format": None,
        "entries": [],
        "risky_entries": [],
        "pickle_entries": [],
        "executable_entries": [],
        "path_traversal_entries": [],
        "nested_archive_entries": [],
        "archive_link_entries": [],
        "archive_device_entries": [],
        "zip_bomb_entries": [],
        "risky_config_entries": [],
        "members_discovered": 0,
        "members_inspected": 0,
        "expanded_bytes": 0,
        "max_depth_observed": 0,
        "complete": True,
        "limit_reasons": [],
        "errors": [],
    }


def _append_unique(result: dict[str, Any], key: str, value: Any, *, limit: int = 1000) -> None:
    values = result[key]
    if value not in values and len(values) < limit:
        values.append(value)


def _record_risky_config(result: dict[str, Any], name: str, raw: bytes) -> None:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        result["complete"] = False
        _append_unique(result, "errors", {"path": name, "error": "model_config_json_invalid"}, limit=100)
        return

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                lowered = str(key).lower()
                if lowered == "trust_remote_code" and child is True:
                    _append_unique(result, "risky_config_entries", {"entry": name, "risk": "trust_remote_code"})
                if lowered == "chat_template" and isinstance(child, str) and any(
                    marker in child.lower() for marker in ("tool_call", "system", "developer")
                ):
                    _append_unique(result, "risky_config_entries", {"entry": name, "risk": "risky_chat_template"})
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(parsed)


def _record_member(
    result: dict[str, Any],
    name: str,
    size: int,
    *,
    depth: int,
    compressed_size: int | None = None,
    link: bool = False,
    device: bool = False,
    max_expanded_bytes: int = MAX_EXPANDED_BYTES,
) -> bool:
    result["members_discovered"] += 1
    result["max_depth_observed"] = max(result["max_depth_observed"], depth)
    if result["members_discovered"] > MAX_ARCHIVE_MEMBERS:
        result["complete"] = False
        _append_unique(result, "limit_reasons", "member_count_limit")
        return False
    result["members_inspected"] += 1
    result["expanded_bytes"] += max(0, size)
    if result["expanded_bytes"] > max_expanded_bytes:
        result["complete"] = False
        _append_unique(result, "limit_reasons", "expanded_byte_limit")
        return False
    _append_unique(result, "entries", name, limit=MAX_ARCHIVE_MEMBERS)
    lowered = name.lower()
    suffix = Path(lowered).suffix
    if _unsafe_path(name):
        _append_unique(result, "path_traversal_entries", name)
    if lowered.endswith(PICKLE_NAMES):
        _append_unique(result, "pickle_entries", name)
        _append_unique(result, "risky_entries", name)
    if suffix in EXECUTABLE_EXTENSIONS:
        _append_unique(result, "executable_entries", name)
    if lowered.endswith(NESTED_NAMES):
        _append_unique(result, "nested_archive_entries", name)
    if link:
        _append_unique(result, "archive_link_entries", name)
    if device:
        _append_unique(result, "archive_device_entries", name)
    if compressed_size is not None and compressed_size > 0 and size > 1_000_000 and size / compressed_size > MAX_COMPRESSION_RATIO:
        _append_unique(result, "zip_bomb_entries", name)
    return True


def _inspect_zip(
    handle: Any,
    result: dict[str, Any],
    *,
    prefix: str,
    depth: int,
    max_expanded_bytes: int,
) -> None:
    with zipfile.ZipFile(handle) as archive:
        for info in archive.infolist():
            name = f"{prefix}!/{info.filename}" if prefix else info.filename
            if not _record_member(
                result,
                name,
                info.file_size,
                depth=depth,
                compressed_size=info.compress_size,
                max_expanded_bytes=max_expanded_bytes,
            ):
                return
            if not info.is_dir() and Path(info.filename).name.lower() in RISKY_CONFIG_NAMES:
                if info.file_size > MAX_CONFIG_BYTES:
                    result["complete"] = False
                    _append_unique(result, "limit_reasons", "model_config_size_limit")
                else:
                    try:
                        _record_risky_config(result, name, archive.read(info))
                    except Exception as exc:
                        result["complete"] = False
                        _append_unique(result, "errors", {"path": name, "error": f"{type(exc).__name__}: {exc}"}, limit=100)
            if info.is_dir() or not info.filename.lower().endswith(NESTED_NAMES):
                continue
            if depth >= MAX_ARCHIVE_DEPTH or info.file_size > MAX_NESTED_MEMBER_BYTES:
                result["complete"] = False
                _append_unique(result, "limit_reasons", "nested_archive_depth_or_size_limit")
                continue
            try:
                nested = archive.read(info)
                _inspect_bytes(
                    nested,
                    result,
                    prefix=name,
                    depth=depth + 1,
                    max_expanded_bytes=max_expanded_bytes,
                )
            except Exception as exc:
                result["complete"] = False
                _append_unique(result, "errors", {"path": name, "error": f"{type(exc).__name__}: {exc}"}, limit=100)


def _inspect_tar(
    handle: Any,
    result: dict[str, Any],
    *,
    prefix: str,
    depth: int,
    max_expanded_bytes: int,
) -> None:
    with tarfile.open(fileobj=handle if hasattr(handle, "read") else None, name=None if hasattr(handle, "read") else str(handle), mode="r:*") as archive:
        for member in archive:
            name = f"{prefix}!/{member.name}" if prefix else member.name
            if not _record_member(
                result,
                name,
                member.size,
                depth=depth,
                link=member.issym() or member.islnk(),
                device=member.isdev() or member.isfifo(),
                max_expanded_bytes=max_expanded_bytes,
            ):
                return
            if member.isfile() and Path(member.name).name.lower() in RISKY_CONFIG_NAMES:
                if member.size > MAX_CONFIG_BYTES:
                    result["complete"] = False
                    _append_unique(result, "limit_reasons", "model_config_size_limit")
                else:
                    config_handle = archive.extractfile(member)
                    if config_handle is None:
                        result["complete"] = False
                        _append_unique(result, "errors", {"path": name, "error": "model_config_unreadable"}, limit=100)
                    else:
                        _record_risky_config(result, name, config_handle.read(MAX_CONFIG_BYTES + 1))
            if not member.isfile() or not member.name.lower().endswith(NESTED_NAMES):
                continue
            if depth >= MAX_ARCHIVE_DEPTH or member.size > MAX_NESTED_MEMBER_BYTES:
                result["complete"] = False
                _append_unique(result, "limit_reasons", "nested_archive_depth_or_size_limit")
                continue
            nested_handle = archive.extractfile(member)
            if nested_handle is None:
                continue
            try:
                _inspect_bytes(
                    nested_handle.read(MAX_NESTED_MEMBER_BYTES + 1),
                    result,
                    prefix=name,
                    depth=depth + 1,
                    max_expanded_bytes=max_expanded_bytes,
                )
            except Exception as exc:
                result["complete"] = False
                _append_unique(result, "errors", {"path": name, "error": f"{type(exc).__name__}: {exc}"}, limit=100)


def _inspect_bytes(
    data: bytes,
    result: dict[str, Any],
    *,
    prefix: str,
    depth: int,
    max_expanded_bytes: int,
) -> None:
    stream = io.BytesIO(data)
    if zipfile.is_zipfile(stream):
        result["is_archive"] = True
        _inspect_zip(
            stream,
            result,
            prefix=prefix,
            depth=depth,
            max_expanded_bytes=max_expanded_bytes,
        )
        return
    stream.seek(0)
    try:
        result["is_archive"] = True
        _inspect_tar(
            stream,
            result,
            prefix=prefix,
            depth=depth,
            max_expanded_bytes=max_expanded_bytes,
        )
    except (tarfile.TarError, OSError):
        # The nested member had an archive-like name but is not a supported
        # tar stream. Keep it inventoried and let the parent remain complete.
        return


def inspect_archive(
    path: str | Path,
    *,
    max_expanded_bytes: int = MAX_EXPANDED_BYTES,
) -> dict[str, Any]:
    result = _new_result()
    source = Path(path)
    try:
        if zipfile.is_zipfile(source):
            result.update({"is_archive": True, "is_zip": True, "format": "zip"})
            _inspect_zip(
                source,
                result,
                prefix="",
                depth=0,
                max_expanded_bytes=max_expanded_bytes,
            )
        elif tarfile.is_tarfile(source):
            result.update({"is_archive": True, "is_tar": True, "format": "tar"})
            _inspect_tar(
                source,
                result,
                prefix="",
                depth=0,
                max_expanded_bytes=max_expanded_bytes,
            )
    except Exception as exc:
        result["complete"] = False
        result["errors"].append({"path": source.name, "error": f"{type(exc).__name__}: {exc}"})
    result["unsafe"] = any(
        result[key]
        for key in (
            "pickle_entries",
            "executable_entries",
            "path_traversal_entries",
            "archive_link_entries",
            "archive_device_entries",
            "zip_bomb_entries",
            "risky_config_entries",
        )
    ) or not result["complete"]
    return result

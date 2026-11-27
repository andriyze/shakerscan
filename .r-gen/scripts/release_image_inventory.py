#!/usr/bin/env python3
"""Validated canonical inventory of ShakerScan release images."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "install" / "release-images.json"


class ReleaseImageInventoryError(ValueError):
    pass


def load_release_images(path: Path = INVENTORY_PATH) -> tuple[dict[str, Any], ...]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != "shakerscan-release-images/v1":
        raise ReleaseImageInventoryError("unsupported release image inventory")
    images = value.get("images")
    if not isinstance(images, list) or not images:
        raise ReleaseImageInventoryError("release image inventory is empty")
    required = {"key", "lock_key", "repository", "role", "dockerfile", "compose_services"}
    normalized: list[dict[str, Any]] = []
    for index, image in enumerate(images):
        if not isinstance(image, dict) or set(image) != required:
            raise ReleaseImageInventoryError(f"release image {index} has unsupported fields")
        if not all(str(image[field]).strip() for field in required - {"compose_services"}):
            raise ReleaseImageInventoryError(f"release image {index} has an empty identity field")
        services = image["compose_services"]
        if not isinstance(services, list) or not services or not all(str(item).strip() for item in services):
            raise ReleaseImageInventoryError(f"release image {index} has invalid compose services")
        normalized.append({**image, "compose_services": list(services)})
    for field in ("key", "lock_key", "repository"):
        values = [str(image[field]) for image in normalized]
        if len(values) != len(set(values)):
            raise ReleaseImageInventoryError(f"duplicate release image {field}")
    return tuple(normalized)


RELEASE_IMAGES = load_release_images()
IMAGE_KEYS = tuple(str(image["key"]) for image in RELEASE_IMAGES)
LOCK_KEYS = {str(image["key"]): str(image["lock_key"]) for image in RELEASE_IMAGES}
REPOSITORIES = {str(image["key"]): str(image["repository"]) for image in RELEASE_IMAGES}

"""Deterministic private-input authority for canonical parallel Scan children."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from types import MappingProxyType
from typing import Mapping, Sequence

from .work_manifests import (
    ScanWorkManifest,
    ScanWorkManifestError,
    ScanWorkManifestKind,
    build_request_manifest,
)


_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


class ParallelScanInputError(ValueError):
    """Parallel child input authority is incomplete or ambiguous."""


@dataclass(frozen=True)
class ParallelRequestInputPartition:
    """Request manifests owned by one immutable child Scan."""

    child_scan_id: str
    shard_index: int
    manifests_by_selection: Mapping[str, ScanWorkManifest]

    def __post_init__(self) -> None:
        manifests = dict(self.manifests_by_selection)
        if any(
            not _HEX_64_RE.fullmatch(str(selection_digest))
            or manifest.kind is not ScanWorkManifestKind.REQUEST
            or manifest.scan_id != self.child_scan_id
            for selection_digest, manifest in manifests.items()
        ):
            raise ParallelScanInputError(
                "parallel request partition contains invalid child authority"
            )
        object.__setattr__(
            self,
            "manifests_by_selection",
            MappingProxyType(dict(sorted(manifests.items()))),
        )

    @property
    def request_count(self) -> int:
        return sum(
            len(manifest.entries)
            for manifest in self.manifests_by_selection.values()
        )


def _owner_slot(
    selection_digest: str,
    request_ref_id: str,
    eligible_slots: Sequence[int],
) -> int:
    material = f"{selection_digest}:{request_ref_id}".encode("utf-8")
    offset = int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
    return int(eligible_slots[offset % len(eligible_slots)])


def partition_request_manifests(
    manifests_by_selection: Mapping[str, ScanWorkManifest],
    *,
    children: Sequence[tuple[str, int]],
    eligible_shards_by_lane: Mapping[str, Sequence[int]] | None = None,
) -> tuple[ParallelRequestInputPartition, ...]:
    """Bind every admitted exact request to exactly one parallel child.

    The assignment uses only immutable public identity.  It is stable across
    process restarts and independent of child UUID generation or input order.
    Child manifests are newly content-addressed under the child Scan UUID and
    expose no URL values, headers, bodies, environments, or credentials.
    """
    normalized_children = tuple(
        sorted(
            ((str(scan_id), int(shard_index)) for scan_id, shard_index in children),
            key=lambda item: item[1],
        )
    )
    if len(normalized_children) < 2:
        raise ParallelScanInputError(
            "parallel request partition requires at least two children"
        )
    shard_indexes = tuple(item[1] for item in normalized_children)
    if len(set(shard_indexes)) != len(shard_indexes):
        raise ParallelScanInputError("parallel child shard indexes must be unique")
    child_ids = tuple(item[0] for item in normalized_children)
    if len(set(child_ids)) != len(child_ids):
        raise ParallelScanInputError("parallel child Scan IDs must be unique")

    lanes: dict[str, tuple[int, ...]] = {}
    for raw_lane, raw_indexes in dict(eligible_shards_by_lane or {}).items():
        lane = str(raw_lane or "anonymous").strip().lower()
        indexes = tuple(sorted({int(item) for item in raw_indexes}))
        if not indexes or any(item not in shard_indexes for item in indexes):
            raise ParallelScanInputError(
                f"parallel request lane {lane} has invalid child ownership"
            )
        lanes[lane] = indexes

    normalized_manifests: dict[str, ScanWorkManifest] = {}
    target_binding_digest: str | None = None
    request_owners: dict[str, tuple[str, int]] = {}
    assigned: dict[int, dict[str, list[dict[str, object]]]] = {
        shard_index: {} for shard_index in shard_indexes
    }
    for raw_selection_digest, manifest in sorted(
        manifests_by_selection.items(), key=lambda item: str(item[0]),
    ):
        selection_digest = str(raw_selection_digest or "").strip().lower()
        if not _HEX_64_RE.fullmatch(selection_digest):
            raise ParallelScanInputError(
                "parallel request selection digest is invalid"
            )
        if manifest.kind is not ScanWorkManifestKind.REQUEST:
            raise ParallelScanInputError(
                "parallel request input must use request manifests"
            )
        if target_binding_digest is None:
            target_binding_digest = manifest.target_binding_digest
        elif manifest.target_binding_digest != target_binding_digest:
            raise ParallelScanInputError(
                "parallel request manifests do not share target authority"
            )
        normalized_manifests[selection_digest] = manifest
        for raw_entry in manifest.entries:
            entry = dict(raw_entry)
            request_ref_id = str(entry["request_ref_id"])
            if request_ref_id in request_owners:
                previous_selection, _previous_shard = request_owners[request_ref_id]
                raise ParallelScanInputError(
                    "parallel request reference is ambiguous across selections: "
                    f"{request_ref_id} ({previous_selection}, {selection_digest})"
                )
            lane = str(entry.get("auth_lane") or "anonymous").lower()
            eligible = lanes.get(lane) or lanes.get("default") or shard_indexes
            owner = _owner_slot(selection_digest, request_ref_id, eligible)
            request_owners[request_ref_id] = (selection_digest, owner)
            entry["selected_shard"] = owner
            assigned[owner].setdefault(selection_digest, []).append(entry)

    partitions: list[ParallelRequestInputPartition] = []
    for child_scan_id, shard_index in normalized_children:
        manifests: dict[str, ScanWorkManifest] = {}
        child_selections = assigned[shard_index]
        for local_index, selection_digest in enumerate(sorted(child_selections)):
            entries = child_selections[selection_digest]
            try:
                manifests[selection_digest] = build_request_manifest(
                    scan_id=child_scan_id,
                    target_binding_digest=str(target_binding_digest),
                    source_action_ids=(f"inputs.collection_{local_index:02d}",),
                    requests=entries,
                    maximum=len(entries),
                )
            except ScanWorkManifestError as exc:
                raise ParallelScanInputError(str(exc)) from exc
        partitions.append(ParallelRequestInputPartition(
            child_scan_id=child_scan_id,
            shard_index=shard_index,
            manifests_by_selection=manifests,
        ))

    expected = {
        request_ref
        for manifest in normalized_manifests.values()
        for request_ref in (str(entry["request_ref_id"]) for entry in manifest.entries)
    }
    actual = {
        str(entry["request_ref_id"])
        for partition in partitions
        for manifest in partition.manifests_by_selection.values()
        for entry in manifest.entries
    }
    if actual != expected or sum(item.request_count for item in partitions) != len(expected):
        raise ParallelScanInputError(
            "parallel request partition is incomplete or duplicated"
        )
    return tuple(partitions)


__all__ = [
    "ParallelRequestInputPartition",
    "ParallelScanInputError",
    "partition_request_manifests",
]

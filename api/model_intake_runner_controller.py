"""Fail-closed Firecracker runner contract and readiness probe.

The API may inspect readiness, but only a dedicated Linux/KVM runner host may
launch this configuration. No fallback executes model code in the API/worker.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import shutil
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def firecracker_readiness(environment: dict[str, str] | None = None) -> dict[str, Any]:
    env = environment or os.environ
    signer_backend = env.get("MODEL_INTAKE_RUNNER_SIGNER_BACKEND", "").lower()
    signer_ready = bool(
        signer_backend == "aws-kms" and env.get("MODEL_INTAKE_RUNNER_SIGNER_KEY_ID")
        or signer_backend == "local-pem"
        and env.get("MODEL_INTAKE_RUNNER_ALLOW_LOCAL_PEM") == "true"
        and env.get("MODEL_INTAKE_RUNNER_SIGNING_KEY_PEM")
    )
    checks: dict[str, Any] = {
        "linux": platform.system() == "Linux",
        "kvm": Path("/dev/kvm").exists(),
        "firecracker": False,
        "jailer": False,
        "kernel": False,
        "rootfs": False,
        "signer": signer_ready,
        "builder_identity": bool(env.get("MODEL_INTAKE_RUNNER_BUILDER_ID")),
        "egress_policy": env.get("MODEL_INTAKE_RUNNER_EGRESS_POLICY") == "deny-all",
        "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "cgroup_parent": Path("/sys/fs/cgroup/shakerscan-model-intake/cgroup.subtree_control").is_file(),
        "network_namespace_tool": shutil.which("ip") is not None,
        "firewall_tool": shutil.which("nft") is not None,
        "filesystem_tool": shutil.which("mkfs.ext4") is not None and shutil.which("debugfs") is not None,
    }
    identities: dict[str, str] = {}
    for name, variable, digest_variable in (
        ("firecracker", "MODEL_INTAKE_FIRECRACKER_BIN", "MODEL_INTAKE_FIRECRACKER_SHA256"),
        ("jailer", "MODEL_INTAKE_JAILER_BIN", "MODEL_INTAKE_JAILER_SHA256"),
        ("kernel", "MODEL_INTAKE_KERNEL_IMAGE", "MODEL_INTAKE_KERNEL_SHA256"),
        ("rootfs", "MODEL_INTAKE_ROOTFS_IMAGE", "MODEL_INTAKE_ROOTFS_SHA256"),
    ):
        path = Path(env.get(variable, ""))
        expected = env.get(digest_variable, "").lower()
        if path.is_file() and len(expected) == 64:
            observed = _sha256(path)
            identities[name] = observed
            checks[name] = observed == expected
    ready = all(checks.values())
    return {
        "status": "READY" if ready else "NOT_READY",
        "ready": ready,
        "executor": "firecracker-jailer",
        "checks": checks,
        "verified_component_sha256": identities,
        "fallback_execution": False,
    }


def build_firecracker_config(request: dict[str, Any]) -> dict[str, Any]:
    required = (
        "vm_id", "kernel_image", "rootfs_image", "input_drive", "output_drive",
        "vcpu_count", "memory_mib", "timeout_seconds",
    )
    missing = [item for item in required if not request.get(item)]
    if missing:
        raise ValueError(f"missing runner fields: {','.join(missing)}")
    if int(request["vcpu_count"]) not in range(1, 33) or int(request["memory_mib"]) not in range(256, 262145):
        raise ValueError("runner CPU or memory limit is invalid")
    return {
        "boot-source": {
            "kernel_image_path": request["kernel_image"],
            "boot_args": "console=ttyS0 root=/dev/vda ro rootfstype=ext4 reboot=k panic=1 pci=off random.trust_cpu=on module.sig_enforce=1",
        },
        "drives": [
            {"drive_id": "rootfs", "path_on_host": request["rootfs_image"], "is_root_device": True, "is_read_only": True},
            {"drive_id": "input", "path_on_host": request["input_drive"], "is_root_device": False, "is_read_only": True},
            {"drive_id": "output", "path_on_host": request["output_drive"], "is_root_device": False, "is_read_only": False},
        ],
        "machine-config": {"vcpu_count": int(request["vcpu_count"]), "mem_size_mib": int(request["memory_mib"]), "smt": False},
        "network-interfaces": [],
        "metadata": {
            "vm_id": request["vm_id"],
            "timeout_seconds": min(int(request["timeout_seconds"]), 3600),
            "seccomp_level": 2,
            "no_network_device": True,
            "cgroup_limits_required": True,
            "receipt_required": True,
        },
    }


__all__ = ["build_firecracker_config", "firecracker_readiness"]

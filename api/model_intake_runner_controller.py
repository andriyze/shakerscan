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


def host_platform(environment: dict[str, str] | None = None) -> str:
    """Normalize the platform of the machine hosting the deployment.

    The API runs inside a Linux container even on Docker Desktop, so
    ``platform.system()`` here says nothing about whether the host can run a
    microVM. ``scanner.sh`` records the real host, matching how the optional
    fleet feature gates itself.
    """
    env = os.environ if environment is None else environment
    raw = env.get("SHAKERSCAN_HOST_PLATFORM", "").strip().lower()
    if raw in {"darwin", "mac", "macos", "osx"}:
        return "macos"
    if raw.startswith("linux"):
        return "linux"
    if raw in {"windows", "win32", "wsl"}:
        return raw
    return "unknown"


def host_supports_firecracker(environment: dict[str, str] | None = None) -> bool:
    """A microVM tier needs a Linux/KVM host; unknown stays eligible."""
    return host_platform(environment) in {"linux", "unknown"}


_VIRTUALIZATION_CPU_FLAGS = ("vmx", "svm")


def cpu_exposes_virtualization(cpuinfo_path: Path | None = None) -> bool | None:
    """Whether this CPU offers the hardware extension KVM is built on.

    Returns ``None`` when the answer cannot be established, so an unreadable or
    unfamiliar ``/proc/cpuinfo`` leaves the host eligible rather than declaring
    it hopeless. ``/proc/cpuinfo`` is not namespaced, so reading it from inside
    the API container still reports the real host CPU.
    """
    path = cpuinfo_path or Path("/proc/cpuinfo")
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    saw_flags = False
    for line in text.splitlines():
        label, separator, values = line.partition(":")
        if not separator or label.strip().lower() not in {"flags", "features"}:
            continue
        saw_flags = True
        if any(flag in values.split() for flag in _VIRTUALIZATION_CPU_FLAGS):
            return True
    return False if saw_flags else None


def firecracker_readiness(
    environment: dict[str, str] | None = None,
    *,
    cpuinfo_path: Path | None = None,
) -> dict[str, Any]:
    env = os.environ if environment is None else environment
    signer_backend = env.get("MODEL_INTAKE_RUNNER_SIGNER_BACKEND", "").lower()
    # A PEM in the environment is readable through /proc/PID/environ by anything
    # sharing the namespace, and systemd EnvironmentFile cannot hold a multi-line
    # value anyway, so a key file is both safer and the only workable shape.
    local_pem_material = bool(
        env.get("MODEL_INTAKE_RUNNER_SIGNING_KEY_PEM")
        or env.get("MODEL_INTAKE_RUNNER_SIGNING_KEY_PEM_FILE")
    )
    signer_ready = bool(
        signer_backend == "aws-kms" and env.get("MODEL_INTAKE_RUNNER_SIGNER_KEY_ID")
        or signer_backend == "local-pem"
        and env.get("MODEL_INTAKE_RUNNER_ALLOW_LOCAL_PEM") == "true"
        and local_pem_material
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
    platform_name = host_platform(env)
    supported_host = host_supports_firecracker(env)
    # A macOS or Windows host cannot ever satisfy these checks, so reporting
    # NOT_READY there reads as a broken deployment the operator should go fix.
    # It is an unavailable tier, not a misconfiguration. Fail-closed behavior is
    # unchanged either way: ready stays false and no job can be queued.
    reason = (
        "The Firecracker microVM tier requires a Linux host with KVM. "
        f"This deployment is hosted on {platform_name}, so exact-subject "
        "runtime execution is unavailable here. Every other Model Intake "
        "check is unaffected."
    )
    reason_code = "host_platform"
    # A Linux host is only usable as a microVM tier if the CPU actually offers
    # the extension. Without it there is nothing on the host to provision, so
    # this belongs with macOS rather than with a half-provisioned runner host.
    # The remedy is real but lives outside the host: most clouds now expose
    # nested virtualization as a per-instance setting, so the reason must not
    # tell the operator the machine is hopeless.
    if supported_host and not checks["kvm"] and cpu_exposes_virtualization(cpuinfo_path) is False:
        supported_host = False
        reason_code = "no_hardware_virtualization"
        reason = (
            "The Firecracker microVM tier requires /dev/kvm. This host exposes no "
            "hardware virtualization extension (no vmx or svm CPU flag), so KVM "
            "cannot start here. On a virtualized cloud instance that is usually a "
            "per-instance setting rather than a hard limit: AWS exposes it as the "
            "nested-virtualization CPU option on a stopped instance, and other "
            "providers have an equivalent. Enable it and restart the host, use a "
            "bare-metal host, or point MODEL_INTAKE_RUNNER_URL at a Linux/KVM "
            "host. Every other Model Intake check is unaffected."
        )
    if not supported_host:
        return {
            "status": "UNSUPPORTED_HOST",
            "ready": False,
            "supported_host": False,
            "host_platform": platform_name,
            "executor": "firecracker-jailer",
            "reason": reason,
            "unsupported_reason": reason_code,
            "checks": checks,
            "verified_component_sha256": identities,
            "fallback_execution": False,
        }
    return {
        "status": "READY" if ready else "NOT_READY",
        "ready": ready,
        "supported_host": True,
        "host_platform": platform_name,
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

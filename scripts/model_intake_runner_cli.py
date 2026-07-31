#!/usr/bin/env python3
"""Opt-in installer for the Model Intake Firecracker microVM tier.

The microVM tier is deliberately not installed by `scanner.sh start`. It needs
root, it mutates the host (systemd unit, cgroup parent, /srv/jailer, nftables),
and it costs a multi-gigabyte guest image that most hosts cannot even use --
macOS and Windows control planes, and any cloud instance without nested
virtualization. Paying that on every install for a tier the majority cannot run
is how an installer earns distrust.

What was missing was not the decision to opt in, it was that opting in meant
reading three shell scripts, sourcing a Firecracker-compatible kernel yourself,
and hand-wiring four environment variables. This turns that into one command
with a pinned kernel and an explicit confirmation.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

# Pinned Firecracker CI guest kernel. Verified against the published artifact:
# a bare URL with no digest would defeat the point of a measured runner.
DEFAULT_KERNEL_URL = (
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64/vmlinux-6.1.128"
)
DEFAULT_KERNEL_SHA256 = "27a8310b9a727517e9eb02044524b6ceb77de5728e3491b6974d5c846227ecc8"

RUNNER_ENV_FILE = Path("/etc/shakerscan/model-intake-runner.env")
SIGNING_KEY_FILE = Path("/etc/shakerscan/model-intake-runner-signing-key.pem")
DEFAULT_SIGNER = "local-pem"
INSTALL_ROOT = Path("/opt/shakerscan/model-intake-runner")
SERVICE = "shakerscan-model-intake-runner"
DEFAULT_BIND_PORT = 8092

HOST_MUTATIONS = [
    f"install firecracker + jailer, a pinned guest kernel, and the guest rootfs into {INSTALL_ROOT}",
    "create /srv/jailer and /var/lib/shakerscan/model-intake-runner",
    "create the cgroup-v2 parent /sys/fs/cgroup/shakerscan-model-intake and enable +cpu +memory +pids",
    f"write {RUNNER_ENV_FILE} (mode 0600) with the runner's internal token and component digests",
    f"generate {SIGNING_KEY_FILE} (mode 0600) when signing receipts with a local key",
    f"install and enable the systemd unit {SERVICE}.service",
    "record MODEL_INTAKE_RUNNER_* wiring in the ShakerScan .env and restart the api container",
]


def _run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, treating an absent binary as a failed run.

    `status` has to answer on any control plane, including a macOS host with no
    systemctl and no docker. Reporting "this host cannot run the tier" is the
    correct answer there, so a missing binary must not raise.
    """
    try:
        return subprocess.run(argv, text=True, **kwargs)
    except (FileNotFoundError, PermissionError) as exc:
        return subprocess.CompletedProcess(argv, 127, stdout="", stderr=str(exc))


def cpu_virtualization() -> bool | None:
    """None when undecidable, matching the readiness probe's fail-eligible rule."""
    try:
        text = Path("/proc/cpuinfo").read_text(errors="replace")
    except OSError:
        return None
    saw = False
    for line in text.splitlines():
        label, sep, values = line.partition(":")
        if not sep or label.strip().lower() not in {"flags", "features"}:
            continue
        saw = True
        if any(flag in values.split() for flag in ("vmx", "svm")):
            return True
    return False if saw else None


def docker_bridge_address() -> str | None:
    """Address the API container can use to reach a host service.

    The runner binds a real interface rather than loopback precisely so the
    containerized API can reach it; the deny-all egress policy and the internal
    bearer token are the controls, not the bind address.
    """
    result = _run(
        ["docker", "network", "inspect", "bridge", "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"],
        capture_output=True,
    )
    gateway = (result.stdout or "").strip()
    return gateway if result.returncode == 0 and gateway else None


# A clean Ubuntu image ships iproute2 and e2fsprogs but not nftables, and the
# provisioner hard-fails without nft. Name the package rather than the binary so
# the fix is one apt-get away instead of a puzzle.
HOST_TOOL_PACKAGES = {
    "nft": "nftables",
    "mkfs.ext4": "e2fsprogs",
    "debugfs": "e2fsprogs",
    "ip": "iproute2",
    "curl": "curl",
    "tar": "tar",
    "sha256sum": "coreutils",
}


def python_venv_package() -> str | None:
    """The python3-venv package name when venv creation would fail, else None.

    Debian and Ubuntu ship python3 without ensurepip, so `python3 -m venv` fails
    on a clean image even though python3 itself is present. A binary-presence
    check cannot see that, and the provisioner needs a working venv.
    """
    probe = _run(
        [sys.executable or "python3", "-c", "import ensurepip, venv"], capture_output=True
    )
    if probe.returncode == 0:
        return None
    version = _run(
        [sys.executable or "python3", "-c",
         "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
        capture_output=True,
    )
    suffix = (version.stdout or "").strip()
    return f"python{suffix}-venv" if suffix else "python3-venv"


def _safe_listdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except OSError:
        return []


def _sha256_path(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _staged_inputs(runtime: Path) -> dict:
    """What the UI's staging step already produced, if anything.

    Staging is unprivileged and slow; the install is privileged and fast. Being
    able to see the staged inputs is what keeps those two apart.
    """
    stage_dir = runtime / "results/model-intake-runner"
    kernel = stage_dir / "vmlinux"
    rootfs = stage_dir / "rootfs.ext4"
    result: dict = {"dir": str(stage_dir), "kernel": None, "rootfs": None}
    if kernel.is_file():
        result["kernel"] = {"path": str(kernel), "sha256": _sha256_path(kernel)}
    if rootfs.is_file():
        result["rootfs"] = {"path": str(rootfs), "bytes": rootfs.stat().st_size}
    return result


def host_facts(runtime: Path) -> dict:
    kvm = Path("/dev/kvm").exists()
    virt = cpu_virtualization()
    installed = {
        "firecracker": (INSTALL_ROOT / "bin/firecracker").is_file(),
        "jailer": (INSTALL_ROOT / "bin/jailer").is_file(),
        "kernel": (INSTALL_ROOT / "kernel/vmlinux").is_file(),
        "rootfs": (INSTALL_ROOT / "rootfs/rootfs.ext4").is_file(),
        # Root-owned and 0600, so a non-root status run must ask the parent
        # directory rather than stat the file and report a false negative.
        "runner_env": RUNNER_ENV_FILE.is_file() or _run(
            ["test", "-f", str(RUNNER_ENV_FILE)], capture_output=True
        ).returncode == 0 or RUNNER_ENV_FILE.parent.is_dir() and any(
            entry.name == RUNNER_ENV_FILE.name
            for entry in _safe_listdir(RUNNER_ENV_FILE.parent)
        ),
    }
    unit = _run(["systemctl", "is-active", SERVICE], capture_output=True)
    tools = {name: shutil.which(name) is not None for name in
             ("docker", "ip", "nft", "mkfs.ext4", "debugfs", "curl", "tar", "sha256sum")}
    return {
        "staged": _staged_inputs(runtime),
        "platform": platform.system().lower(),
        "arch": platform.machine(),
        "kvm": kvm,
        "cpu_virtualization": virt,
        "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "installed": installed,
        "service_state": (unit.stdout or "unknown").strip(),
        "host_tools": tools,
        "missing_host_tools": sorted(name for name, present in tools.items() if not present),
        "missing_python_venv_package": python_venv_package(),
    }


def installability(facts: dict) -> tuple[bool, str]:
    if facts["platform"] != "linux":
        return False, f"The microVM tier requires a Linux host; this is {facts['platform']}."
    if facts["arch"] != "x86_64":
        return False, f"The pinned guest runtime is x86_64 only; this host is {facts['arch']}."
    if not facts["kvm"]:
        if facts["cpu_virtualization"] is False:
            return False, (
                "/dev/kvm is absent and this CPU exposes no virtualization extension. "
                "On a cloud instance that is usually a per-instance setting: AWS exposes it "
                "as the nested-virtualization CPU option on a stopped instance."
            )
        return False, "/dev/kvm is absent. Load KVM or enable virtualization on this host."
    if not facts["cgroup_v2"]:
        return False, "cgroup v2 is required and /sys/fs/cgroup/cgroup.controllers is absent."
    packages = sorted({HOST_TOOL_PACKAGES.get(name, name) for name in facts["missing_host_tools"]})
    if facts.get("missing_python_venv_package"):
        packages.append(facts["missing_python_venv_package"])
    if packages:
        missing = list(facts["missing_host_tools"])
        if facts.get("missing_python_venv_package"):
            missing.append("python3 -m venv")
        return False, (
            "Missing host prerequisites: " + ", ".join(missing)
            + ". Install them with: sudo apt-get install -y " + " ".join(sorted(set(packages)))
        )
    return True, "This host can run the Model Intake microVM tier."


def cmd_status(args, runtime: Path) -> int:
    facts = host_facts(runtime)
    ok, reason = installability(facts)
    complete = all(facts["installed"].values())
    facts["can_install"] = ok
    facts["reason"] = reason
    facts["installed_complete"] = complete
    if args.json:
        print(json.dumps(facts, indent=2, sort_keys=True))
        return 0

    print("Model Intake microVM runner")
    print(f"  host            : {facts['platform']}/{facts['arch']}")
    print(f"  /dev/kvm        : {'present' if facts['kvm'] else 'absent'}")
    print(f"  cpu virt ext    : {facts['cpu_virtualization']}")
    print(f"  components      : " + ", ".join(
        f"{name}={'yes' if present else 'no'}" for name, present in facts["installed"].items()))
    print(f"  systemd service : {facts['service_state']}")
    print()
    if complete and facts["service_state"] == "active":
        print("Installed and running.")
        return 0
    print(reason)
    if ok:
        print()
        print("Not installed. To install it (this mutates the host, and asks before doing so):")
        print("  sudo ./scanner.sh model-intake-runner install --confirm")
    return 0


def _write_dotenv(env_path: Path, values: dict[str, str]) -> None:
    """Upsert keys in the runtime .env without disturbing anything else."""
    lines = env_path.read_text().splitlines() if env_path.is_file() else []
    for key, value in values.items():
        pattern = re.compile(rf"^{re.escape(key)}=")
        replacement = f"{key}={value}"
        for index, line in enumerate(lines):
            if pattern.match(line):
                lines[index] = replacement
                break
        else:
            lines.append(replacement)
    env_path.write_text("\n".join(lines) + "\n")


def _read_runner_env(key: str) -> str | None:
    if not RUNNER_ENV_FILE.is_file():
        return None
    for line in RUNNER_ENV_FILE.read_text().splitlines():
        name, sep, value = line.partition("=")
        if sep and name.strip() == key:
            return value.strip()
    return None


def cmd_install(args, runtime: Path) -> int:
    facts = host_facts(runtime)
    ok, reason = installability(facts)
    if not ok:
        print(f"Cannot install here: {reason}", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("The microVM tier installs host binaries and a systemd unit, so this needs root:",
              file=sys.stderr)
        print(f"  sudo ./scanner.sh model-intake-runner install --signer {args.signer or DEFAULT_SIGNER} --confirm",
              file=sys.stderr)
        return 2

    signer_env: dict[str, str] = {}
    signer = args.signer or DEFAULT_SIGNER
    if signer == "local-pem":
        # Proves the receipt path end to end, but the receipts it signs are not
        # backed by a production trust anchor. Say so every time rather than
        # letting the default quietly decide the trust story.
        print("NOTE: signing runner receipts with a locally generated key.")
        print("      This is not a production trust anchor. Use --signer kms:<key-id> for that.\n")
        if not SIGNING_KEY_FILE.is_file():
            SIGNING_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
            generated = _run(
                ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(SIGNING_KEY_FILE)],
                capture_output=True,
            )
            if generated.returncode != 0:
                print(f"Could not generate a signing key: {generated.stderr}", file=sys.stderr)
                return 2
        # The key never enters the environment, where /proc/PID/environ would
        # expose it; the runner reads the file instead.
        SIGNING_KEY_FILE.chmod(0o600)
        signer_env["MODEL_INTAKE_RUNNER_SIGNER_BACKEND"] = "local-pem"
        signer_env["MODEL_INTAKE_RUNNER_ALLOW_LOCAL_PEM"] = "true"
        signer_env["MODEL_INTAKE_RUNNER_SIGNING_KEY_PEM_FILE"] = str(SIGNING_KEY_FILE)
    elif signer.startswith("kms:"):
        key_id = signer.split(":", 1)[1].strip()
        if not key_id:
            print("--signer kms:<key-id> requires a key id", file=sys.stderr)
            return 2
        signer_env["MODEL_INTAKE_RUNNER_SIGNER_BACKEND"] = "aws-kms"
        signer_env["MODEL_INTAKE_RUNNER_SIGNER_KEY_ID"] = key_id
    else:
        print(f"Unknown signer {signer!r}. Use kms:<key-id> or local-pem.", file=sys.stderr)
        return 2

    print("This will change the host:")
    for item in HOST_MUTATIONS:
        print(f"  - {item}")
    print(f"\nGuest kernel pin:\n  {DEFAULT_KERNEL_URL}\n  sha256:{DEFAULT_KERNEL_SHA256}")
    print(f"\nThe guest rootfs build pulls CPU PyTorch and transformers; expect a"
          f" multi-gigabyte image and several minutes.\n")
    if not args.confirm:
        print("Re-run with --confirm to proceed.", file=sys.stderr)
        return 3

    rootfs = Path(args.rootfs) if args.rootfs else runtime / "results/model-intake-runner/rootfs.ext4"
    if not rootfs.is_file():
        print(f"==> building guest rootfs -> {rootfs}")
        built = _run([str(runtime / "scripts/build-model-intake-guest-rootfs.sh"), str(rootfs)])
        if built.returncode != 0:
            print("Guest rootfs build failed.", file=sys.stderr)
            return built.returncode
    else:
        print(f"==> reusing existing guest rootfs {rootfs}")

    bind_host = args.bind_host or docker_bridge_address()
    if not bind_host:
        print("Could not determine the Docker bridge gateway; pass --bind-host explicitly.",
              file=sys.stderr)
        return 2

    # A staged kernel is only reused when it still matches the pinned digest;
    # a stale or tampered file falls back to a fresh verified download.
    kernel_url = args.kernel_url
    staged_kernel = facts["staged"].get("kernel")
    if staged_kernel and staged_kernel["sha256"] == args.kernel_sha256:
        kernel_url = f"file://{staged_kernel['path']}"
        print(f"==> reusing staged kernel {staged_kernel['path']}")

    print(f"==> provisioning Firecracker (bind {bind_host}:{args.bind_port})")
    provision_env = {
        **os.environ,
        "MODEL_INTAKE_KERNEL_URL": kernel_url,
        "MODEL_INTAKE_KERNEL_SHA256": args.kernel_sha256,
        "MODEL_INTAKE_ROOTFS_SOURCE": str(rootfs),
        "MODEL_INTAKE_RUNNER_BIND_HOST": bind_host,
        "MODEL_INTAKE_RUNNER_BIND_PORT": str(args.bind_port),
    }
    provisioned = _run(
        [str(runtime / "scripts/provision-model-intake-firecracker.sh")], env=provision_env
    )
    if provisioned.returncode != 0:
        print("Provisioning failed.", file=sys.stderr)
        return provisioned.returncode

    builder_id = args.builder_id or f"shakerscan-runner-{platform.node()}"
    with RUNNER_ENV_FILE.open("a") as handle:
        for key, value in {**signer_env, "MODEL_INTAKE_RUNNER_BUILDER_ID": builder_id}.items():
            handle.write(f"{key}={value}\n")

    token = _read_runner_env("MODEL_INTAKE_RUNNER_INTERNAL_TOKEN")
    if not token:
        print(f"No internal token found in {RUNNER_ENV_FILE}.", file=sys.stderr)
        return 2

    print(f"==> enabling {SERVICE}")
    enabled = _run(["systemctl", "enable", "--now", SERVICE])
    if enabled.returncode != 0:
        print(f"Could not enable {SERVICE}; check journalctl -u {SERVICE}.", file=sys.stderr)
        return enabled.returncode

    print("==> wiring the API to the runner")
    _write_dotenv(runtime / ".env", {
        "MODEL_INTAKE_RUNNER_URL": f"http://{bind_host}:{args.bind_port}",
        "MODEL_INTAKE_RUNNER_INTERNAL_TOKEN": token,
        "MODEL_INTAKE_RUNNER_HOST_RESULTS_ROOT": "/var/lib/shakerscan/model-intake-results",
    })
    # `docker compose restart` reuses the existing container and never re-reads
    # .env, so the API would keep an empty MODEL_INTAKE_RUNNER_URL and go on
    # answering readiness from its own container instead of the runner.
    recreated = _run(["docker", "compose", "up", "-d", "api"], cwd=str(runtime))
    if recreated.returncode != 0:
        print("Could not recreate the api container; run 'docker compose up -d api' by hand.",
              file=sys.stderr)

    print("\nInstalled. Verify with:")
    print("  ./scanner.sh model-intake-runner status")
    print("  curl -s localhost:8080/model-intake/runners/readiness")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanner.sh model-intake-runner")
    parser.add_argument("--runtime", default=".", help="ShakerScan runtime directory")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="Report host capability and install state")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    install = sub.add_parser("install", help="Install the microVM tier on this host")
    install.add_argument("--confirm", action="store_true", help="Apply the host changes")
    install.add_argument(
        "--signer",
        default=DEFAULT_SIGNER,
        help=f"kms:<key-id> for a production trust anchor, or local-pem (default: {DEFAULT_SIGNER})",
    )
    install.add_argument("--builder-id", help="Recorded in signed runner receipts")
    install.add_argument("--rootfs", help="Reuse a prebuilt guest rootfs.ext4")
    install.add_argument("--bind-host", help="Address the API container reaches the runner on")
    install.add_argument("--bind-port", type=int, default=DEFAULT_BIND_PORT)
    install.add_argument("--kernel-url", default=DEFAULT_KERNEL_URL)
    install.add_argument("--kernel-sha256", default=DEFAULT_KERNEL_SHA256)
    install.set_defaults(func=cmd_install)

    args = parser.parse_args(argv)
    return args.func(args, Path(args.runtime).resolve())


if __name__ == "__main__":
    sys.exit(main())

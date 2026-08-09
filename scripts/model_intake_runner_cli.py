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
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

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
    "openssl": "openssl",
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


def host_packages(runtime: Path, facts: dict) -> list[str]:
    """Return the release-owned OS package set plus any version-specific venv fix."""
    manifest = runtime / "runner/host/system-requirements.ubuntu.txt"
    packages: list[str] = []
    try:
        for line in manifest.read_text().splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", value):
                    raise ValueError(f"invalid package name in {manifest}: {value!r}")
                packages.append(value)
    except OSError as exc:
        raise ValueError(f"runner system requirements are missing: {manifest}") from exc
    if facts.get("missing_python_venv_package"):
        packages.append(str(facts["missing_python_venv_package"]))
    return sorted(set(packages))


def install_host_packages(runtime: Path, facts: dict) -> bool:
    if not Path("/etc/debian_version").is_file() or shutil.which("apt-get") is None:
        return False
    try:
        packages = host_packages(runtime, facts)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return False
    print("==> installing release-owned Firecracker host prerequisites")
    refreshed = _run(["apt-get", "update"])
    if refreshed.returncode != 0:
        return False
    installed = _run(["apt-get", "install", "-y", "--no-install-recommends", *packages])
    return installed.returncode == 0


def _path_exists(path: Path) -> bool | None:
    """Existence without asserting readability. None means "cannot tell".

    The runner env file is root-owned inside a root-only directory, so stat()
    raises PermissionError for the ordinary user `status` exists to serve.
    `sudo -n` answers only for an operator with passwordless sudo, which most
    do not have — and reporting that unreadable file as absent made a complete
    install look like no install at all, telling the operator to run it again.
    Unknown is its own answer; callers corroborate it with a readable signal.
    """
    try:
        return path.is_file()
    except OSError:
        probe = _run(["sudo", "-n", "test", "-f", str(path)], capture_output=True)
        if probe.returncode == 0:
            return True
        # Distinguish "sudo says no such file" from "sudo would not run at all".
        return False if probe.returncode == 1 and not (probe.stderr or "").strip() else None


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


GUEST_ROOTFS_INPUTS = (
    "runner/guest/Dockerfile",
    "runner/guest/requirements.lock",
    "runner/guest/guest-init",
    "runner/guest/guest_worker.py",
)


def _guest_rootfs_inputs_sha256(runtime: Path) -> str:
    digest = hashlib.sha256()
    for relative in GUEST_ROOTFS_INPUTS:
        path = runtime / relative
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _staged_inputs(runtime: Path) -> dict:
    """What the UI's staging step already produced, if anything.

    Staging is unprivileged and slow; the install is privileged and fast. Being
    able to see the staged inputs is what keeps those two apart.
    """
    stage_dir = runtime / ".shakerscan-model-intake-runner-stage"
    kernel = stage_dir / "vmlinux"
    rootfs = stage_dir / "rootfs.ext4"
    manifest_path = stage_dir / "stage-manifest.json"
    result: dict = {
        "dir": str(stage_dir), "kernel": None, "rootfs": None,
        "integrity_verified": False,
    }
    try:
        if any(path.is_symlink() for path in (stage_dir, manifest_path, kernel, rootfs)):
            result["error"] = "symlink_rejected"
            return result
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != "model-intake-runner-stage/v1":
            result["error"] = "invalid_manifest_schema"
            return result
        artifacts = manifest.get("artifacts", {})
        for name, path in (("kernel", kernel), ("rootfs", rootfs)):
            expected = artifacts.get(name, {})
            observed = {"path": str(path), "bytes": path.stat().st_size,
                        "sha256": _sha256_path(path)}
            result[name] = observed
            if (observed["bytes"] != int(expected.get("bytes", -1))
                    or observed["sha256"] != expected.get("sha256")):
                result["error"] = f"{name}_digest_mismatch"
                return result
        if result["kernel"]["sha256"] != DEFAULT_KERNEL_SHA256:
            result["error"] = "kernel_not_pinned"
            return result
        if manifest.get("rootfs_inputs_sha256") != _guest_rootfs_inputs_sha256(runtime):
            result["error"] = "rootfs_inputs_changed"
            return result
        result["integrity_verified"] = True
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        result["error"] = f"manifest_unavailable:{type(exc).__name__}"
    return result


def _runtime_runner_url(runtime: Path) -> bool:
    """Whether a completed install wired the API to the runner."""
    env_path = runtime / ".env"
    try:
        for line in env_path.read_text("utf-8", errors="replace").splitlines():
            if line.startswith("MODEL_INTAKE_RUNNER_URL="):
                return bool(line.split("=", 1)[1].strip())
    except OSError:
        return False
    return False


def _shared_results_root(runtime: Path) -> Path:
    """Return the exact host directory bind-mounted into containers as /results."""
    candidate = runtime / "results"
    if candidate.is_symlink():
        raise ValueError("the ShakerScan results directory must not be a symlink")
    if not candidate.is_dir():
        raise ValueError(
            "the ShakerScan results directory is missing; start ShakerScan before installing the runner"
        )
    return candidate.resolve(strict=True)


def install_is_complete(facts: dict) -> bool:
    """Installed unless a component is definitely missing.

    An unreadable component is not a missing one. Treating unknown as missing
    reported a working install as absent.
    """
    if any(present is False for present in facts["installed"].values()):
        return False
    if all(present is True for present in facts["installed"].values()):
        return True
    # Something is unreadable; accept it only when a readable signal agrees the
    # install completed.
    return facts["service_state"] == "active" or bool(facts.get("api_wired_to_runner"))


def _validated_text(value: str, label: str, *, max_length: int = 300) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_length or any(ord(char) < 32 for char in cleaned):
        raise ValueError(f"{label} contains an empty, oversized, or control-character value")
    return cleaned


def _upsert_env_file(path: Path, values: dict[str, str | None]) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing to replace symlinked environment file: {path}")
    existing_stat = path.stat() if path.exists() else None
    lines = path.read_text().splitlines() if path.is_file() else []
    for key, raw_value in values.items():
        pattern = re.compile(rf"^{re.escape(key)}=")
        if raw_value is None:
            lines = [line for line in lines if not pattern.match(line)]
            continue
        value = _validated_text(raw_value, key, max_length=2000)
        replacement = f"{key}={value}"
        for index, line in enumerate(lines):
            if pattern.match(line):
                lines[index] = replacement
                break
        else:
            lines.append(replacement)
    temporary = path.with_name(f".{path.name}.partial")
    temporary.write_text("\n".join(lines) + "\n")
    if existing_stat is None:
        temporary.chmod(0o600)
    else:
        # The installer runs as root, while the source checkout and its .env
        # normally belong to the invoking operator. Atomic replacement with a
        # root-created temporary file must not lock that operator out of the
        # runtime after a successful install. Root-only runner files retain
        # their existing root ownership and mode through the same path.
        os.chown(temporary, existing_stat.st_uid, existing_stat.st_gid)
        temporary.chmod(stat.S_IMODE(existing_stat.st_mode))
    temporary.replace(path)


def host_facts(runtime: Path) -> dict:
    kvm = Path("/dev/kvm").exists()
    virt = cpu_virtualization()
    installed = {
        "firecracker": (INSTALL_ROOT / "bin/firecracker").is_file(),
        "jailer": (INSTALL_ROOT / "bin/jailer").is_file(),
        "kernel": (INSTALL_ROOT / "kernel/vmlinux").is_file(),
        "rootfs": (INSTALL_ROOT / "rootfs/rootfs.ext4").is_file(),
        # Root-owned inside a root-only directory, so this may be None
        # (unreadable) rather than a definite yes or no.
        "runner_env": _path_exists(RUNNER_ENV_FILE),
    }
    unit = _run(["systemctl", "is-active", SERVICE], capture_output=True)
    tools = {name: shutil.which(name) is not None for name in
             ("docker", "ip", "nft", "mkfs.ext4", "debugfs", "curl", "tar", "sha256sum", "openssl")}
    return {
        "staged": _staged_inputs(runtime),
        "platform": platform.system().lower(),
        "arch": platform.machine(),
        "kvm": kvm,
        "cpu_virtualization": virt,
        "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "installed": installed,
        # Readable without root and written by a completed install, so it
        # corroborates an unreadable runner env file.
        "api_wired_to_runner": _runtime_runner_url(runtime),
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
    complete = install_is_complete(facts)
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
        f"{name}={'yes' if present is True else 'no' if present is False else 'unreadable'}"
        for name, present in facts["installed"].items()))
    print(f"  systemd service : {facts['service_state']}")
    print(f"  api wired       : {'yes' if facts['api_wired_to_runner'] else 'no'}")
    print()
    if complete and facts["service_state"] == "active":
        print("Installed and running.")
        return 0
    if complete:
        # Installed but not running is a service fault, not a missing install.
        print(f"Installed, but {SERVICE} is {facts['service_state']}.")
        print(f"  sudo systemctl status {SERVICE}")
        print(f"  sudo journalctl -u {SERVICE} -n 50")
        return 0
    if any(present is None for present in facts["installed"].values()):
        print("Some components are root-only and could not be read as this user.")
        print("  sudo ./scanner.sh model-intake-runner status")
        print()
    print(reason)
    if ok:
        print()
        print("Not installed. To install it (this mutates the host, and asks before doing so):")
        print("  sudo ./scanner.sh model-intake-runner install --confirm")
    return 0


def _write_dotenv(env_path: Path, values: dict[str, str]) -> None:
    """Upsert keys in the runtime .env without disturbing anything else."""
    _upsert_env_file(env_path, values)


def _read_runner_env(key: str) -> str | None:
    if not RUNNER_ENV_FILE.is_file():
        return None
    for line in RUNNER_ENV_FILE.read_text().splitlines():
        name, sep, value = line.partition("=")
        if sep and name.strip() == key:
            return value.strip()
    return None


def _read_dotenv_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() and not key.lstrip().startswith("#"):
            values[key.strip()] = value.strip()
    return values


def _runner_public_key_pem(signer: str) -> str:
    if signer == "local-pem":
        exported = _run(
            ["openssl", "pkey", "-in", str(SIGNING_KEY_FILE), "-pubout"],
            capture_output=True,
        )
    else:
        key_id = signer.split(":", 1)[1]
        script = (
            "import boto3,sys;"
            "from cryptography.hazmat.primitives.serialization import "
            "load_der_public_key,Encoding,PublicFormat;"
            "der=boto3.client('kms').get_public_key(KeyId=sys.argv[1])['PublicKey'];"
            "sys.stdout.buffer.write(load_der_public_key(der).public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))"
        )
        exported = _run(
            [str(INSTALL_ROOT / "venv/bin/python"), "-c", script, key_id],
            capture_output=True,
        )
    if exported.returncode != 0 or "BEGIN PUBLIC KEY" not in (exported.stdout or ""):
        raise RuntimeError("could not export the runner signing public key")
    return exported.stdout.strip() + "\n"


def _api_request(url: str, token: str, method: str = "GET",
                 payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        decoded = json.loads(response.read().decode("utf-8"))
    if not isinstance(decoded, dict):
        raise RuntimeError("ShakerScan API returned a non-object response")
    return decoded


def _register_runner_trust_anchors(runtime: Path, signer: str, builder_id: str) -> None:
    dotenv = _read_dotenv_values(runtime / ".env")
    token = dotenv.get("MODEL_INTAKE_OPERATOR_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError("MODEL_INTAKE_OPERATOR_TOKEN is unavailable in the runtime .env")
    public_api = dotenv.get("SHAKERSCAN_PUBLIC_API_URL", "").rstrip("/")
    if public_api.startswith("https://"):
        base = public_api
    else:
        bind_host = dotenv.get("SHAKERSCAN_BIND_HOST", "127.0.0.1")
        if bind_host in {"0.0.0.0", "::", ""}:
            bind_host = "127.0.0.1"
        if ":" in bind_host and not bind_host.startswith("["):
            bind_host = f"[{bind_host}]"
        api_port = dotenv.get("SHAKERSCAN_API_PORT", "8080")
        base = f"http://{bind_host}:{api_port}"
    last_error: Exception | None = None
    for _ in range(30):
        try:
            _api_request(f"{base}/health", token)
            break
        except Exception as exc:  # API recreation is briefly unavailable.
            last_error = exc
            time.sleep(1)
    else:
        raise RuntimeError(f"ShakerScan API did not become ready: {type(last_error).__name__}")

    public_key_pem = _runner_public_key_pem(signer)
    fingerprint = hashlib.sha256(public_key_pem.encode()).hexdigest()
    existing = _api_request(f"{base}/model-intake/trust-anchors?active_only=true", token)
    anchors = existing.get("trust_anchors") if isinstance(existing.get("trust_anchors"), list) else []
    environments = ["production"] if signer.startswith("kms:") else [
        "development", "test", "staging", "production"
    ]
    for environment in environments:
        if any(
            item.get("purpose") == "runtime_runner"
            and item.get("environment") == environment
            and item.get("builder_id_constraint") == builder_id
            and (item.get("public_key_sha256") == fingerprint
                 or item.get("public_key_pem") == public_key_pem)
            for item in anchors if isinstance(item, dict)
        ):
            continue
        name = f"microvm-{builder_id}-{environment}-{fingerprint[:12]}"
        _api_request(
            f"{base}/model-intake/trust-anchors",
            token,
            "POST",
            {
                "name": name[:240],
                "description": (
                    "Installed Model Intake microVM production receipt signer"
                    if signer.startswith("kms:")
                    else "Installed Model Intake microVM local evidence signer; not valid for production admission"
                ),
                "public_key_pem": public_key_pem,
                "public_key_sha256": fingerprint,
                "policy_profile": (
                    "production"
                    if signer.startswith("kms:")
                    else "local-pem-evidence"
                ),
                "purpose": "runtime_runner",
                "environment": environment,
                "builder_id_constraint": builder_id,
                "source": "model-intake-runner-installer",
                "owner": "ShakerScan operator",
                "is_active": True,
            },
        )
    readiness = _api_request(f"{base}/model-intake/runners/readiness", token)
    if readiness.get("ready") is not True or readiness.get("status") != "READY":
        raise RuntimeError("runner service did not report READY after installation")


def cmd_install(args, runtime: Path) -> int:
    facts = host_facts(runtime)
    ok, reason = installability(facts)
    if os.geteuid() != 0:
        print("The microVM tier installs host binaries and a systemd unit, so this needs root:",
              file=sys.stderr)
        print(f"  sudo ./scanner.sh model-intake-runner install --signer {args.signer or DEFAULT_SIGNER} --confirm",
              file=sys.stderr)
        return 2
    if not ok:
        missing_packages = bool(
            facts.get("missing_host_tools") or facts.get("missing_python_venv_package")
        )
        structurally_supported = (
            facts.get("platform") == "linux"
            and facts.get("arch") == "x86_64"
            and facts.get("kvm") is True
            and facts.get("cgroup_v2") is True
        )
        if not (args.confirm and missing_packages and structurally_supported):
            print(f"Cannot install here: {reason}", file=sys.stderr)
            return 2
        if not install_host_packages(runtime, facts):
            print(
                "Could not install the host prerequisites automatically. "
                f"The exact missing-prerequisite report was: {reason}",
                file=sys.stderr,
            )
            return 2
        facts = host_facts(runtime)
        ok, reason = installability(facts)
        if not ok:
            print(f"Host prerequisites remain incomplete: {reason}", file=sys.stderr)
            return 2

    signer_env: dict[str, str | None] = {}
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
        signer_env["MODEL_INTAKE_RUNNER_SIGNER_KEY_ID"] = None
    elif signer.startswith("kms:"):
        try:
            key_id = _validated_text(signer.split(":", 1)[1], "KMS key id")
        except ValueError:
            print("--signer kms:<key-id> requires a key id", file=sys.stderr)
            return 2
        signer_env["MODEL_INTAKE_RUNNER_SIGNER_BACKEND"] = "aws-kms"
        signer_env["MODEL_INTAKE_RUNNER_SIGNER_KEY_ID"] = key_id
        signer_env["MODEL_INTAKE_RUNNER_ALLOW_LOCAL_PEM"] = "false"
        signer_env["MODEL_INTAKE_RUNNER_SIGNING_KEY_PEM_FILE"] = None
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
    if not re.fullmatch(r"[0-9a-f]{64}", args.kernel_sha256):
        print("--kernel-sha256 must be a lowercase SHA-256 digest.", file=sys.stderr)
        return 2

    staged = facts["staged"]
    if args.rootfs:
        rootfs = Path(args.rootfs).resolve()
        if not args.rootfs_sha256:
            print("--rootfs requires --rootfs-sha256 so custom images are integrity-bound.", file=sys.stderr)
            return 2
        rootfs_sha256 = args.rootfs_sha256.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", rootfs_sha256):
            print("--rootfs-sha256 must be a lowercase SHA-256 digest.", file=sys.stderr)
            return 2
        if not rootfs.is_file() or rootfs.is_symlink() or _sha256_path(rootfs) != rootfs_sha256:
            print("Custom rootfs is missing, symlinked, or does not match --rootfs-sha256.", file=sys.stderr)
            return 2
    elif staged.get("integrity_verified"):
        rootfs = Path(staged["rootfs"]["path"])
        rootfs_sha256 = staged["rootfs"]["sha256"]
        print(f"==> reusing integrity-verified staged rootfs {rootfs}")
    else:
        rootfs = runtime / ".shakerscan-model-intake-runner-stage/rootfs.ext4"
        print(f"==> building guest rootfs -> {rootfs}")
        built = _run([str(runtime / "scripts/build-model-intake-guest-rootfs.sh"), str(rootfs)])
        if built.returncode != 0:
            print("Guest rootfs build failed.", file=sys.stderr)
            return built.returncode
        rootfs_sha256 = _sha256_path(rootfs)

    bind_host = args.bind_host or docker_bridge_address()
    if not bind_host:
        print("Could not determine the Docker bridge gateway; pass --bind-host explicitly.",
              file=sys.stderr)
        return 2
    try:
        ipaddress.ip_address(bind_host)
    except ValueError:
        print("--bind-host must be a literal IPv4 or IPv6 address.", file=sys.stderr)
        return 2
    if not 1 <= args.bind_port <= 65535:
        print("--bind-port must be between 1 and 65535.", file=sys.stderr)
        return 2
    try:
        shared_results_root = _shared_results_root(runtime)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    # A staged kernel is only reused when it still matches the pinned digest;
    # a stale or tampered file falls back to a fresh verified download.
    kernel_url = args.kernel_url
    staged_kernel = staged.get("kernel") if staged.get("integrity_verified") else None
    if staged_kernel and staged_kernel["sha256"] == args.kernel_sha256:
        kernel_url = f"file://{staged_kernel['path']}"
        print(f"==> reusing staged kernel {staged_kernel['path']}")

    print(f"==> provisioning Firecracker (bind {bind_host}:{args.bind_port})")
    provision_env = {
        **os.environ,
        "MODEL_INTAKE_KERNEL_URL": kernel_url,
        "MODEL_INTAKE_KERNEL_SHA256": args.kernel_sha256,
        "MODEL_INTAKE_ROOTFS_SOURCE": str(rootfs),
        "MODEL_INTAKE_ROOTFS_SHA256": rootfs_sha256,
        "MODEL_INTAKE_ROOTFS_INPUTS_SHA256": _guest_rootfs_inputs_sha256(runtime),
        "MODEL_INTAKE_RUNNER_BIND_HOST": bind_host,
        "MODEL_INTAKE_RUNNER_BIND_PORT": str(args.bind_port),
        # Compose bind-mounts <runtime>/results at /results. Firecracker runs
        # on the host, so both sides must name that same physical directory.
        "MODEL_INTAKE_RUNNER_SHARED_RESULTS_ROOT": str(shared_results_root),
    }
    provisioned = _run(
        [str(runtime / "scripts/provision-model-intake-firecracker.sh")], env=provision_env
    )
    if provisioned.returncode != 0:
        print("Provisioning failed.", file=sys.stderr)
        return provisioned.returncode

    try:
        builder_id = _validated_text(
            args.builder_id or f"shakerscan-runner-{platform.node()}", "builder id"
        )
        _upsert_env_file(
            RUNNER_ENV_FILE,
            {**signer_env, "MODEL_INTAKE_RUNNER_BUILDER_ID": builder_id},
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    token = _read_runner_env("MODEL_INTAKE_RUNNER_INTERNAL_TOKEN")
    if not token:
        print(f"No internal token found in {RUNNER_ENV_FILE}.", file=sys.stderr)
        return 2

    print(f"==> enabling {SERVICE}")
    enabled = _run(["systemctl", "enable", SERVICE])
    if enabled.returncode != 0:
        print(f"Could not enable {SERVICE}; check journalctl -u {SERVICE}.", file=sys.stderr)
        return enabled.returncode
    restarted = _run(["systemctl", "restart", SERVICE])
    if restarted.returncode != 0:
        print(f"Could not restart {SERVICE}; check journalctl -u {SERVICE}.", file=sys.stderr)
        return restarted.returncode

    print("==> wiring the API to the runner")
    _write_dotenv(runtime / ".env", {
        "MODEL_INTAKE_RUNNER_URL": f"http://{bind_host}:{args.bind_port}",
        "MODEL_INTAKE_RUNNER_INTERNAL_TOKEN": token,
        "MODEL_INTAKE_RUNNER_HOST_RESULTS_ROOT": str(shared_results_root),
    })
    # `docker compose restart` reuses the existing container and never re-reads
    # .env, so the API would keep an empty MODEL_INTAKE_RUNNER_URL and go on
    # answering readiness from its own container instead of the runner.
    recreated = _run(["docker", "compose", "up", "-d", "api"], cwd=str(runtime))
    if recreated.returncode != 0:
        print("Could not recreate the api container; run 'docker compose up -d api' by hand.",
              file=sys.stderr)
        return recreated.returncode

    print("==> registering the runner public key as a purpose-scoped trust anchor")
    try:
        _register_runner_trust_anchors(runtime, signer, builder_id)
    except (RuntimeError, OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"Trust-anchor registration failed: {exc}", file=sys.stderr)
        return 2

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
    install.add_argument("--rootfs-sha256", help="Required SHA-256 when --rootfs is supplied")
    install.add_argument("--bind-host", help="Address the API container reaches the runner on")
    install.add_argument("--bind-port", type=int, default=DEFAULT_BIND_PORT)
    install.add_argument("--kernel-url", default=DEFAULT_KERNEL_URL)
    install.add_argument("--kernel-sha256", default=DEFAULT_KERNEL_SHA256)
    install.set_defaults(func=cmd_install)

    args = parser.parse_args(argv)
    return args.func(args, Path(args.runtime).resolve())


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
set -euo pipefail

FIRECRACKER_VERSION="${FIRECRACKER_VERSION:-v1.16.1}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_ROOT="${MODEL_INTAKE_RUNNER_INSTALL_ROOT:-/opt/shakerscan/model-intake-runner}"
SHARED_RESULTS_ROOT="${MODEL_INTAKE_RUNNER_SHARED_RESULTS_ROOT:-/var/lib/shakerscan/model-intake-results}"
KERNEL_URL="${MODEL_INTAKE_KERNEL_URL:-}"
KERNEL_SHA256="${MODEL_INTAKE_KERNEL_SHA256:-}"
ROOTFS_SOURCE="${MODEL_INTAKE_ROOTFS_SOURCE:-}"
# The API reaches the runner over HTTP. It runs in a container, so a loopback
# bind is unreachable from it; the installer passes the Docker bridge address.
# The deny-all egress policy and the internal token are what keep that safe.
RUNNER_BIND_HOST="${MODEL_INTAKE_RUNNER_BIND_HOST:-127.0.0.1}"
RUNNER_BIND_PORT="${MODEL_INTAKE_RUNNER_BIND_PORT:-8092}"
TEMP_DIR="$(mktemp -d)"

cleanup() { rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root on the dedicated Linux/KVM runner host" >&2
    exit 1
fi
if [[ ! -e /dev/kvm ]]; then
    echo "/dev/kvm is unavailable; nested virtualization or a bare-metal KVM host is required" >&2
    exit 1
fi
if [[ -z "$KERNEL_URL" || ! "$KERNEL_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "MODEL_INTAKE_KERNEL_URL and its pinned MODEL_INTAKE_KERNEL_SHA256 are required" >&2
    exit 1
fi
if [[ -z "$ROOTFS_SOURCE" || ! -f "$ROOTFS_SOURCE" ]]; then
    echo "MODEL_INTAKE_ROOTFS_SOURCE must name a locally built guest rootfs" >&2
    exit 1
fi
if [[ "$SHARED_RESULTS_ROOT" != /* ]]; then
    echo "MODEL_INTAKE_RUNNER_SHARED_RESULTS_ROOT must be an absolute host path" >&2
    exit 1
fi
for command in curl debugfs docker ip mkfs.ext4 nft python3 sha256sum tar; do
    command -v "$command" >/dev/null || { echo "Required runner command is unavailable: $command" >&2; exit 1; }
done

arch="$(uname -m)"
case "$arch" in x86_64) ;; *) echo "The current hash-locked guest runtime supports x86_64 only: $arch" >&2; exit 1;; esac
archive="firecracker-${FIRECRACKER_VERSION}-${arch}.tgz"
release="https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}"
curl -fsSLo "$TEMP_DIR/$archive" "$release/$archive"
curl -fsSLo "$TEMP_DIR/$archive.sha256.txt" "$release/$archive.sha256.txt"
(cd "$TEMP_DIR" && sha256sum -c "$archive.sha256.txt")
tar -C "$TEMP_DIR" -xzf "$TEMP_DIR/$archive"

mkdir -p "$INSTALL_ROOT/bin" "$INSTALL_ROOT/kernel" "$INSTALL_ROOT/rootfs" "$INSTALL_ROOT/app" /srv/jailer
install -m 0755 "$(find "$TEMP_DIR/release-${FIRECRACKER_VERSION}-${arch}" -maxdepth 1 -type f -name 'firecracker-*' | head -1)" "$INSTALL_ROOT/bin/firecracker"
install -m 0755 "$(find "$TEMP_DIR/release-${FIRECRACKER_VERSION}-${arch}" -maxdepth 1 -type f -name 'jailer-*' | head -1)" "$INSTALL_ROOT/bin/jailer"
curl -fsSLo "$TEMP_DIR/vmlinux" "$KERNEL_URL"
echo "$KERNEL_SHA256  $TEMP_DIR/vmlinux" | sha256sum -c -
install -m 0644 "$TEMP_DIR/vmlinux" "$INSTALL_ROOT/kernel/vmlinux"
install -m 0644 "$ROOTFS_SOURCE" "$INSTALL_ROOT/rootfs/rootfs.ext4"
install -m 0644 \
    "$ROOT_DIR/api/model_intake_control_plane.py" \
    "$ROOT_DIR/api/model_intake_components.py" \
    "$ROOT_DIR/api/model_intake_loader_profiles.py" \
    "$ROOT_DIR/api/model_intake_runner_inputs.py" \
    "$ROOT_DIR/api/model_intake_runner_controller.py" \
    "$ROOT_DIR/api/model_intake_runner_receipts.py" \
    "$ROOT_DIR/api/model_intake_firecracker_runner.py" \
    "$ROOT_DIR/api/model_intake_runner_service.py" \
    "$INSTALL_ROOT/app/"
python3 -m venv "$INSTALL_ROOT/venv"
"$INSTALL_ROOT/venv/bin/pip" install --no-cache-dir --require-hashes -r "$ROOT_DIR/runner/host/requirements.lock"

mkdir -p /sys/fs/cgroup/shakerscan-model-intake
for controller in cpu memory pids; do
    grep -qw "$controller" /sys/fs/cgroup/cgroup.controllers || {
        echo "Required cgroup-v2 controller unavailable: $controller" >&2
        exit 1
    }
done
echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control || true
echo '+cpu +memory +pids' > /sys/fs/cgroup/shakerscan-model-intake/cgroup.subtree_control || true

install -d -m 0700 /etc/shakerscan
if [[ ! -f /etc/shakerscan/model-intake-runner.env ]]; then
    runner_token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
    cat > /etc/shakerscan/model-intake-runner.env <<EOF
MODEL_INTAKE_RUNNER_INTERNAL_TOKEN=$runner_token
MODEL_INTAKE_RUNNER_JOB_ROOT=/var/lib/shakerscan/model-intake-runner/jobs
MODEL_INTAKE_RUNNER_QUARANTINE_ROOT=$SHARED_RESULTS_ROOT
MODEL_INTAKE_RUNNER_WORK_ROOT=/var/lib/shakerscan/model-intake-runner/work
MODEL_INTAKE_RUNNER_CONVERSION_ROOT=$SHARED_RESULTS_ROOT/model-intake-conversions
MODEL_INTAKE_JAILER_ROOT=/srv/jailer
MODEL_INTAKE_FIRECRACKER_BIN=$INSTALL_ROOT/bin/firecracker
MODEL_INTAKE_FIRECRACKER_SHA256=$(sha256sum "$INSTALL_ROOT/bin/firecracker" | awk '{print $1}')
MODEL_INTAKE_JAILER_BIN=$INSTALL_ROOT/bin/jailer
MODEL_INTAKE_JAILER_SHA256=$(sha256sum "$INSTALL_ROOT/bin/jailer" | awk '{print $1}')
MODEL_INTAKE_KERNEL_IMAGE=$INSTALL_ROOT/kernel/vmlinux
MODEL_INTAKE_KERNEL_SHA256=$(sha256sum "$INSTALL_ROOT/kernel/vmlinux" | awk '{print $1}')
MODEL_INTAKE_ROOTFS_IMAGE=$INSTALL_ROOT/rootfs/rootfs.ext4
MODEL_INTAKE_ROOTFS_SHA256=$(sha256sum "$INSTALL_ROOT/rootfs/rootfs.ext4" | awk '{print $1}')
MODEL_INTAKE_RUNNER_EGRESS_POLICY=deny-all
EOF
    chmod 0600 /etc/shakerscan/model-intake-runner.env
fi
install -d -m 0700 \
    /var/lib/shakerscan/model-intake-runner/jobs \
    /var/lib/shakerscan/model-intake-runner/work \
    "$SHARED_RESULTS_ROOT/model-intake-conversions"
cat > /etc/systemd/system/shakerscan-model-intake-runner.service <<EOF
[Unit]
Description=ShakerScan physical Model Intake Firecracker runner
After=network.target
ConditionPathExists=/dev/kvm

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_ROOT/app
EnvironmentFile=/etc/shakerscan/model-intake-runner.env
ExecStart=$INSTALL_ROOT/venv/bin/uvicorn model_intake_runner_service:app --host $RUNNER_BIND_HOST --port $RUNNER_BIND_PORT --no-access-log
Restart=on-failure
RestartSec=3
UMask=0077
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=false
RestrictAddressFamilies=AF_UNIX AF_INET
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

cat <<EOF
MODEL_INTAKE_FIRECRACKER_BIN=$INSTALL_ROOT/bin/firecracker
MODEL_INTAKE_FIRECRACKER_SHA256=$(sha256sum "$INSTALL_ROOT/bin/firecracker" | awk '{print $1}')
MODEL_INTAKE_JAILER_BIN=$INSTALL_ROOT/bin/jailer
MODEL_INTAKE_JAILER_SHA256=$(sha256sum "$INSTALL_ROOT/bin/jailer" | awk '{print $1}')
MODEL_INTAKE_KERNEL_IMAGE=$INSTALL_ROOT/kernel/vmlinux
MODEL_INTAKE_KERNEL_SHA256=$(sha256sum "$INSTALL_ROOT/kernel/vmlinux" | awk '{print $1}')
MODEL_INTAKE_ROOTFS_IMAGE=$INSTALL_ROOT/rootfs/rootfs.ext4
MODEL_INTAKE_ROOTFS_SHA256=$(sha256sum "$INSTALL_ROOT/rootfs/rootfs.ext4" | awk '{print $1}')
MODEL_INTAKE_RUNNER_EGRESS_POLICY=deny-all
EOF

echo "Runner service installed but not enabled. Configure a production receipt signer and builder identity"
echo "in /etc/shakerscan/model-intake-runner.env, copy its internal token to the API secret store, then run:"
echo "  systemctl enable --now shakerscan-model-intake-runner"

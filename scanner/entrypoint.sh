#!/bin/bash
# Entrypoint script for ShakerScan
# Configure DNS resolution
configure_dns() {
echo "Configuring DNS resolvers..."
if [ "${SHK_DNS_OVERRIDE:-}" = "1" ]; then
# Skip if resolv.conf not writable
if [ ! -w /etc/resolv.conf ]; then
echo "Skipping resolv.conf override: /etc/resolv.conf not writable"
else
# Ensure Docker's internal DNS (127.0.0.11) is FIRST for container name resolution
# Then add external DNS as fallback for scanning external targets
# Don't touch options line - Docker's defaults work fine
if ! grep -q "^nameserver 127.0.0.11" /etc/resolv.conf; then
# Prepend Docker DNS as first resolver (avoid sed -i on bind-mounted resolv.conf)
tmp_resolv="$(mktemp)"
                {
echo "nameserver 127.0.0.11"
cat /etc/resolv.conf
                } > "$tmp_resolv"
if ! cat "$tmp_resolv" > /etc/resolv.conf; then
echo "Warning: unable to update /etc/resolv.conf"
fi
rm -f "$tmp_resolv"
fi
# Add external DNS as fallback (idempotent)
grep -q "^nameserver 1.1.1.1" /etc/resolv.conf || echo "nameserver 1.1.1.1" >> /etc/resolv.conf
grep -q "^nameserver 8.8.8.8" /etc/resolv.conf || echo "nameserver 8.8.8.8" >> /etc/resolv.conf
fi
else
echo "Skipping resolv.conf override (set SHK_DNS_OVERRIDE=1 to enable)"
fi
# Configure subfinder to use specific resolvers
mkdir -p /tmp/.config/subfinder
cat > /tmp/.config/subfinder/config.yaml <<EOF
resolvers:
  - 1.1.1.1
  - 8.8.8.8
  - 8.8.4.4
sources:
  - crtsh
  - hackertarget
  - anubis
  - urlscan
  - waybackarchive
exclude-sources:
  - securitytrails
  - passivetotal
  - censys
timeout: 30
rate-limit: 2
EOF
export DNSCACHE_DISABLE=1
export RES_OPTIONS="timeout:2 attempts:3 rotate"
}
# Configure DNS
configure_dns
# Set Playwright environment variables
export PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# Verify the image-layer identity before any development bind mounts are synced.
# Runtime environment variables may declare what a deployment expects, but they
# cannot rewrite the version/revision baked into the release manifest.
python3 /app/release_identity.py --verify

# Dev source consistency: when the host source trees are bind-mounted as
# DIRECTORIES (/app/_src/{scanner,api}), COPY their files over the baked /app
# copies so the running code uses the live host source. We COPY (not symlink)
# because Python resolves a symlinked entrypoint's path, putting sys.path[0] in the
# wrong tree (ModuleNotFoundError); real files at /app keep imports native for both
# worker.py and the scanner subprocess. Directory mounts avoid the macOS single-file
# bind-mount inode-pinning that served stale/truncated files (silent "no output,
# exit 0" scans). No-op in baked/prod mode (no _src). Edit + restart the container
# to pick up changes.
sync_dev_sources() {
    for d in /app/_src/scanner /app/_src/api; do
        [ -d "$d" ] || continue
        echo "[entrypoint] syncing live source from $d"
        cp -f "$d"/*.py /app/ 2>/dev/null || true
    done
    [ -d /app/_src/scanner/scanner_tools ] && cp -rf /app/_src/scanner/scanner_tools/. /app/scanner_tools/ 2>/dev/null || true
    [ -d /app/_src/scanner/wordlists ] && cp -rf /app/_src/scanner/wordlists/. /app/wordlists/ 2>/dev/null || true
    [ -d /app/_src/scanner/payloads ] && cp -rf /app/_src/scanner/payloads/. /app/payloads/ 2>/dev/null || true
    [ -d /app/_src/api/ai_gate ] && cp -rf /app/_src/api/ai_gate/. /app/ai_gate/ 2>/dev/null || true
    for package in capabilities hunt runtime scan; do
        [ -d "/app/_src/api/$package" ] || continue
        mkdir -p "/app/$package"
        cp -rf "/app/_src/api/$package/." "/app/$package/"
    done
}
sync_dev_sources

# Route every worker role through the V2 admission entrypoint. The wrapper keeps
# the existing queue/fleet/device plumbing and delegates non-DAST jobs unchanged.
if [ "${1:-}" = "python3" ] && [ "${2:-}" = "/app/worker.py" ] && [ -f /app/worker_v2.py ]; then
    shift 2
    set -- python3 /app/worker_v2.py "$@"
fi

# Route the API through the V2 Hunt-start contract while the compatibility
# application continues to own persistence, queues, fleet operations, and routes.
if [ "${1:-}" = "python3" ] && [ "${2:-}" = "/app/api.py" ] && [ -f /app/api_v2.py ]; then
    shift 2
    set -- python3 /app/api_v2.py "$@"
fi

# Execute command passed to container
exec "$@"

#!/bin/bash
# Entrypoint script for DAST Scanner
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
# Execute command passed to container
exec "$@"
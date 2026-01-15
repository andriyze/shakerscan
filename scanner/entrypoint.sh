#!/bin/bash
# Entrypoint script for DAST Scanner

# Configure DNS resolution
configure_dns() {
    echo "Configuring DNS resolvers..."

    # Preserve Docker's internal DNS (127.0.0.11) for container networking
    # This is CRITICAL for container-to-container name resolution (e.g., 'postgres', 'redis')
    if [ -w /etc/resolv.conf ]; then
        # Backup original
        cp /etc/resolv.conf /etc/resolv.conf.bak

        # IMPORTANT: Ensure Docker's internal DNS is FIRST (required for container name resolution)
        # On some EC2/Linux hosts, Docker's 127.0.0.11 may not be present or may be misconfigured
        if ! grep -q "nameserver 127.0.0.11" /etc/resolv.conf; then
            echo "Adding Docker internal DNS (127.0.0.11) as primary resolver..."
            # Prepend Docker's internal DNS so container names resolve first
            { echo "nameserver 127.0.0.11"; cat /etc/resolv.conf; } > /tmp/resolv.conf.new
            cat /tmp/resolv.conf.new > /etc/resolv.conf
            rm -f /tmp/resolv.conf.new
        fi

        # Add external DNS as fallback (for scanning external targets)
        grep -q "nameserver 1.1.1.1" /etc/resolv.conf || echo "nameserver 1.1.1.1" >> /etc/resolv.conf
        grep -q "nameserver 8.8.8.8" /etc/resolv.conf || echo "nameserver 8.8.8.8" >> /etc/resolv.conf

        # Add DNS options if not already present (avoid duplicates on container restart)
        grep -q "^options.*timeout" /etc/resolv.conf || echo "options timeout:2 attempts:3 rotate" >> /etc/resolv.conf
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

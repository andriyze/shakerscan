#!/bin/bash
# Entrypoint script for DAST Scanner

# Configure DNS resolution
configure_dns() {
    echo "Configuring DNS resolvers..."

    # Preserve Docker's internal DNS (127.0.0.11) for container networking
    # Only add external resolvers as fallback, don't overwrite
    if [ -w /etc/resolv.conf ]; then
        # Backup original and append external resolvers
        cp /etc/resolv.conf /etc/resolv.conf.bak
        # Add external DNS as additional nameservers (after Docker's internal DNS)
        grep -q "1.1.1.1" /etc/resolv.conf || echo "nameserver 1.1.1.1" >> /etc/resolv.conf
        grep -q "8.8.8.8" /etc/resolv.conf || echo "nameserver 8.8.8.8" >> /etc/resolv.conf
        echo "options timeout:2 attempts:3 rotate" >> /etc/resolv.conf
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

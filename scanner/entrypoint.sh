#!/bin/bash
# Entrypoint script for DAST Scanner

# Configure DNS resolution
configure_dns() {
    echo "Configuring DNS resolvers..."

    # Skip DNS configuration if resolv.conf is not writable
    if [ ! -w /etc/resolv.conf ]; then
        echo "resolv.conf not writable, skipping DNS configuration"
        return
    fi

    # Backup original
    cp /etc/resolv.conf /etc/resolv.conf.bak

    # Detect if we're in host network mode or have custom DNS (127.0.0.11 won't work)
    # Check if Docker's internal DNS is reachable before injecting
    local use_docker_dns=true
    if [ -n "$DOCKER_HOST_NETWORK" ] || [ -n "$CUSTOM_DNS" ]; then
        echo "Host network or custom DNS detected, skipping Docker DNS injection"
        use_docker_dns=false
    elif ! getent hosts localhost >/dev/null 2>&1; then
        # Basic sanity check - if we can't resolve localhost, DNS is broken
        echo "Warning: DNS resolution appears broken"
    fi

    # Build new resolv.conf with proper ordering:
    # 1. Docker internal DNS first (if applicable) - critical for container name resolution
    # 2. External DNS as fallback - needed for scanning external targets
    # 3. Preserve existing options, merge with our required options
    local tmp_resolv="/tmp/resolv.conf.$$"

    # Extract existing options line (if any) and other directives (search, domain, sortlist)
    local existing_options=""
    existing_options=$(grep "^options" /etc/resolv.conf | head -1 || true)
    grep -E "^(search|domain|sortlist)" /etc/resolv.conf > "$tmp_resolv" 2>/dev/null || true

    # Add nameservers in correct order (deduplicated)
    {
        # Docker internal DNS first (unless host network mode)
        if [ "$use_docker_dns" = true ]; then
            echo "nameserver 127.0.0.11"
        fi
        # External fallback DNS
        echo "nameserver 1.1.1.1"
        echo "nameserver 8.8.8.8"
        # Preserve any other nameservers from original (deduplicated)
        grep "^nameserver" /etc/resolv.conf | grep -v -E "127.0.0.11|1.1.1.1|8.8.8.8" || true
    } >> "$tmp_resolv"

    # Merge options: preserve existing options and add our required ones if missing
    local final_options="options"
    if [ -n "$existing_options" ]; then
        # Extract existing option values
        final_options="$existing_options"
    fi
    # Add our required options if not present
    echo "$final_options" | grep -q "timeout" || final_options="$final_options timeout:2"
    echo "$final_options" | grep -q "attempts" || final_options="$final_options attempts:3"
    echo "$final_options" | grep -q "rotate" || final_options="$final_options rotate"
    echo "$final_options" >> "$tmp_resolv"

    # Atomically replace resolv.conf
    cat "$tmp_resolv" > /etc/resolv.conf
    rm -f "$tmp_resolv"

    echo "DNS configured: $(grep -c '^nameserver' /etc/resolv.conf) nameservers"

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

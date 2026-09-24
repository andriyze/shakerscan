#!/bin/sh
# Build-only helper: refresh signed indexes after mirror rotation before retrying the
# same complete package set. Never use --fix-missing (which can omit dependencies).
set -eu

if [ "$#" -eq 0 ]; then
    echo 'apt_install.sh requires at least one package' >&2
    exit 2
fi

# The pinned Noble base uses plaintext official mirror URLs. A runner-side HTTP
# cache can return indexes whose package URLs are no longer retrievable over HTTP,
# even after an update. Use the same official repositories over verified HTTPS.
# Keep suites, components and Signed-By unchanged; do not change third-party or
# Debian sources, invent a mirror, pin a downgrade, or fall back to plaintext.
upgrade_ubuntu_sources() {
    for source in "$1/sources.list" "$1"/sources.list.d/*.list "$1"/sources.list.d/*.sources; do
        [ -f "$source" ] && [ ! -L "$source" ] || continue
        sed -i -E \
            -e 's@http://archive\.ubuntu\.com/ubuntu([/[:space:]]|$)@https://archive.ubuntu.com/ubuntu\1@g' \
            -e 's@http://security\.ubuntu\.com/ubuntu([/[:space:]]|$)@https://security.ubuntu.com/ubuntu\1@g' \
            -e 's@http://ports\.ubuntu\.com/ubuntu-ports([/[:space:]]|$)@https://ports.ubuntu.com/ubuntu-ports\1@g' \
            "$source"
    done
}
upgrade_ubuntu_sources /etc/apt

attempt=1
while :; do
    # A base image or a failed update can retain an obsolete Packages index. Do not
    # reuse it on a retry, and ask caching proxies to revalidate index responses.
    rm -rf /var/lib/apt/lists/*
    if apt-get -o APT::Update::Error-Mode=any \
        -o Acquire::Retries=2 -o Acquire::http::Timeout=30 \
        -o Acquire::https::Timeout=30 -o Acquire::http::No-Cache=true \
        -o Acquire::https::No-Cache=true update && \
       apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 \
        -o Acquire::https::Timeout=30 install -y --no-install-recommends "$@"; then
        rm -rf /var/lib/apt/lists/*
        exit 0
    else
        status=$?
    fi
    if [ "$attempt" -ge 3 ]; then
        echo "APT dependency installation failed after ${attempt} refreshed attempts" >&2
        exit "$status"
    fi
    echo "APT dependency installation failed; refreshing indexes before attempt $((attempt + 1))/3" >&2
    sleep "$((attempt * 5))"
    attempt=$((attempt + 1))
done

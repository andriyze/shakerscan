#!/bin/sh
# Build-only helper: refresh signed indexes after mirror rotation before retrying the
# same complete package set. Never use --fix-missing (which can omit dependencies).
set -eu

if [ "$#" -eq 0 ]; then
    echo 'apt_install.sh requires at least one package' >&2
    exit 2
fi

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

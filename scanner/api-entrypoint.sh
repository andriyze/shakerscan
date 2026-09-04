#!/bin/sh
set -eu
umask 0002

export PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
python3 /app/release_identity.py --verify
exec "$@"

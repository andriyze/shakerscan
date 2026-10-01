#!/usr/bin/env bash
set -euo pipefail
node --version
npm --prefix ui ci
npm --prefix ui test
(cd ui && npx tsc --noEmit)
npm --prefix ui run build
python3 scripts/check_module_size.py

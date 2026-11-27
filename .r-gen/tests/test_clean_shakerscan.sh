#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash -n scripts/clean-shakerscan.sh
python3 -m unittest discover -s tests -p test_clean_shakerscan.py -v

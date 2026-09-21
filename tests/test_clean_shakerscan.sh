#!/usr/bin/env bash
set -euo pipefail
script="scripts/clean-shakerscan.sh"
bash -n "$script"
out="$(bash "$script" --help)"
grep -q "macOS and Linux" <<<"$out"
grep -q -- "--keep-client" <<<"$out"
grep -q -- "--images" <<<"$out"
# Safety contract: never use host-wide Docker pruning.
! grep -Eq 'docker (system|volume|container|image) prune' "$script"
grep -q 'label=com.docker.compose.project=' "$script"
grep -q 'Type DELETE SHAKERSCAN' "$script"
echo "clean-shakerscan static tests passed"

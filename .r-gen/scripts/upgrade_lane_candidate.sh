#!/usr/bin/env bash
# The candidate a pull request's upgrade lane installs, and a source tree of the same release.
#
# A pull request has no candidate images of its own: its upgrade lanes (upgrade-path.yml,
# installed-upgrade.yml) install the newest candidate built on main (build-on-main.yml), whose
# images carry main's VERSION. A pull request that changes VERSION -- every release branch --
# would install its own runtime files with those images, and the upgraded stack refuses to start
# with "release identity mismatch". The lane then installs the candidate's own commit, keeping
# only the pull request's copies of the gate files the lane exists to test, so both halves of the
# upgrade are one release. The upgrade to the pull request's own version is proven by the release
# candidate, which calls these workflows with its exact commit and images; this script is never
# used there.
#
# Usage:
#   scripts/upgrade_lane_candidate.sh --out DIR [--run-id ID] [--record FILE] GATE_FILE...
#
# Downloads the candidate receipt of build-on-main run ID (default: the newest successful one)
# into DIR. When the receipt's version differs from this tree's VERSION, checks out the receipt's
# candidate commit and restores GATE_FILEs from the pull request. Fails unless the resulting tree
# has the candidate's version and runtime manifest. Writes run_id, candidate_version,
# candidate_sha and pinned to $GITHUB_OUTPUT, the decision to $GITHUB_STEP_SUMMARY, and a JSON
# record to FILE. Needs gh (GH_TOKEN, REPOSITORY), git, jq and sha256sum.
set -euo pipefail

main() {
    out=""
    run_id=""
    record=""
    gate_files=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --out) out="$2"; shift 2 ;;
            --run-id) run_id="$2"; shift 2 ;;
            --record) record="$2"; shift 2 ;;
            --) shift; gate_files+=("$@"); break ;;
            -*) echo "upgrade lane: unknown option $1" >&2; exit 2 ;;
            *) gate_files+=("$1"); shift ;;
        esac
    done
    fail() { echo "upgrade lane: $*" >&2; exit 1; }
    [ -n "$out" ] || { echo "upgrade lane: --out is required" >&2; exit 2; }
    [ "${#gate_files[@]}" -gt 0 ] || { echo "upgrade lane: name the gate files under test" >&2; exit 2; }
    : "${REPOSITORY:?REPOSITORY is required}"

    if [ -z "$run_id" ]; then
        run_id="$(gh run list -R "$REPOSITORY" --workflow build-on-main.yml --branch main \
            --status success --limit 1 --json databaseId --jq '.[0].databaseId')"
    fi
    [[ "$run_id" =~ ^[0-9]+$ ]] || fail "no successful build-on-main run"
    artifact="$(gh api "repos/$REPOSITORY/actions/runs/$run_id/artifacts" \
        --jq '[.artifacts[] | select(.name | startswith("release-candidate-uncertified-"))][0].name')"
    if [ -z "$artifact" ] || [ "$artifact" = "null" ]; then
        fail "build-on-main run $run_id kept no candidate receipt"
    fi
    mkdir -p "$out"
    gh run download "$run_id" -R "$REPOSITORY" -n "$artifact" -D "$out"
    receipt="$out/release-candidate-receipt.json"
    [ -f "$receipt" ] || fail "build-on-main run $run_id: $artifact holds no release-candidate-receipt.json"

    candidate_version="$(jq -r '.version // ""' "$receipt")"
    candidate_sha="$(jq -r '.candidate_sha // ""' "$receipt")"
    runtime_manifest="$(jq -r '.runtime_manifest_sha256 // ""' "$receipt")"
    [[ "$candidate_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "the candidate receipt names no version"
    [[ "$candidate_sha" =~ ^[0-9a-f]{40}$ ]] || fail "the candidate receipt names no commit"
    [[ "$runtime_manifest" =~ ^[0-9a-f]{64}$ ]] || fail "the candidate receipt names no runtime manifest"

    tree_version="$(tr -d '[:space:]' < VERSION)"
    pinned=false
    reason="the pull request carries the candidate's version $candidate_version; its tree is installed"
    if [ "$tree_version" != "$candidate_version" ]; then
        pinned=true
        reason="the pull request carries $tree_version and the newest candidate built on main is $candidate_version: the lane installs that candidate's commit $candidate_sha with the pull request's gate files; the upgrade to $tree_version is proven by its release candidate"
        keep="$(mktemp -d)"
        for file in "${gate_files[@]}"; do
            case "$file" in /*|*..*) fail "gate file $file is not a path inside the tree" ;; esac
            [ -f "$file" ] || fail "gate file $file is not in the pull request's tree"
            mkdir -p "$keep/$(dirname "$file")"
            cp -p "$file" "$keep/$file"
        done
        git fetch --no-tags --depth=1 origin "$candidate_sha"
        git -c advice.detachedHead=false checkout --force --detach "$candidate_sha"
        for file in "${gate_files[@]}"; do
            mkdir -p "$(dirname "$file")"
            cp -p "$keep/$file" "$file"
        done
        rm -rf "$keep"
        [ "$(tr -d '[:space:]' < VERSION)" = "$candidate_version" ] \
            || fail "commit $candidate_sha does not carry the candidate's version $candidate_version"
    fi
    if [ "$pinned" = true ]; then
        [ "$(sha256sum install/MANIFEST.sha256 | cut -d' ' -f1)" = "$runtime_manifest" ] \
            || fail "commit $candidate_sha does not carry the candidate's runtime manifest"
        # A gate file the installer ships would put the pull request's copy into the candidate's
        # runtime: refuse it by name, then check every runtime file against the manifest.
        for file in "${gate_files[@]}"; do
            if awk -v path="$file" '$2 == path { found = 1 } END { exit !found }' install/MANIFEST.sha256; then
                fail "gate file $file is a runtime file of the candidate (install/MANIFEST.sha256)"
            fi
        done
        sha256sum --check --quiet --status install/MANIFEST.sha256 \
            || fail "the pinned tree's runtime files differ from the candidate's manifest"
    fi

    echo "upgrade lane: $reason"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        printf '### Upgrade lane candidate\n\n%s.\n' "$reason" >> "$GITHUB_STEP_SUMMARY"
    fi
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        {
            echo "run_id=$run_id"
            echo "candidate_version=$candidate_version"
            echo "candidate_sha=$candidate_sha"
            echo "pinned=$pinned"
        } >> "$GITHUB_OUTPUT"
    fi
    if [ -n "$record" ]; then
        mkdir -p "$(dirname "$record")"
        jq -n --arg pr_version "$tree_version" --arg candidate_version "$candidate_version" \
            --arg candidate_sha "$candidate_sha" --arg run_id "$run_id" --arg reason "$reason" \
            --argjson pinned "$pinned" --args '{
              schema: "shakerscan.upgrade-lane-candidate/v1", pull_request_version: $pr_version,
              candidate: {version: $candidate_version, source_sha: $candidate_sha, build_on_main_run: $run_id},
              pinned_to_candidate_commit: $pinned, gate_files: $ARGS.positional, reason: $reason}' \
            "${gate_files[@]}" > "$record"
    fi
}

main "$@"

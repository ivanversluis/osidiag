#!/usr/bin/env bash
# Build a single-root Git snapshot from reviewed main. Does NOT change GitHub.
set -euo pipefail
if [[ $# -ne 1 ]]; then echo "Usage: $0 /absolute/path/to/new-empty-directory" >&2; exit 2; fi
for cmd in git gh tar; do command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 2; }; done
SOURCE="$(git rev-parse --show-toplevel)"
DEST="$1"
[[ "$DEST" = /* && ! -e "$DEST" ]] || { echo "Use an absolute, nonexistent destination" >&2; exit 2; }
[[ "$(git -C "$SOURCE" branch --show-current)" == main ]] || { echo "Use main after PR #19 is merged" >&2; exit 2; }
[[ -z "$(git -C "$SOURCE" status --porcelain)" ]] || { echo "Source working tree is dirty" >&2; exit 2; }
merged="$(gh pr view 19 -R ivanversluis/osidiag --json mergedAt --jq .mergedAt)"
[[ "$merged" != null && -n "$merged" ]] || { echo "PR #19 must be merged first" >&2; exit 2; }
git -C "$SOURCE" fetch --no-tags origin main
[[ "$(git -C "$SOURCE" rev-parse HEAD)" == "$(git -C "$SOURCE" rev-parse refs/remotes/origin/main)" ]] || { echo "Local main differs from origin/main" >&2; exit 2; }
SOURCE_TREE="$(git -C "$SOURCE" rev-parse HEAD^{tree})"
mkdir -p "$DEST"
git -C "$SOURCE" archive --format=tar HEAD | tar -xf - -C "$DEST"
git -C "$DEST" init -b main
git -C "$DEST" add -A
git -C "$DEST" commit -m "Initial public osidiag release (Apache-2.0)"
NEW_TREE="$(git -C "$DEST" rev-parse HEAD^{tree})"
[[ "$SOURCE_TREE" == "$NEW_TREE" ]] || { echo "STOP: tree differs from source" >&2; exit 1; }
[[ "$(git -C "$DEST" rev-list --count HEAD)" == 1 ]] || { echo "STOP: expected one commit" >&2; exit 1; }
[[ "$(git -C "$DEST" rev-list --parents -n1 HEAD | wc -w | tr -d ' ')" == 1 ]] || { echo "STOP: root commit has ancestors" >&2; exit 1; }
echo "Verified: one root commit with exact source tree $SOURCE_TREE"
echo "No GitHub repository modified; follow docs/PUBLIC_BASELINE.md for the cutover."

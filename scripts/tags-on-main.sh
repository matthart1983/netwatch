#!/usr/bin/env bash
# Fail unless every release tag is in HEAD's history.
#
#   scripts/tags-on-main.sh
#
# CI runs it on pushes to main and on pull requests into it. A hotfix released
# from a release/X.Y.Z branch has to be merged back: v0.35.3 was published
# from one and stayed off main for twelve days, and a release cut from main in
# that time would have dropped its FreeBSD fix. While a tag is missing, CI on
# main fails, so the release guard refuses the next tag cut from it.
#
# Needs the full history and the tags (actions/checkout with fetch-depth: 0).
set -euo pipefail

die() { echo "::error::$*"; exit 1; }

[ "$(git rev-parse --is-shallow-repository)" = false ] ||
    die "shallow clone: check out with fetch-depth: 0 so every tag's history is present"

tags=$(git tag --list 'v*')
# No tags at all means they were not fetched, not that none exist; passing
# then would make this a check that cannot fail.
[ -n "${tags}" ] || die "no v* tags in this clone; fetch them (fetch-depth: 0 does)"

missing=0
while read -r tag; do
    if ! git merge-base --is-ancestor "${tag}" HEAD; then
        echo "::error::${tag} is not on main. Merge the branch it was released from (git merge ${tag}) before releasing from main."
        missing=$((missing + 1))
    fi
done <<< "${tags}"
[ "${missing}" -eq 0 ] || exit 1
echo "all $(grep -c . <<< "${tags}") release tags are in HEAD's history"

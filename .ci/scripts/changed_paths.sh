#!/bin/sh
# Emit the list of files changed in this CI run to stdout, one per line.
#
# Diff range, in priority order:
#   1. $CI_COMMIT_BEFORE_SHA..HEAD   if BEFORE_SHA is set and non-zero
#                                    (webhook payload's body.before — the
#                                    only correct range for multi-commit
#                                    pushes; HEAD~1..HEAD would miss
#                                    earlier commits in the push)
#   2. HEAD~1..HEAD                  single-commit push fallback
#   3. git ls-files                  shallow clone with no parent
#                                    available — conservative full set
#
# The zero-SHA check matches GitLab's "first push to branch" payload,
# which sends body.before = 40 zeros.
#
# Designed to run in alpine/git (POSIX sh, no bashisms). Sourced or
# executed by .ci/scripts/changed-paths in each CI WorkflowTemplate's
# changed-paths-step inline args.

set -e

ZERO_SHA="0000000000000000000000000000000000000000"

if [ -n "$CI_COMMIT_BEFORE_SHA" ] && [ "$CI_COMMIT_BEFORE_SHA" != "$ZERO_SHA" ]; then
  # Best-effort fetch in case the depth-50 clone didn't include before_sha
  # (e.g. a long-lived branch suddenly merged after many main commits).
  git fetch --depth=1 origin "$CI_COMMIT_BEFORE_SHA" 2>/dev/null || true
  git diff --name-only "$CI_COMMIT_BEFORE_SHA"..HEAD
elif git rev-parse HEAD~1 >/dev/null 2>&1; then
  git diff --name-only HEAD~1..HEAD
else
  git ls-files
fi

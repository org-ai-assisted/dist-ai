#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Step-level canonical-repos gate. Emits `allowed=true|false`
## to $GITHUB_OUTPUT based on whether ${THIS_REPO} is in the
## comma-separated ${CANONICAL_REPOS} list.
##
## Expected env:
##   CANONICAL_REPOS - comma-separated 'owner/repo' list
##                     (typically from steps.cfg.outputs.canonical_repos)
##   THIS_REPO       - the current repository (github.repository)
##
## Strict by design: workflow_dispatch does NOT bypass. A fork-
## side manual dispatch would burn runner time for nothing (org
## secrets are not available to forks) and the canonical's
## quota is therefore never at risk from cross-fork manual
## triggers.
##
## Used by reusable-coverity.yml after the dm-consumer.yml
## load step. Subsequent expensive steps (cov-download / build /
## submit) gate on `steps.gate.outputs.allowed == 'true'`.

set -o errexit
set -o errtrace
set -o nounset
set -o pipefail
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## CANONICAL_REPOS is CSV that may carry whitespace after commas
## ("org/foo, org/bar"). The ',<repo>,' test is exact-match, so a stray space
## would make a genuine member miss and silently skip the gated Coverity steps.
## Repo names never contain whitespace -> strip it from both sides before
## matching (the log messages below keep the originals).
canonical_repos_compact="${CANONICAL_REPOS//[[:space:]]/}"
this_repo_compact="${THIS_REPO//[[:space:]]/}"

if grep --fixed-strings --quiet -- ",${this_repo_compact}," <<< ",${canonical_repos_compact},"; then
   printf '%s\n' \
      "gate: ${THIS_REPO} is canonical (in '${CANONICAL_REPOS}'); allowing" >&2
   printf '%s\n' 'allowed=true' >> "${GITHUB_OUTPUT}"
else
   printf '%s\n' \
      "gate: ${THIS_REPO} is not canonical (list: '${CANONICAL_REPOS}'); skipping expensive steps" >&2
   printf '%s\n' 'allowed=false' >> "${GITHUB_OUTPUT}"
fi

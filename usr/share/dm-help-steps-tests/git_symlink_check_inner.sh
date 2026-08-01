#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive the shipped 'check-git-symlinks' against the repo named by argv 1.
##
## The function body arrives on STDIN rather than in argv: it is read straight out
## of the shipped 1100_sanity-tests, so the test exercises the real text.
## 'error' comes from help-steps/pre in a real build and exits non-zero after
## printing; stub it the same way here.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

error() {
   printf '%s\n' "$*" >&2
   exit 1
}

source_code_folder_dist="$1"
# shellcheck disable=SC1091
source /dev/stdin
check-git-symlinks

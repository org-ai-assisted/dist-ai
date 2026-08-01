#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive the extracted 'check-required-tools' body (argv 1) with 'error' stubbed to
## report and exit non-zero, exactly as help-steps/pre's does.
##
## $GUARD_HAS is helper-scripts' has.sh from the SAME checkout: the function under
## test uses 'has' (R-090) rather than 'command -v', so the harness provides the
## real one -- stubbing it would test the stub's idea of "present", not the
## shipped one.
## $GUARD_PATH is the PATH the guard sees, which is what selects the branch.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

body="$1"

error() {
   printf '%s\n' "$*" >&2
   exit 1
}

# shellcheck disable=SC1090
source "${GUARD_HAS}"
PATH="${GUARD_PATH}"
eval "${body}"
check-required-tools

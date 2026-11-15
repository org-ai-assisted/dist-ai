#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Strict-mode child-process runner for ws_func_verify_local_repo_installed, invoked by
## battery_check_card_evidence_test.sh. It exists as a SEPARATE script (not an inline `bash -c`,
## per R-192) because an errexit-triggered ABORT can only be OBSERVED from another process: inside
## the test it would either kill the test shell (errexit active) or be masked (errexit is OFF in a
## subshell on the lhs of `||` / in an `if`/`while` condition). Runs under the SAME strict mode the
## production tool runs under, sources the REAL tool (no copy), and shadows gc_run with a successful
## reinstall carrying NO 'OK: ' line -- the single-package / glued-line case whose extraction, pre-
## fix, aborted the whole run before its own ${build_matches:-...} fallback.
## argv: $1 = path to the dm-whonix-pair tool, $2 = shot_dir for the emitted card.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=../../bin/dm-whonix-pair
source "$1"

## Sanctioned isolation stub (forces the real function's no-'OK:'-line branch); emits a successful
## reinstall whose stdout has no 'OK: ' line, exit 0.
gc_run() {
   printf '%s\n' "Setting up anon-apps-config (7:18.1-1) ..."
   return 0
}

ws='verifyws'
local_repo='whonix'
GUEST_SHARE_MOUNT='/mnt/shared'
LOCAL_TEST_APT_OPTS=''
shot_dir="$2"
ws_func_verify_local_repo_installed

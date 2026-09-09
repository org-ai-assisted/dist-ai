#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the sanity-check error handler in help-steps/mmdebstrap.
##
## THE TRAP IT GUARDS: the wrapper is invoked through PATH by pbuilder /
## grml-debootstrap with help-steps stripped from PATH, so help-steps/pre (which
## defines the error helper) is NOT available. Its sanity checks call an error
## helper on failure; if the wrapper does not define one itself, a failed check
## aborts with a misleading '<helper>: command not found' on the ERROR path --
## the exact path a broken bootstrap takes -- burying the real cause (e.g.
## "DIST_APTGETOPT_SERIALIZED is unset!"). Because this only fires on failure, a
## non-functional handler stays invisible until a real build breaks.
##
## The contract: with a required variable unset, the wrapper prints its own
## intended 'ERROR: ...' message and exits non-zero -- never 'command not found'.
##
## Drives the REAL help-steps/mmdebstrap. No root, no network, no build (the
## wrapper aborts at the first sanity check, long before invoking mmdebstrap).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

wrapper="${dm_checkout}/help-steps/mmdebstrap"
if [ ! -r "${wrapper}" ]; then
   printf '%s\n' "FATAL: help-steps/mmdebstrap not found at '${wrapper}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

## Reproduce the invocation environment: 'env -i' starts from an empty
## environment (so DIST_APTGETOPT_SERIALIZED is unset, tripping the first sanity
## check) with only help-steps stripped from PATH, as pbuilder calls it. Capture
## both streams and the exit code.
output="$(env -i PATH="/usr/sbin:/usr/bin:/sbin:/bin" bash "${wrapper}" 2>&1 || true)"
rc=0
env -i PATH="/usr/sbin:/usr/bin:/sbin:/bin" bash "${wrapper}" >/dev/null 2>&1 || rc="$?"

case "${output}" in
   *"ERROR: DIST_APTGETOPT_SERIALIZED is unset!"*)
      pass "wrapper emits its intended ERROR message when a required variable is unset"
      ;;
   *)
      fail "wrapper did not emit 'ERROR: DIST_APTGETOPT_SERIALIZED is unset!'"
      printf '%s\n' "DEBUG: wrapper output:" >&2
      printf '%s\n' "${output}" >&2
      ;;
esac

case "${output}" in
   *"command not found"*)
      fail "wrapper hit 'command not found' on the error path -- the error helper is undefined"
      ;;
   *)
      pass "wrapper does not fall back to 'command not found' (error helper is defined)"
      ;;
esac

if [ "${rc}" -ne 0 ]; then
   pass "wrapper exits non-zero on a failed sanity check (rc=${rc})"
else
   fail "wrapper exited 0 despite an unset required variable"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: mmdebstrap error handler reports the real cause."

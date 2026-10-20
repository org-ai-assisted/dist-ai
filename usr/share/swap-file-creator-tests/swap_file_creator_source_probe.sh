#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NON-strict: this probe must start with
## errexit OFF to observe whether sourcing SUBJECT (or calling the pure function)
## turns it ON. Run by select_swap_backend_test.sh, which asserts on its stdout
## and exit code. arg1: 'source' (just source) or 'call' (source, then call
## select_swap_backend once).
##
## The subject sources check_runtime.bsh at source time via HELPER_SCRIPTS_PATH
## (inherited from the parent test env), and does NOT auto-run main() when
## sourced (its was_executed guard is false).
##
## Exit: 0 no leak and select_swap_backend is defined; 1 sourcing or the call
## enabled errexit (leak); 3 select_swap_backend is undefined.

# shellcheck disable=SC1090,SC1091,SC2154  # SUBJECT: the swap-file-creator path, from the env
source "${SUBJECT}"

if ! declare -F select_swap_backend >/dev/null ; then
   exit 3
fi

if [ "${1:-}" = "call" ]; then
   select_swap_backend no '' '' >/dev/null 2>&1 || true
fi

## If sourcing (or the call) enabled errexit, this 'false' aborts (exit 1);
## otherwise 'true' yields exit 0.
false
true

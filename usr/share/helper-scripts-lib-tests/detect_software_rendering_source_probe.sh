#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NON-strict: this probe must start with
## errexit OFF to observe whether sourcing SUBJECT (or calling the function)
## turns it ON. Run by detect_software_rendering_test.sh, which asserts on its
## stdout and exit code. arg1: 'source' (just source) or 'call' (source, then
## call the function).
##
## Exit: 0 no leak and the function is defined; 1 sourcing or the call enabled
## errexit (leak); 3 the function is undefined.

# shellcheck disable=SC1090,SC1091
source "${SUBJECT}"

if ! has detect_software_rendering ; then
   exit 3
fi

if [ "${1:-}" = "call" ]; then
   detect_software_rendering >/dev/null 2>&1 || true
fi

## If sourcing (or the call) enabled errexit, this 'false' aborts (exit 1);
## otherwise 'true' yields exit 0.
false
true

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NON-strict: this probe runs in a fresh
## shell (errexit and nounset OFF by default), sources SUBJECT (or sources then
## calls the function), and reports whether sourcing turned errexit or nounset
## back ON (a strict-mode leak into the sourcing shell). Run by
## apparmor_info_filter_test.sh, which asserts on its exit code. arg1: 'source'
## (just source) or 'call' (source, then call the function with empty stdin).
##
## Exit: 0 no leak and the function is defined; non-zero a strict-mode leak
## (errexit or nounset); 3 the function is undefined.

# shellcheck disable=SC1090,SC1091,SC2154  # SUBJECT: the apparmor-info path, from the env
source "${SUBJECT}"

if ! declare -F apparmor_info_filter >/dev/null ; then
   exit 3
fi

if [ "${1:-}" = "call" ]; then
   apparmor_info_filter DENIED </dev/null >/dev/null 2>&1 || true
fi

## nounset leak? Referencing an unset variable aborts the shell under 'set -u';
## under the no-leak baseline it expands to empty and execution continues.
# shellcheck disable=SC2154
printf '%s' "${__apparmor_info_probe_unset_canary__}" >/dev/null

## errexit leak? 'false' aborts the shell under 'set -e'; otherwise 'true' exit 0.
false
true

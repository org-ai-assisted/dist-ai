#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for helper-scripts parse_opt.sh range_arg().
##
## THE BUG: 'for tests in ${list}' was unquoted, so an allow-list entry like 'a*'
## was GLOB-expanded against the current directory. Whether an option value was
## accepted then depended on unrelated files in the CWD -- a value equal to any
## filename that matched an allow-list glob was silently accepted. Fix: iterate
## with globbing disabled (word-splitting on the separators is intended), so
## entries are matched literally.
##
## Drives the REAL range_arg by SOURCING parse_opt.sh. No root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   hs_path="${HELPER_SCRIPTS_REPO}"
else
   hs_path='/usr'
fi
parse_opt="${hs_path}/usr/libexec/helper-scripts/parse_opt.sh"
## HELPER_SCRIPTS_REPO points at a checkout root (contains usr/); the installed
## fallback is /usr, so parse_opt.sh lives at <base>/libexec/... there.
if [ ! -r "${parse_opt}" ]; then
   parse_opt="${hs_path}/libexec/helper-scripts/parse_opt.sh"
fi
if [ ! -r "${parse_opt}" ]; then
   printf '%s\n' "FATAL: parse_opt.sh not readable (set HELPER_SCRIPTS_REPO to a checkout)." >&2
   exit 1
fi
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO:-}"

pass_count=0
fail_count=0
pass() { pass_count=$((pass_count + 1)); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$((fail_count + 1)); printf '%s\n' "FAIL: $*" >&2; }

## A directory whose filenames would be matched by the 'a*' allow-list glob.
work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT
touch -- "${work_dir}/aaa"
touch -- "${work_dir}/bbb"

## Run range_arg in a subshell (range_arg calls 'die', which exits) from inside
## the glob directory. Returns its exit code (0 = value accepted).
run_range() {
   (
      cd -- "${work_dir}" || exit 99
      # shellcheck disable=SC1090
      source "${parse_opt}" >/dev/null 2>&1
      range_arg "$@" >/dev/null 2>&1
   )
}

## 'aaa' is NOT a literal allow-list entry ('a*' and 'other' are). Pre-fix, 'a*'
## globbed to the CWD files aaa/bbb and 'aaa' was wrongly accepted.
if run_range mode aaa "a*" other; then
   fail "range_arg accepted 'aaa' -- allow-list glob 'a*' leaked CWD filenames"
else
   pass "range_arg rejects 'aaa' (allow-list entry 'a*' matched literally, not globbed)"
fi

## the literal allow-list value is still accepted
if run_range mode "a*" "a*" other; then
   pass "range_arg accepts the literal allow-list entry 'a*'"
else
   fail "range_arg wrongly rejected the literal allow-list entry 'a*'"
fi

## an ordinary space-separated allow-list still works
if run_range mode true "true false"; then
   pass "range_arg accepts a normal value from a space-separated allow-list"
else
   fail "range_arg wrongly rejected 'true' from 'true false'"
fi
if run_range mode nope "true false"; then
   fail "range_arg accepted an out-of-range value"
else
   pass "range_arg rejects an out-of-range value"
fi

printf '%s\n' ""
printf '%s\n' "===== range_arg_glob: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]

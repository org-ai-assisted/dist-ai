#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for accountctl.sh get_entry field lookup (ai-review F4).
##
## THE BUG: get_entry did 'index="$(get_field DB FIELD)"' without checking the
## result. For an unsupported/empty field, get_field logs an error and returns
## 1 while printing nothing, so index became '', and 'entry[$((index))]' coerced
## the empty index to 0 -- silently returning the NAME field with a success exit
## code instead of erroring. The fix checks get_field's result.
##
## Drives the REAL get_entry + get_field extracted verbatim from the shipped
## accountctl.sh; the external/root deps it calls are stubbed for isolation.
##
## No root, no network.

## The stub functions (log/has/is_user/is_group/getent) are reached only
## through the extracted get_entry, which shellcheck cannot trace.
# shellcheck disable=SC2317

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/accountctl.sh"
else
   subject='/usr/libexec/helper-scripts/accountctl.sh'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: accountctl.sh not readable at '${subject}'; set HELPER_SCRIPTS_REPO or install helper-scripts." >&2
   exit 1
fi

extract() {
   awk -v fn="$1" 'BEGIN{p="^"fn"\\(\\)\\{$"} $0 ~ p {f=1} f {print} f && /^\}$/ {exit}' "${subject}"
}

## External / root deps -- stubbed. getent returns a fixed passwd entry.
log() { :; }
has() { return 0; }
is_user() { return 0; }
is_group() { return 0; }
getent() { printf '%s\n' 'alice:x:1001:1002:Alice:/home/alice:/bin/bash'; }

# shellcheck disable=SC1090
source /dev/stdin <<< "$(extract get_field)"
# shellcheck disable=SC1090
source /dev/stdin <<< "$(extract get_entry)"

if ! declare -F get_field >/dev/null || ! declare -F get_entry >/dev/null; then
   printf '%s\n' "FATAL: could not extract get_field/get_entry from '${subject}'." >&2
   exit 1
fi

test_failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## ---- a supported field still resolves correctly ----
rc=0
out="$(get_entry alice passwd uid)" || rc=$?
if [ "${rc}" = "0" ] && [ "${out}" = "1001" ]; then
   pass "get_entry returns the uid field ('${out}')"
else
   fail "get_entry uid wrong (rc=${rc}, out='${out}', expected 1001)"
fi

rc=0
out="$(get_entry alice passwd gid)" || rc=$?
if [ "${rc}" = "0" ] && [ "${out}" = "1002" ]; then
   pass "get_entry returns the gid field ('${out}')"
else
   fail "get_entry gid wrong (rc=${rc}, out='${out}', expected 1002)"
fi

## ---- F4: an unsupported field ERRORS rather than returning the name field ----
rc=0
out="$(get_entry alice passwd badfield)" || rc=$?
if [ "${rc}" != "0" ]; then
   pass "get_entry errors on an unsupported field (rc=${rc})"
else
   fail "get_entry silently returned '${out}' with rc 0 for an unsupported field (the bug)"
fi

if [ "${test_failures}" = "0" ]; then
   printf '%s\n' "OK: all accountctl get_entry assertions passed."
   exit 0
fi
printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
exit 1

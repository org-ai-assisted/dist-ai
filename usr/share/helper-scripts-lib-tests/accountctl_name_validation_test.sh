#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for accountctl.sh name validation.
##
## Guards two ai-review findings:
##   F2: is_name_valid used '+' in the trailing char class, so it required at
##       least 2 characters and rejected valid single-character names ('a',
##       'a$'). The fix is '*'.
##   F1: is_user/is_group called is_name_valid as a BARE statement, so its
##       'return 1' on an invalid name was suppressed by errexit under the
##       file's own documented 'is_group X || ...' idiom, letting a name with
##       regex metacharacters reach the grep fallback (cross-account
##       disclosure). The fix enforces it with '|| return 1'.
##
## Drives the REAL functions extracted verbatim from the shipped accountctl.sh.
##
## No root, no network.

## The stub functions (log/as_root/has/getent) are reached only through the
## functions dynamically sourced from accountctl.sh, which shellcheck cannot
## trace, so it reads them as unreachable.
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

## External / root deps the functions call -- stubbed for isolation.
log() { :; }
as_root() { :; }

# shellcheck disable=SC1090
source /dev/stdin <<< "$(extract is_name_valid)"
# shellcheck disable=SC1090
source /dev/stdin <<< "$(extract is_group)"

if ! declare -F is_name_valid >/dev/null || ! declare -F is_group >/dev/null; then
   printf '%s\n' "FATAL: could not extract is_name_valid/is_group from '${subject}'." >&2
   exit 1
fi

test_failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

assert_valid() {
   if is_name_valid "$1"; then pass "accepts valid name: '$1'"; else fail "rejected valid name: '$1'"; fi
}
assert_invalid() {
   if is_name_valid "$1"; then fail "accepted invalid name: '$1'"; else pass "rejects invalid name: '$1'"; fi
}

## ---- F2: single-character and normal names accepted ----
assert_valid a
assert_valid 'a$'
assert_valid user
assert_valid _sys
assert_valid user.name
assert_valid user@host

## ---- validation still rejects the dangerous / malformed names ----
assert_invalid ''
assert_invalid '[ar]oot'
assert_invalid 'se*'
assert_invalid '^x'
assert_invalid 'a b'
assert_invalid 'Ab'
assert_invalid '1x'

## ---- F1: is_group ENFORCES validation before any lookup ----
## Stub the lookup so a bare (unenforced) is_name_valid would fall through to
## it and wrongly succeed; the fix must return 1 before getent is consulted.
getent_called=""
has() { [ "$1" = "getent" ]; }
getent() {
   getent_called="yes"
   return 0
}

rc=0
getent_called=""
is_group '[se]udo' || rc=$?
if [ "${rc}" != "0" ] && [ -z "${getent_called}" ]; then
   pass "is_group rejects a metacharacter name before any lookup"
else
   fail "is_group did not enforce validation (rc=${rc}, getent_called='${getent_called}')"
fi

## A valid, present group still resolves via the (stubbed) lookup.
rc=0
getent_called=""
is_group sudo || rc=$?
if [ "${rc}" = "0" ] && [ "${getent_called}" = "yes" ]; then
   pass "is_group resolves a valid group via the lookup"
else
   fail "is_group failed for a valid group (rc=${rc}, getent_called='${getent_called}')"
fi

if [ "${test_failures}" = "0" ]; then
   printf '%s\n' "OK: all accountctl name-validation assertions passed."
   exit 0
fi
printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
exit 1

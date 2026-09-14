#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Vendoring drift guard for 'group_has_nonroot_member'.
##
## The canonical definition lives in helper-scripts accountctl.sh. security-misc's
## debian/security-misc-shared.preinst VENDORS it verbatim, because a preinst runs
## at unpack time -- before helper-scripts (a plain Depends) is guaranteed
## configured -- so it cannot source the library. This test FAILS if the two
## copies diverge (whitespace/indentation normalized, since the preinst and the
## library indent differently).
##
## Lives in the derivative-maker aggregate suite because both submodules are
## always present in a derivative-maker checkout, so the guard runs
## unconditionally -- a missing copy is a broken checkout (FATAL), never a skip.
##
## No root, no network.

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

canonical="${dm_checkout}/packages/kicksecure/helper-scripts/usr/libexec/helper-scripts/accountctl.sh"
vendored="${dm_checkout}/packages/kicksecure/security-misc/debian/security-misc-shared.preinst"

for f in "${canonical}" "${vendored}"; do
   if [ ! -r "${f}" ]; then
      printf '%s\n' "FATAL: '${f}' not readable; set DERIVATIVE_MAKER_DIR to a full derivative-maker checkout." >&2
      exit 1
   fi
done

## Extract the function body (signature line to first column-0 '}') and strip
## leading whitespace, so the differing indentation between the two files is not
## flagged as drift while any real change is.
extract_normalized() {
   awk '/^group_has_nonroot_member\(\) \{$/ {f=1} f {print} f && /^\}$/ {exit}' "$1" \
      | sed 's/^[[:space:]]*//'
}

canonical_body="$(extract_normalized "${canonical}")"
vendored_body="$(extract_normalized "${vendored}")"

if [ -z "${canonical_body}" ]; then
   fail "group_has_nonroot_member not found in canonical '${canonical}'"
elif [ -z "${vendored_body}" ]; then
   fail "group_has_nonroot_member not found in vendored '${vendored}'"
elif [ "${canonical_body}" = "${vendored_body}" ]; then
   pass "vendored group_has_nonroot_member matches accountctl.sh"
else
   fail "vendored group_has_nonroot_member drifted from accountctl.sh"
   diff <(printf '%s\n' "${canonical_body}") <(printf '%s\n' "${vendored_body}") >&2 || true
fi

if [ "${test_failures}" = "0" ]; then
   printf '%s\n' "OK: group_has_nonroot_member drift guard passed."
   exit 0
fi
printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
exit 1

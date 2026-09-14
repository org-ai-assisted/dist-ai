#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for accountctl.sh 'group_has_nonroot_member'.
##
## THE BUG it guards against: security-misc's install checks used to detect
## group membership with 'getent group <g> | cut -d: -f4', i.e. the group's
## SUPPLEMENTARY member field only. An account whose PRIMARY group is <g>
## (created with 'useradd -g <g>') genuinely has that group's access but never
## appears in the member field, so it was missed -- a real sudo/console-capable
## admin could be locked out (install aborted). 'group_has_nonroot_member' also
## checks primary-GID membership via getent passwd.
##
## Drives the REAL function: extracts it verbatim from the shipped accountctl.sh
## (current text, so the test cannot drift from the code).
##
## Part A: deterministic branch coverage against a stubbed getent (canned
##   passwd/group data), including the primary-GID case the old logic missed.
## Part B: proves the primary-group case is REAL -- finds an actual non-root
##   primary-group-only account on this host (system accounts like 'daemon'
##   provide one on any Debian system) and confirms the pre-fix supplementary-
##   only logic misses it while the new function finds it.
##
## No root, no network.

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

## Extract group_has_nonroot_member verbatim (top-level def, closing brace in
## column 0). Reading the current text keeps the test from drifting.
func_body="$(awk '/^group_has_nonroot_member\(\) \{$/ {f=1} f {print} f && /^\}$/ {exit}' "${subject}")"
if [ -z "${func_body}" ]; then
   printf '%s\n' "FATAL: could not extract group_has_nonroot_member from '${subject}'." >&2
   exit 1
fi
# shellcheck disable=SC1090
source /dev/stdin <<< "${func_body}"

test_failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## The pre-fix detection: the group's SUPPLEMENTARY member field only. Kept here
## to assert that it MISSES a primary-GID member the new function finds.
old_supplementary_only_has_nonroot_member() {
   local grp members member
   local -a member_list
   grp="$1"
   members="$(getent group -- "${grp}" 2>/dev/null | cut -d: -f4)" || true
   IFS="," read -r -a member_list <<< "${members}" || true
   for member in "${member_list[@]}"; do
      if [ -n "${member}" ] && [ "${member}" != "root" ]; then
         return 0
      fi
   done
   return 1
}

assert_member() {
   local group description
   group="$1"; description="$2"
   if group_has_nonroot_member "${group}"; then
      pass "${description}"
   else
      fail "${description} (expected a non-root member, found none)"
   fi
}
assert_no_member() {
   local group description
   group="$1"; description="$2"
   if group_has_nonroot_member "${group}"; then
      fail "${description} (unexpectedly found a non-root member)"
   else
      pass "${description}"
   fi
}

## ---- Part A: deterministic branches against a stubbed getent ----
## Canned data: bob's PRIMARY group is 'testgrp' (gid 5000); alice's primary is
## gid 100. Group member (supplementary) fields as noted.
getent() {
   local db name
   db="$1"; shift
   name=""
   [ "$#" -eq 0 ] || name="${!#}"
   case "${db}" in
      passwd)
         printf '%s\n' 'root:x:0:0:root:/root:/bin/bash'
         printf '%s\n' 'bob:x:6000:5000:Bob:/home/bob:/bin/bash'
         printf '%s\n' 'alice:x:6001:100:Alice:/home/alice:/bin/bash'
         ;;
      group)
         case "${name}" in
            testgrp)
               printf '%s\n' 'testgrp:x:5000:'
               ;;
            suppgrp)
               printf '%s\n' 'suppgrp:x:5100:alice'
               ;;
            rootgrp)
               printf '%s\n' 'rootgrp:x:5200:root'
               ;;
            *)
               return 2
               ;;
         esac
         ;;
      *)
         return 2
         ;;
   esac
}

## The key case: bob is a member of testgrp via PRIMARY GID; testgrp's
## supplementary field is empty.
assert_member testgrp "primary-GID member is found (new logic)"
if old_supplementary_only_has_nonroot_member testgrp; then
   fail "pre-fix supplementary-only logic should MISS the primary-GID member"
else
   pass "pre-fix supplementary-only logic misses the primary-GID member (the bug)"
fi
assert_member suppgrp "supplementary non-root member is found"
assert_no_member rootgrp "group with only root as member is not counted"
assert_no_member missinggrp "missing group yields no member"

unset -f getent

## ---- Part B: prove the primary-group case is real on this host ----
## Find a non-root account whose primary group has NO non-root supplementary
## member -- a genuine primary-group-only membership.
real_group=""
real_account=""
while IFS=: read -r acct_name _ _ acct_gid _; do
   [ "${acct_name}" != "root" ] || continue
   [ -n "${acct_gid}" ] || continue
   grp_name="$(getent group -- "${acct_gid}" 2>/dev/null | cut -d: -f1)" || true
   [ -n "${grp_name}" ] || continue
   ## Skip groups that already have a non-root supplementary member (then the
   ## old logic would find it too, so it would not demonstrate the gap).
   if old_supplementary_only_has_nonroot_member "${grp_name}"; then
      continue
   fi
   real_group="${grp_name}"
   real_account="${acct_name}"
   break
done < <(getent passwd)

if [ -n "${real_group}" ]; then
   printf '%s\n' "INFO: real primary-group-only account: '${real_account}' -> group '${real_group}'"
   if old_supplementary_only_has_nonroot_member "${real_group}"; then
      fail "real host: precondition -- '${real_group}' unexpectedly has a non-root supplementary member"
   else
      pass "real host: pre-fix logic misses '${real_account}' (primary group '${real_group}')"
   fi
   assert_member "${real_group}" "real host: new logic finds '${real_account}' via primary GID"
else
   ## Every stock Debian ships system accounts with primary-group-only
   ## membership (daemon, bin, ...); absence is unexpected but not a failure of
   ## the function -- Part A already exercised the logic deterministically.
   printf '%s\n' "INFO: no real primary-group-only account found on this host; Part A covered the logic."
fi

if [ "${test_failures}" = "0" ]; then
   printf '%s\n' "OK: all group_has_nonroot_member assertions passed."
   exit 0
fi
printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
exit 1

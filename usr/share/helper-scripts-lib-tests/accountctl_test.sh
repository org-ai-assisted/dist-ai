#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Comprehensive unit tests for helper-scripts accountctl.sh.
##
## Drives the REAL library: SOURCES the shipped accountctl.sh (no extraction)
## with HELPER_SCRIPTS_PATH pointed at the checkout, then shadows its external /
## root dependencies (getent, chpasswd, passwd, as_root, log) with fixtures and
## recorders so every query/state/mutation function is exercised deterministically
## without root and without touching real accounts. 'has' accepts a function
## shadow, so 'has getent'/'has passwd' take the getent branch against fixtures.
##
## Covers the ai-review findings as regressions:
##   F1  is_user/is_group enforce is_name_valid before any lookup.
##   F2  is_name_valid accepts single-character names.
##   F4  get_entry errors on an unsupported field instead of returning the name.
## plus name validation, escaping, field mapping, password state/mutation, and
## group_has_nonroot_member (with a real-host primary-group proof).
##
## No root, no network.

## The dependency shadows below are reached only through the sourced library
## functions, which shellcheck cannot trace.
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
   hs_root="${HELPER_SCRIPTS_REPO}"
else
   hs_root='/usr'
fi
subject="${hs_root}/usr/libexec/helper-scripts/accountctl.sh"
[ "${hs_root}" = "/usr" ] && subject='/usr/libexec/helper-scripts/accountctl.sh'
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: accountctl.sh not readable at '${subject}'; set HELPER_SCRIPTS_REPO or install helper-scripts." >&2
   exit 1
fi

## accountctl.sh resolves its own siblings (has.bsh, as_root.sh, log_run_die.sh)
## via HELPER_SCRIPTS_PATH; point it at the same checkout.
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
fi
# shellcheck disable=SC1090
source "${subject}"

test_failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## ---- fixtures + dependency shadows (defined AFTER source to shadow) ----
## passwd: name:x:uid:gid:gecos:home:shell
fixture_passwd="\
root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
carol:x:1002:1002:Carol:/home/carol:/bin/bash
dave:x:1003:1003:Dave:/home/dave:/bin/bash
svc:x:200:5000:Svc:/:/usr/sbin/nologin"
## group: name:x:gid:members
fixture_group="\
root:x:0:
testgrp:x:5000:
suppgrp:x:5100:alice
rootgrp:x:5200:root"
## shadow: name:pass:...  (alice active, bob locked, carol disabled, dave empty)
fixture_shadow="\
root:\$6\$rootsalt\$roothash:19000:0:99999:7:::
alice:\$6\$asalt\$ahash:19000:0:99999:7:::
bob:!\$6\$bsalt\$bhash:19000:0:99999:7:::
carol:*:19000:0:99999:7:::
dave::19000:0:99999:7:::"

## getent <db> [--] [key]: key matches passwd/shadow name (field 1); group key
## matches name (field 1) OR gid (field 3). No key -> whole db. rc 2 if no match.
getent() {
   local db="" key="" arg data line f1 f3 matched=""
   for arg in "$@"; do
      if [ "${arg}" = "--" ]; then
         continue
      fi
      if [ -z "${db}" ]; then
         db="${arg}"
      elif [ -z "${key}" ]; then
         key="${arg}"
      fi
   done
   case "${db}" in
      passwd)
         data="${fixture_passwd}"
         ;;
      group)
         data="${fixture_group}"
         ;;
      shadow)
         data="${fixture_shadow}"
         ;;
      *)
         return 2
         ;;
   esac
   if [ -z "${key}" ]; then
      printf '%s\n' "${data}"
      return 0
   fi
   while IFS= read -r line; do
      f1="${line%%:*}"
      if [ "${f1}" = "${key}" ]; then
         printf '%s\n' "${line}"
         matched="yes"
         continue
      fi
      if [ "${db}" = "group" ]; then
         f3="$(printf '%s' "${line}" | cut -d: -f3)"
         if [ "${f3}" = "${key}" ]; then
            printf '%s\n' "${line}"
            matched="yes"
         fi
      fi
   done <<< "${data}"
   [ -n "${matched}" ] || return 2
}

## as_root: skip the root requirement in the test.
as_root() { :; }
## log: silence.
log() { :; }
## passwd / chpasswd: record what mutation was requested (no real change).
mutation_log=""
passwd() { mutation_log="${mutation_log}passwd $* "; }
chpasswd() { local in; in="$(cat)"; mutation_log="${mutation_log}chpasswd[${*}]<${in}> "; }

## ---- is_name_valid (F2 + validation) ----
for n in a 'a$' user _sys user.name user@host; do
   if is_name_valid "${n}"; then pass "is_name_valid accepts '${n}'"; else fail "is_name_valid rejected valid '${n}'"; fi
done
for n in '' '[ar]oot' 'se*' '^x' 'a b' 'Ab' '1x'; do
   if is_name_valid "${n}"; then fail "is_name_valid accepted invalid '${n}'"; else pass "is_name_valid rejects '${n}'"; fi
done

## ---- escape_name ----
if [ "$(escape_name 'a.b$c')" = 'a\.b\$c' ]; then pass "escape_name escapes . and \$"; else fail "escape_name wrong: '$(escape_name 'a.b$c')'"; fi

## ---- is_user / is_group (existence + F1 enforcement) ----
if is_user alice; then pass "is_user finds existing user"; else fail "is_user missed alice"; fi
if is_user nouser 2>/dev/null; then fail "is_user accepted nonexistent"; else pass "is_user rejects nonexistent"; fi
if is_user '[a]lice' 2>/dev/null; then fail "is_user F1: accepted metacharacter name"; else pass "is_user rejects metacharacter name (F1)"; fi
if is_group testgrp; then pass "is_group finds existing group"; else fail "is_group missed testgrp"; fi
if is_group nogroup 2>/dev/null; then fail "is_group accepted nonexistent"; else pass "is_group rejects nonexistent"; fi
if is_group '[t]estgrp' 2>/dev/null; then fail "is_group F1: accepted metacharacter name"; else pass "is_group rejects metacharacter name (F1)"; fi

## ---- get_field ----
if [ "$(get_field passwd uid)" = "2" ]; then pass "get_field passwd uid -> 2"; else fail "get_field passwd uid wrong"; fi
if [ "$(get_field group members)" = "3" ]; then pass "get_field group members -> 3"; else fail "get_field group members wrong"; fi
rc=0; get_field passwd bogus >/dev/null 2>&1 || rc=$?
if [ "${rc}" != "0" ]; then pass "get_field errors on unknown field"; else fail "get_field accepted unknown field"; fi

## ---- get_entry (F4) ----
if [ "$(get_entry alice passwd uid)" = "1000" ]; then pass "get_entry alice passwd uid -> 1000"; else fail "get_entry uid wrong: '$(get_entry alice passwd uid)'"; fi
if [ "$(get_entry alice passwd home)" = "/home/alice" ]; then pass "get_entry alice passwd home"; else fail "get_entry home wrong"; fi
rc=0; out="$(get_entry alice passwd bogus 2>/dev/null)" || rc=$?
if [ "${rc}" != "0" ]; then pass "get_entry errors on unsupported field (F4)"; else fail "get_entry F4: returned '${out}' rc 0 for a bad field"; fi

## ---- get_pass / get_clean_pass ----
if [ "$(get_pass alice)" = '$6$asalt$ahash' ]; then pass "get_pass alice"; else fail "get_pass alice wrong: '$(get_pass alice)'"; fi
if [ "$(get_clean_pass bob '!')" = '$6$bsalt$bhash' ]; then pass "get_clean_pass strips leading '!'"; else fail "get_clean_pass wrong: '$(get_clean_pass bob '!')'"; fi

## ---- is_pass_empty / is_pass_locked / is_pass_disabled ----
if is_pass_empty dave; then pass "is_pass_empty dave"; else fail "is_pass_empty missed dave"; fi
if is_pass_empty alice; then fail "is_pass_empty false-positive alice"; else pass "is_pass_empty rejects alice"; fi
if is_pass_locked bob; then pass "is_pass_locked bob"; else fail "is_pass_locked missed bob"; fi
if is_pass_locked alice; then fail "is_pass_locked false-positive alice"; else pass "is_pass_locked rejects alice"; fi
if is_pass_disabled carol; then pass "is_pass_disabled carol"; else fail "is_pass_disabled missed carol"; fi
if is_pass_disabled alice; then fail "is_pass_disabled false-positive alice"; else pass "is_pass_disabled rejects alice"; fi

## ---- lock_pass / unlock_pass (mutation dispatch) ----
mutation_log=""; lock_pass alice
if [[ "${mutation_log}" == *"passwd --quiet --lock -- alice"* ]]; then pass "lock_pass locks an unlocked account"; else fail "lock_pass did not call passwd --lock: '${mutation_log}'"; fi
mutation_log=""; lock_pass bob
if [ -z "${mutation_log}" ]; then pass "lock_pass no-ops an already-locked account"; else fail "lock_pass acted on a locked account: '${mutation_log}'"; fi
mutation_log=""; unlock_pass bob
if [[ "${mutation_log}" == *'chpasswd'*'bob:$6$bsalt$bhash'* ]]; then pass "unlock_pass restores the clean password"; else fail "unlock_pass wrong: '${mutation_log}'"; fi

## ---- group_has_nonroot_member (primary GID + supplementary) ----
if group_has_nonroot_member testgrp; then pass "group_has_nonroot_member finds a primary-GID member (svc)"; else fail "group_has_nonroot_member missed the primary-GID member"; fi
if group_has_nonroot_member suppgrp; then pass "group_has_nonroot_member finds a supplementary member (alice)"; else fail "group_has_nonroot_member missed the supplementary member"; fi
if group_has_nonroot_member rootgrp; then fail "group_has_nonroot_member counted a root-only group"; else pass "group_has_nonroot_member ignores a root-only group"; fi
if group_has_nonroot_member nogroup; then fail "group_has_nonroot_member matched a missing group"; else pass "group_has_nonroot_member rejects a missing group"; fi

## ---- group_has_nonroot_member: real-host primary-group proof ----
## Restore the real getent to prove a genuine primary-group membership exists
## and is found (system accounts like 'daemon' provide one on any Debian host).
unset -f getent
old_supp_only() {
   local grp m; local -a ml
   grp="$1"
   m="$(command getent group -- "${grp}" 2>/dev/null | cut -d: -f4)" || true
   IFS="," read -r -a ml <<< "${m}" || true
   for member in "${ml[@]}"; do
      if [ -n "${member}" ] && [ "${member}" != "root" ]; then
         return 0
      fi
   done
   return 1
}
real_group=""
while IFS=: read -r acct _ _ gid _; do
   [ "${acct}" != "root" ] || continue
   [ -n "${gid}" ] || continue
   gname="$(command getent group -- "${gid}" 2>/dev/null | cut -d: -f1)" || true
   [ -n "${gname}" ] || continue
   if old_supp_only "${gname}"; then
      continue
   fi
   real_group="${gname}"
   break
done < <(command getent passwd)
if [ -n "${real_group}" ]; then
   if old_supp_only "${real_group}"; then
      fail "real host: '${real_group}' unexpectedly has a non-root supplementary member"
   else
      pass "real host: pre-fix supplementary-only logic misses primary group '${real_group}'"
   fi
   if group_has_nonroot_member "${real_group}"; then pass "real host: new logic finds the primary-group member of '${real_group}'"; else fail "real host: new logic missed '${real_group}'"; fi
else
   printf '%s\n' "INFO: no real primary-group-only account found; fixtures covered the logic."
fi

if [ "${test_failures}" = "0" ]; then
   printf '%s\n' "OK: all accountctl assertions passed."
   exit 0
fi
printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
exit 1

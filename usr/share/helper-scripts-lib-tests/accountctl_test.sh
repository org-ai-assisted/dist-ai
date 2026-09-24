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

## The subject MUST define every function this suite drives. A missing one means
## a stale/wrong accountctl.sh (e.g. an older installed copy predating a
## function): FATAL, never a vacuous pass. Without this, a 'reject' assertion
## (if fn; then fail; else pass) reads bash's 127 "command not found" as an
## ordinary false and reports PASS for a function that does not exist.
accountctl_required_functions='is_name_valid escape_name is_user is_group get_field get_entry get_pass get_clean_pass is_pass_empty is_pass_locked is_pass_disabled lock_pass unlock_pass disable_pass group_has_nonroot_member'
accountctl_missing_functions=''
for accountctl_fn in ${accountctl_required_functions}; do
   declare -F "${accountctl_fn}" >/dev/null 2>&1 || accountctl_missing_functions="${accountctl_missing_functions} ${accountctl_fn}"
done
if [ -n "${accountctl_missing_functions}" ]; then
   printf '%s\n' "FATAL: accountctl.sh at '${subject}' is missing required function(s):${accountctl_missing_functions}; the subject is stale or wrong (point HELPER_SCRIPTS_REPO at a current checkout)." >&2
   exit 1
fi

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
erin:x:1004:1004:Erin:/home/erin:/bin/bash
svc:x:200:5000:Svc:/:/usr/sbin/nologin
legacy:x:500:0:Legacy gid-0 account:/:/usr/sbin/nologin"
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
dave::19000:0:99999:7:::
erin:!!:19000:0:99999:7:::"

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
   ## Record every lookup so an F1 test can assert the is_name_valid gate
   ## short-circuits BEFORE any getent lookup (a rejected-by-lookup miss and a
   ## rejected-by-gate refusal both return false; only the call trace tells them
   ## apart).
   getent_calls="${getent_calls:-}${db}:${key} "
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
for n in a 'a$' user _sys user.name user@host Ab AdminUser _SysOp; do
   if is_name_valid "${n}"; then pass "is_name_valid accepts '${n}'"; else fail "is_name_valid rejected valid '${n}'"; fi
done
for n in '' '[ar]oot' 'se*' '^x' 'a b' '1x' '.hidden'; do
   if is_name_valid "${n}"; then fail "is_name_valid accepted invalid '${n}'"; else pass "is_name_valid rejects '${n}'"; fi
done

## A non-ASCII name must be rejected even when the CALLER runs under a UTF-8
## locale: glibc would otherwise collate-expand [a-zA-Z] and accept it. The fix
## is is_name_valid's own 'local LC_ALL=C'. Needs a full-collation UTF-8 locale
## (C.UTF-8's minimal collation does not expand ranges); skip only this check,
## not the suite, when none is installed (e.g. a minimal CI image).
utf8_locale=""
locale_list="$(locale -a 2>/dev/null || true)"
for cand in en_US.UTF-8 en_US.utf8 de_DE.UTF-8; do
   if grep --quiet --ignore-case --line-regexp -- "${cand//UTF-8/utf8}" <<<"${locale_list}"; then
      utf8_locale="${cand}"
      break
   fi
done
non_ascii="$(printf '\xc3\x89')"   # U+00C9 (E with acute); no raw non-ASCII in source
if [ -n "${utf8_locale}" ]; then
   if LC_ALL="${utf8_locale}" is_name_valid "${non_ascii}"; then
      fail "is_name_valid accepted a non-ASCII name under ${utf8_locale} (missing LC_ALL=C)"
   else
      pass "is_name_valid rejects a non-ASCII name under ${utf8_locale} (LC_ALL=C forces ASCII)"
   fi
else
   printf '%s\n' "  INFO: no full-collation UTF-8 locale installed; skipped the non-ASCII is_name_valid check"
fi

## ---- escape_name ----
# shellcheck disable=SC2016  # single-quoted literals are test input/expected output, not expansions
if [ "$(escape_name 'a.b$c')" = 'a\.b\$c' ]; then pass "escape_name escapes . and \$"; else fail "escape_name wrong: '$(escape_name 'a.b$c')'"; fi

## ---- is_user / is_group (existence + F1 enforcement) ----
if is_user alice; then pass "is_user finds existing user"; else fail "is_user missed alice"; fi
if is_user nouser 2>/dev/null; then fail "is_user accepted nonexistent"; else pass "is_user rejects nonexistent"; fi
## F1: an invalid name must be rejected by the is_name_valid gate BEFORE any
## lookup. A bogus name misses the lookup too, so the return value alone cannot
## prove the gate fired -- assert getent was never reached (getent_calls stays
## empty). Absent the '|| return 1', is_user would fall through to getent here.
getent_calls=""
if is_user '[a]lice' 2>/dev/null; then
   fail "is_user F1: accepted metacharacter name"
elif [ -n "${getent_calls}" ]; then
   fail "is_user F1: reached getent for an invalid name (is_name_valid gate not enforced): '${getent_calls}'"
else
   pass "is_user rejects metacharacter name before any lookup (F1)"
fi
if is_group testgrp; then pass "is_group finds existing group"; else fail "is_group missed testgrp"; fi
if is_group nogroup 2>/dev/null; then fail "is_group accepted nonexistent"; else pass "is_group rejects nonexistent"; fi
getent_calls=""
if is_group '[t]estgrp' 2>/dev/null; then
   fail "is_group F1: accepted metacharacter name"
elif [ -n "${getent_calls}" ]; then
   fail "is_group F1: reached getent for an invalid name (is_name_valid gate not enforced): '${getent_calls}'"
else
   pass "is_group rejects metacharacter name before any lookup (F1)"
fi

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
# shellcheck disable=SC2016  # single-quoted hash literal is expected output, not an expansion
if [ "$(get_pass alice)" = '$6$asalt$ahash' ]; then pass "get_pass alice"; else fail "get_pass alice wrong: '$(get_pass alice)'"; fi
# shellcheck disable=SC2016  # single-quoted hash literal is expected output, not an expansion
if [ "$(get_clean_pass bob '!')" = '$6$bsalt$bhash' ]; then pass "get_clean_pass strips leading '!'"; else fail "get_clean_pass wrong: '$(get_clean_pass bob '!')'"; fi

## ---- is_pass_empty / is_pass_locked / is_pass_disabled ----
if is_pass_empty dave; then pass "is_pass_empty dave"; else fail "is_pass_empty missed dave"; fi
if is_pass_empty alice; then fail "is_pass_empty false-positive alice"; else pass "is_pass_empty rejects alice"; fi
if is_pass_locked bob; then pass "is_pass_locked bob"; else fail "is_pass_locked missed bob"; fi
if is_pass_locked alice; then fail "is_pass_locked false-positive alice"; else pass "is_pass_locked rejects alice"; fi
if is_pass_disabled carol; then pass "is_pass_disabled carol"; else fail "is_pass_disabled missed carol"; fi
if is_pass_disabled alice; then fail "is_pass_disabled false-positive alice"; else pass "is_pass_disabled rejects alice"; fi

## ---- F5: is_user/is_group return checked at every call site (issue #84) ----
## A valid-but-nonexistent name must make the query/state functions FAIL, not
## fall through to getent (which yields empty output, rc 0). Pre-fix, the bare
## 'is_user'/'is_group' (no '|| return 1') was swallowed under the library's
## no-errexit convention, so a caller treated a nonexistent account as existing
## with an empty password. 'nosuchuser'/'nosuchgrp' are valid names absent from
## the fixtures.
rc=0; out="$(get_entry nosuchuser passwd shell 2>/dev/null)" || rc=$?
if [ "${rc}" != "0" ]; then pass "get_entry fails for a nonexistent user (F5/#84)"; else fail "get_entry F5: rc 0 (out='${out}') for a nonexistent user"; fi
rc=0; out="$(get_pass nosuchuser 2>/dev/null)" || rc=$?
if [ "${rc}" != "0" ]; then pass "get_pass fails for a nonexistent user (F5/#84)"; else fail "get_pass F5: rc 0 (out='${out}') for a nonexistent user"; fi
if is_pass_empty nosuchuser 2>/dev/null; then fail "is_pass_empty F5: reported a nonexistent user's password empty (#84)"; else pass "is_pass_empty rejects a nonexistent user (F5/#84)"; fi
if is_pass_locked nosuchuser 2>/dev/null; then fail "is_pass_locked F5: matched a nonexistent user (#84)"; else pass "is_pass_locked rejects a nonexistent user (F5/#84)"; fi
rc=0; out="$(get_entry nosuchgrp group members 2>/dev/null)" || rc=$?
if [ "${rc}" != "0" ]; then pass "get_entry fails for a nonexistent group (F5/#84)"; else fail "get_entry F5: rc 0 (out='${out}') for a nonexistent group"; fi

## ---- lock_pass / unlock_pass (mutation dispatch) ----
mutation_log=""; lock_pass alice
if [[ "${mutation_log}" == *"passwd --quiet --lock -- alice"* ]]; then pass "lock_pass locks an unlocked account"; else fail "lock_pass did not call passwd --lock: '${mutation_log}'"; fi
mutation_log=""; lock_pass bob
if [ -z "${mutation_log}" ]; then pass "lock_pass no-ops an already-locked account"; else fail "lock_pass acted on a locked account: '${mutation_log}'"; fi
mutation_log=""; unlock_pass bob
# shellcheck disable=SC2016  # single-quoted hash literal is a match pattern, not an expansion
if [[ "${mutation_log}" == *'chpasswd'*'bob:$6$bsalt$bhash'* ]]; then pass "unlock_pass restores the clean password"; else fail "unlock_pass wrong: '${mutation_log}'"; fi

## ---- '!!' shadow field ('passwd -l' on a never-set password): strip ALL
##      leading markers, not one per symbol char (findings F1/F2/F3) ----
if is_pass_empty erin; then pass "is_pass_empty detects a '!!' (never-set) account (F2)"; else fail "is_pass_empty missed the '!!' account"; fi
mutation_log=""; unlock_pass erin
if [[ "${mutation_log}" == *'<erin:>'* ]]; then pass "unlock_pass fully unlocks a '!!' account (F1)"; else fail "unlock_pass left a marker on '!!': '${mutation_log}'"; fi
mutation_log=""; disable_pass erin
if [[ "${mutation_log}" == *'<erin:!*>'* ]]; then pass "disable_pass writes a clean '!*' for a '!!' account (F3)"; else fail "disable_pass corrupted the '!!' field: '${mutation_log}'"; fi

## ---- group_has_nonroot_member (primary GID + supplementary) ----
if group_has_nonroot_member testgrp; then pass "group_has_nonroot_member finds a primary-GID member (svc)"; else fail "group_has_nonroot_member missed the primary-GID member"; fi
if group_has_nonroot_member suppgrp; then pass "group_has_nonroot_member finds a supplementary member (alice)"; else fail "group_has_nonroot_member missed the supplementary member"; fi
if group_has_nonroot_member rootgrp; then fail "group_has_nonroot_member counted a root-only group"; else pass "group_has_nonroot_member ignores a root-only group"; fi
if group_has_nonroot_member nogroup; then fail "group_has_nonroot_member matched a missing group"; else pass "group_has_nonroot_member rejects a missing group"; fi
## F4: a numeric argument must be rejected outright, not reinterpreted by getent
## as a GID lookup. Probe 5100 -- the GID of suppgrp, which HAS a non-root member
## (alice). Absent the [a-zA-Z_] guard, 'getent group -- 5100' resolves suppgrp and
## finds alice, so the function would return true; the guard makes it reject.
## (Probing '0' proves nothing: GID 0's group is empty, so even a guard-less
## impl returns false for it.)
if group_has_nonroot_member 5100; then fail "group_has_nonroot_member did a GID lookup for '5100' (F4 guard missing)"; else pass "group_has_nonroot_member rejects a numeric argument (F4)"; fi

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

## ---- property fuzz: drive the real pure functions over many random inputs ----
fuzz_script="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/accountctl_fuzz.sh"
if [ ! -r "${fuzz_script}" ]; then
   fail "accountctl_fuzz.sh not found at '${fuzz_script}'"
else
   fuzz_seed="${ACCOUNTCTL_FUZZ_SEED:-1}"
   fuzz_iters="${ACCOUNTCTL_FUZZ_ITERS:-500}"
   fuzz_out="$(SUBJECT="${subject}" bash "${fuzz_script}" "${fuzz_seed}" "${fuzz_iters}" 2>&1)"
   fuzz_fails="$(printf '%s\n' "${fuzz_out}" | sed -n 's/^FUZZFAILS=//p')"
   if [ "${fuzz_fails:-1}" = "0" ]; then
      pass "property fuzz: ${fuzz_iters} iterations, 0 violations (seed ${fuzz_seed})"
   else
      fail "property fuzz: ${fuzz_fails} violation(s)"
      printf '%s\n' "${fuzz_out}" >&2
   fi
fi

if [ "${test_failures}" = "0" ]; then
   printf '%s\n' "OK: all accountctl assertions passed."
   exit 0
fi
printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
exit 1

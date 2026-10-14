#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## password_strength.sh: password_strength_check gates a passphrase (read from
## STDIN) through libpwquality 'pwscore' and accepts ONLY the maximum score
## (100). It is stricter than pwscore's own accept/reject: a passphrase pwscore
## accepts with a sub-maximum score must still be refused. That "require best"
## rule is the canary below -- a bare mirror of pwscore's exit status would pass
## it wrongly.
##
## Sources the INSTALLED password_strength.sh by default; HELPER_SCRIPTS_REPO
## points it at a checkout (how the suite runner wires CI). Requires a working
## pwscore (libpwquality + the cracklib dictionary); an absent/broken pwscore is
## an ENVIRONMENT bug -> FATAL, never a skip. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   password_strength_sh_path="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/password_strength.sh"
else
   password_strength_sh_path='/usr/libexec/helper-scripts/password_strength.sh'
fi

if [ ! -r "${password_strength_sh_path}" ]; then
   printf '%s\n' "FATAL: password_strength.sh not readable at '${password_strength_sh_path}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

## shellcheck resolves the file statically from dist-ai's own tree, which has no
## helper-scripts copy, so there is nothing to point 'source=' at.
# shellcheck disable=SC1090,SC1091
source "${password_strength_sh_path}"

if [ ! "$(type -t password_strength_check)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${password_strength_sh_path}' defined no 'password_strength_check' function" >&2
   exit 1
fi

## A known-strong passphrase MUST reach the maximum score, proving pwscore and
## its cracklib dictionary are functional. If it does not, the environment is
## broken (pwscore absent, or the dictionary unbuilt) -- fail loud, do not skip.
strong_passphrase='correct-horse-battery-staple-9x7q-river-mountain'
strong_score=0
strong_score="$(printf '%s' "${strong_passphrase}" | pwscore 2>/dev/null)" || strong_score='PWSCORE_ERROR'
if [ ! "${strong_score}" = "100" ]; then
   printf '%s\n' "FATAL: environment: pwscore did not score a strong passphrase 100 (got '${strong_score}'); libpwquality or the cracklib dictionary is missing/broken" >&2
   exit 1
fi

pass_count=0
fail_count=0

check_accepts() {
   if printf '%s' "$1" | password_strength_check; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: accepts strong passphrase"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: expected strong passphrase accepted, was refused"
   fi
}

check_refuses() {
   if printf '%s' "$1" | password_strength_check; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: expected '$2' refused, was accepted"
   else
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: refuses '$2'"
   fi
}

## --- accepted: only a maximum-score passphrase ------------------------------
check_accepts "${strong_passphrase}"

## --- refused: weak passphrases pwscore itself rejects -----------------------
check_refuses 'password' 'dictionary word'
check_refuses 'hunter2' 'too short'
check_refuses '' 'empty'

## --- CANARY: "require best score" -------------------------------------------
## A passphrase pwscore ACCEPTS (exit 0) but scores BELOW 100 must still be
## refused by password_strength_check. A helper that merely mirrored pwscore's
## exit status would accept it and this case would fail.
medium_passphrase='medium-pass-9'
medium_score=0
medium_rc=0
medium_score="$(printf '%s' "${medium_passphrase}" | pwscore 2>/dev/null)" || medium_rc=$?
if [ "${medium_rc}" -ne 0 ] || [ "${medium_score}" = "100" ] || [ -z "${medium_score}" ]; then
   printf '%s\n' "FATAL: canary fixture invalid: pwscore must ACCEPT '${medium_passphrase}' with a sub-100 score (rc=${medium_rc} score='${medium_score}'); pick another fixture" >&2
   exit 1
fi
if printf '%s' "${medium_passphrase}" | password_strength_check; then
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: canary: accepted '${medium_passphrase}' (pwscore ${medium_score}/100); require-best-score not enforced"
else
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: canary: refuses '${medium_passphrase}' that pwscore accepts at ${medium_score}/100"
fi

## --- CANARY: usercheck via the optional username argument ------------------
## A passphrase that scores 100 with NO username must be REFUSED when the
## account name it contains is passed, proving the username reaches pwscore's
## usercheck. Without the argument pwscore skips usercheck, so a helper that
## dropped the argument would accept it and this case would fail.
usercheck_name='alice'
usercheck_pass='alice-xK9#mQ2sVL7qrt'
usercheck_score=0
usercheck_rc=0
usercheck_score="$(printf '%s' "${usercheck_pass}" | pwscore 2>/dev/null)" || usercheck_rc=$?
if [ "${usercheck_rc}" -ne 0 ] || [ ! "${usercheck_score}" = "100" ]; then
   printf '%s\n' "FATAL: usercheck fixture invalid: pwscore must score '${usercheck_pass}' 100 WITHOUT a username (rc=${usercheck_rc} score='${usercheck_score}')" >&2
   exit 1
fi
if printf '%s' "${usercheck_pass}" | password_strength_check "${usercheck_name}"; then
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: usercheck: accepted a passphrase containing the username '${usercheck_name}'"
else
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: usercheck: refuses a passphrase containing the username '${usercheck_name}'"
fi

printf '%s\n' ""
printf '%s\n' "===== password_strength_check: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]

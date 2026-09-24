#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## username-plain-for-sudoers (help-steps/build-step-helpers.bsh, used by
## 1200_prepare-build-machine) gates a value interpolated verbatim into a sudoers
## rule. It delegates the /etc/adduser.conf NAME_REGEX to the canonical
## check_valid_linux_user_account_name (helper-scripts strings.bsh) and adds the
## sudoers-specific rejection of the reserved word 'ALL'. So it must ACCEPT a
## plain [A-Za-z_][A-Za-z0-9_-]* name and one with a single trailing '$' (Samba
## machine account), and REFUSE a leading digit/dash, any sudoers metacharacter,
## and 'ALL'.
##
## Both real functions are SOURCED (build-step-helpers.bsh + the strings.bsh it
## relies on); the canary shows the NAME_REGEX check alone would let 'ALL'
## through. Needs no root, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

## strings.bsh (check_valid_linux_user_account_name) is sourced the same way the
## build does it (help-steps/variables): HELPER_SCRIPTS_PATH-relative, defaulting
## to the dm checkout's helper-scripts submodule. It sources its own siblings via
## HELPER_SCRIPTS_PATH, so export it before sourcing.
: "${HELPER_SCRIPTS_PATH:=${dm_checkout}/packages/kicksecure/helper-scripts}"
export HELPER_SCRIPTS_PATH
strings_bsh="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh"
if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not found at '${strings_bsh}' (needed for check_valid_linux_user_account_name)." >&2
   exit 1
fi
# shellcheck disable=SC1090
source "${strings_bsh}"

lib="${dm_checkout}/help-steps/build-step-helpers.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FAIL: cannot read ${lib}" >&2
   exit 1
fi
# shellcheck disable=SC1090
source "${lib}"

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

check_accept() {
   if username-plain-for-sudoers "$1"; then
      pass "accepts '$1'"
   else
      fail "expected '$1' accepted, was refused"
   fi
}
check_reject() {
   if username-plain-for-sudoers "$1"; then
      fail "expected '$1' refused, was accepted"
   else
      pass "refuses '$1'"
   fi
}

## --- accepted: plain names and a single trailing '$' -----------------------
check_accept alice
check_accept root
check_accept _svc
check_accept build-user
check_accept x9
check_accept 'host$'
## A name is only a sudoers alias token if it is ENTIRELY [A-Z][A-Z0-9_]*; any
## lowercase letter makes it a real user again.
check_accept Root
check_accept ROOTx

## --- refused: sudoers uppercase-alias tokens and metacharacters -------------
check_reject ''
## sudoers reads a bare [A-Z][A-Z0-9_]* word as an alias reference, not a user:
## 'ALL' grants everyone; 'BUILD'/'ROOT' are undefined-alias references.
check_reject ALL
check_reject BUILD
check_reject ROOT
check_reject A
check_reject 'a b'
check_reject 'a%b'
check_reject 'a=b'
check_reject 'a,b'
check_reject 'a:b'
# shellcheck disable=SC2016
check_reject 'a$b'
## Only ONE trailing '$' is tolerated.
check_reject 'host$$'
## A lone '$' is not a valid name.
check_reject '$'
## NAME_REGEX requires a leading letter/underscore: a leading digit or dash is
## refused (the pre-reuse form wrongly accepted both).
check_reject '9x'
check_reject '-foo'

## --- CANARY: the uppercase-alias guard is load-bearing ---------------------
## check_valid_linux_user_account_name (the NAME_REGEX check we delegate to)
## ACCEPTS 'BUILD' -- it is a syntactically valid account name -- yet sudoers
## reads it as an alias token. A gate relying on NAME_REGEX plus only an 'ALL'
## reject would wrongly accept 'BUILD'. Confirm NAME_REGEX accepts it while the
## real function refuses.
nameregex_accepts_build=no
if check_valid_linux_user_account_name BUILD ; then
   nameregex_accepts_build=yes
fi
if [ "${nameregex_accepts_build}" = "yes" ] && ! username-plain-for-sudoers BUILD ; then
   pass "canary: NAME_REGEX accepts 'BUILD'; the sudoers-alias guard refuses it"
else
   fail "canary broken: nameregex_accepts_build=${nameregex_accepts_build}"
fi

summary_line="===== username-plain-for-sudoers: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0

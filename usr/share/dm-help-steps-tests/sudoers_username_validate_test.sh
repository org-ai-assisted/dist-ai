#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## username-plain-for-sudoers (help-steps/build-step-helpers.bsh, used by
## 1200_prepare-build-machine) gates a value interpolated verbatim into a sudoers
## rule. It must REFUSE anything carrying a sudoers metacharacter or the reserved
## word 'ALL', and ACCEPT a plain [A-Za-z0-9_-] name plus one with a single
## trailing '$' (Samba machine account), which /etc/adduser.conf NAME_REGEX also
## permits.
##
## The real function is SOURCED from the shared helper library; the canary
## redefines the pre-fix form in a subshell. Needs no root, no build.

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

## --- refused: reserved word and sudoers metacharacters ---------------------
check_reject ''
check_reject ALL
check_reject 'a b'
check_reject 'a%b'
check_reject 'a=b'
check_reject 'a,b'
check_reject 'a:b'
check_reject 'a$b'
## Only ONE trailing '$' is tolerated.
check_reject 'host$$'
## A lone '$' strips to empty.
check_reject '$'

## --- CANARY: accepting a trailing '$' is the actual fix --------------------
## The pre-fix form did not strip a trailing '$', so 'host$' hit the
## metacharacter class and was refused. Redefine that form in a subshell and
## confirm it refuses 'host$' while still refusing a real metacharacter.
buggy_refuses_host=no
buggy_refuses_meta=no
(
   username-plain-for-sudoers() {
      case "$1" in
         ''|*[!A-Za-z0-9_-]*)
            return 1
            ;;
         ALL)
            return 1
            ;;
      esac
      return 0
   }
   username-plain-for-sudoers 'host$'
) || buggy_refuses_host=yes
(
   username-plain-for-sudoers() {
      case "$1" in
         ''|*[!A-Za-z0-9_-]*)
            return 1
            ;;
         ALL)
            return 1
            ;;
      esac
      return 0
   }
   username-plain-for-sudoers 'a b'
) || buggy_refuses_meta=yes
if [ "${buggy_refuses_host}" = "yes" ] && [ "${buggy_refuses_meta}" = "yes" ]; then
   pass "canary: the pre-fix form refuses 'host\$' (and still refuses metachars)"
else
   fail "canary broken: host=${buggy_refuses_host} meta=${buggy_refuses_meta}"
fi

summary_line="===== username-plain-for-sudoers: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0

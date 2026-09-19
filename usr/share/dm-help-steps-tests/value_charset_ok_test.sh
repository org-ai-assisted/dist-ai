#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## value_charset_ok (variables.d/05_lib.bsh) is the one place the branding/identity
## build vars (dist_build_hostname, dist_build_type_short[_pretty],
## dist_build_version) are charset-checked at their resolution in variables.d.
## Those values are spliced UNQUOTED into the ISO GRUB menu, the live kernel
## cmdline and the boot splash, so it must REFUSE an empty value and any character
## outside the caller's allow-list -- especially a space (cmdline split) or a
## newline (GRUB command injection).
##
## The real function is SOURCED. Needs no root, no build.

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

lib="${dm_checkout}/variables.d/05_lib.bsh"
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

check_ok() {
   if value_charset_ok "$1" "$2"; then
      pass "accepts '$1' in [$2]"
   else
      fail "expected '$1' accepted in [$2], was refused"
   fi
}
check_bad() {
   if value_charset_ok "$1" "$2"; then
      fail "expected '$1' refused in [$2], was accepted"
   else
      pass "refuses '$1' in [$2]"
   fi
}

## --- accepted: the real build-var shapes -----------------------------------
check_ok 'localhost'          'A-Za-z0-9.-'
check_ok 'host.example.com'   'A-Za-z0-9.-'
check_ok 'dist-installer-cli' 'A-Za-z0-9._-'
check_ok '17.4.3.7-1-gabc123' 'A-Za-z0-9._-'
check_ok 'Kicksecure'         'A-Za-z0-9 ._-'
check_ok 'Kicksecure 17'      'A-Za-z0-9 ._-'

## --- refused: empty, out-of-class, and injection vectors -------------------
check_bad ''            'A-Za-z0-9.-'
check_bad 'a b'         'A-Za-z0-9.-'
check_bad 'a;grub'      'A-Za-z0-9.-'
check_bad 'a<b'         'A-Za-z0-9 ._-'
## a space is in the pretty class but NOT the hostname/version class
check_bad 'has space'   'A-Za-z0-9._-'
## a newline (GRUB command injection) is refused by every class
check_bad "$(printf 'a\nb')" 'A-Za-z0-9 ._-'

## --- CANARY: the charset check is load-bearing -----------------------------
## A non-empty-only check would accept a newline-bearing value; value_charset_ok
## refuses it. Confirm the value is non-empty yet still rejected.
inj="$(printf 'grubline\ninjected')"
if [ -n "${inj}" ] && ! value_charset_ok "${inj}" 'A-Za-z0-9.-'; then
   pass 'canary: a non-empty newline value is refused (a non-empty check would pass it)'
else
   fail 'canary broken: newline value not refused'
fi

summary_line="===== value_charset_ok: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0

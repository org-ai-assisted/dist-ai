#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Assert the exact VBoxManage guestcontrol argv built by gc_run (vbox-session.bsh),
## with a capturing VBOXMANAGE stub -- no VM. Covers the empty-password channel
## (task #83), the shell-snippet wrapping (/bin/bash then -- -lc; argv[0] is
## auto-set from --exe, so NO duplicate program-name arg -- see gc_run), and
## the optional
## --timeout (seconds -> ms).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
lib="${script_dir}/../dm-image-boot-tests/vbox-session.bsh"
[ -r "${lib}" ] || { printf 'ERROR: vbox-session.bsh not found: %s\n' "${lib}" >&2; exit 1; }

tmp="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap, not a direct call
cleanup() {
   safe-rm --recursive --force -- "${tmp}"
}
trap cleanup EXIT

## Stub VBoxManage: print its args joined by '|' (an empty arg -> '||'), so the
## full argv including the empty --password value is asserted exactly.
stub="${tmp}/vboxmanage-stub"
cat > "${stub}" <<'STUB'
#!/bin/bash
IFS='|'; printf '%s\n' "$*"
STUB
chmod +x "${stub}"

## Caller globals gc_run needs (consumed by the sourced vbox-session.bsh).
# shellcheck disable=SC2034
vm='testvm'
# shellcheck disable=SC2034
VBOXMANAGE="${stub}"
# shellcheck source=../dm-image-boot-tests/vbox-session.bsh
source "${lib}"

pass=0
fail=0
assert_eq() {
   local desc="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf 'PASS: %s\n' "${desc}"
      pass=$(( pass + 1 ))
   else
      printf 'FAIL: %s\n  got:  %s\n  want: %s\n' "${desc}" "${got}" "${want}" >&2
      fail=$(( fail + 1 ))
   fi
}

got_timed="$(gc_run user 'whoami' 60)"
assert_eq 'gc_run with timeout' "${got_timed}" \
   'guestcontrol|testvm|run|--username|user|--password||--timeout|60000|--wait-stdout|--wait-stderr|--exe|/bin/bash|--|-lc|whoami'

got_plain="$(gc_run sysmaint 'true')"
assert_eq 'gc_run without timeout' "${got_plain}" \
   'guestcontrol|testvm|run|--username|sysmaint|--password||--wait-stdout|--wait-stderr|--exe|/bin/bash|--|-lc|true'

## gc_account_for_role maps boot role -> the account that may authenticate in it.
assert_eq 'account for sysmaint' "$(gc_account_for_role sysmaint)" 'sysmaint'
assert_eq 'account for user'     "$(gc_account_for_role user)"     'user'
assert_eq 'account default'      "$(gc_account_for_role '')"       'user'

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0

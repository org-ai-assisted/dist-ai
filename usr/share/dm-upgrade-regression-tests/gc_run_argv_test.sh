#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## gc_run (vbox-session.bsh) is now a THIN wrapper over vbox-exec-local -- the single source
## of the guestcontrol argv. Assert gc_run delegates correctly (vm, --role=account, --cmd, the
## optional --timeout in SECONDS) with a capturing vbox-exec-local stub -- NO raw guestcontrol
## argv here (that lives in vbox-exec-local-test.sh, so the argv has exactly one test). Also
## cover gc_account_for_role. No VM.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
lib="${script_dir}/../dm-smbios-reader-boot-tests/vbox-session.bsh"
[ -r "${lib}" ] || { printf 'ERROR: vbox-session.bsh not found: %s\n' "${lib}" >&2; exit 1; }

tmp="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap, not a direct call
cleanup() {
   safe-rm --recursive --force -- "${tmp}"
}
trap cleanup EXIT

## Stub vbox-exec-local: print its args joined by '|', so gc_run's delegated invocation is
## asserted exactly (an empty arg would show as '||').
stub="${tmp}/vbox-exec-local-stub"
cat > "${stub}" <<'STUB'
#!/bin/bash
IFS='|'; printf '%s\n' "$*"
STUB
chmod +x "${stub}"

## Caller globals the sourced vbox-session.bsh consumes.
# shellcheck disable=SC2034
vm='testvm'
export VBOX_EXEC_LOCAL="${stub}"
# shellcheck source=../dm-smbios-reader-boot-tests/vbox-session.bsh
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
assert_eq 'gc_run delegates with timeout (SECONDS, not ms)' "${got_timed}" \
   'testvm|--role|user|--cmd|whoami|--timeout|60'

got_plain="$(gc_run sysmaint 'true')"
assert_eq 'gc_run delegates without timeout' "${got_plain}" \
   'testvm|--role|sysmaint|--cmd|true'

## gc_account_for_role maps boot role -> the account that may authenticate in it.
assert_eq 'account for sysmaint' "$(gc_account_for_role sysmaint)" 'sysmaint'
assert_eq 'account for user'     "$(gc_account_for_role user)"     'user'
assert_eq 'account default'      "$(gc_account_for_role '')"       'user'

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0

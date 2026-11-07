#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dm-whonix-pair's --interface contract and the CLI functional-lane wiring (#29):
##   - --interface defaults to gui (existing GUI battery preserved); gui|cli parse, an unknown
##     value is REJECTED (SETUP_RC).
##   - functional mode dispatches main_functional_cli when interface=cli, main_functional (GUI)
##     otherwise -- asserted BEHAVIORALLY by stubbing both drivers and calling main.
##   - the CLI executor runs over guestcontrol (gc_run), NOT the OCR run_check, and the CLI
##     driver routes-skips the GUI-login (6) and systemcheck (8) checks (which need a graphical
##     / logind user session) with a loud reason -- never a silent green.
## Sources the REAL script define-only (EOF guard); no VM, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
tool="${here}/../../bin/dm-whonix-pair"
[ -x "${tool}" ] || { printf '%s\n' "FAIL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
assert() {
   local label="$1"
   shift
   if "$@"; then
      pass=$(( pass + 1 )); printf '%s\n' "PASS: ${label}"
   else
      fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${label}"
   fi
}

## --- parse contract ---
assert "interface defaults to gui" test "${interface}" = 'gui'

interface='gui'
parse_args --interface cli
assert "--interface cli sets interface=cli" test "${interface}" = 'cli'

interface='cli'
parse_args --interface gui
assert "--interface gui sets interface=gui" test "${interface}" = 'gui'

## an unknown interface is REJECTED (SETUP_RC=2); die exits, so run in a subshell + capture rc.
iface_rc=0
( parse_args --interface bogus ) >/dev/null 2>&1 || iface_rc=$?
assert "--interface bogus rejected (SETUP_RC)" test "${iface_rc}" -eq 2

## --interface with NO value must fail SETUP_RC (2), not crash with a bare $2-unbound (exit 1).
noval_rc=0
( parse_args --interface ) >/dev/null 2>&1 || noval_rc=$?
assert "--interface with no value rejected (SETUP_RC)" test "${noval_rc}" -eq 2

## --- behavioral dispatch: stub both drivers, skip the VM lock re-exec, call main ---
export DM_VM_LOCK_HELD=1
DISPATCHED=''
# shellcheck disable=SC2317  ## called indirectly via main
main_functional() {
   DISPATCHED='gui'
   return 0
}
# shellcheck disable=SC2317  ## called indirectly via main
main_functional_cli() {
   DISPATCHED='cli'
   return 0
}

DISPATCHED=''
interface='gui'
main --mode functional --interface cli >/dev/null 2>&1 || true
assert "functional + interface=cli dispatches the CLI driver" test "${DISPATCHED}" = 'cli'

DISPATCHED=''
interface='gui'
main --mode functional >/dev/null 2>&1 || true
assert "functional default dispatches the GUI driver" test "${DISPATCHED}" = 'gui'

## --- source canaries: the CLI path runs over guestcontrol, not the OCR terminal ---
# shellcheck disable=SC2016  ## intentional literal match of the source text
assert "ws_func_cli_exec runs the check over gc_run (not run_check/OCR)" \
   grep --quiet --fixed-strings 'gc_run "$2" "$3" "$4"' "${tool}"
assert "main_functional_cli drives the battery with the CLI callbacks" \
   grep --quiet --fixed-strings 'run_release_check_battery ws_func_cli_exec ws_func_cli_reboot_sysmaint' "${tool}"
# shellcheck disable=SC2016  ## intentional literal match of the source text (no expansion)
assert "CLI reboot confirms power-off before restart (wait_vm_off guard)" \
   grep --quiet --fixed-strings 'wait_vm_off "${ws}" 20' "${tool}"
assert "CLI reboot reaches sysmaint via guestcontrol (headless, no OCR terminal)" \
   grep --quiet --fixed-strings 'wait_guestcontrol_ready sysmaint 300' "${tool}"
assert "CLI driver routes-skips the GUI-login check (6)" \
   grep --quiet --fixed-strings 'RELEASE_CHECK_SKIP_REASON[6]=' "${tool}"
assert "CLI driver routes-skips the systemcheck check (8)" \
   grep --quiet --fixed-strings 'RELEASE_CHECK_SKIP_REASON[8]=' "${tool}"

## --- a FAILED CLI check appends its in-guest output to --check-log (so dm-release-test can
##     publish the failure tail). Stub gc_run to fail with recognizable output. ---
cl="$(mktemp)"
# shellcheck disable=SC2317  ## called indirectly by ws_func_cli_exec
gc_run() {
   printf '%s\n' "boom-output-xyz"
   return 7
}
# shellcheck disable=SC2034  ## read by ws_func_cli_exec
check_log="${cl}"
clrc=0
ws_func_cli_exec 4 user 'failing-cmd' 60 >/dev/null 2>&1 || clrc=$?
assert "failed CLI check returns nonzero" test "${clrc}" -ne 0
assert "failed CLI check captures in-guest output to check_log" \
   grep --quiet --fixed-strings 'boom-output-xyz' "${cl}"
assert "failed CLI check records the check number + cmd" \
   grep --quiet --fixed-strings 'check 4 (failing-cmd) FAILED' "${cl}"
safe-rm --force -- "${cl}"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1

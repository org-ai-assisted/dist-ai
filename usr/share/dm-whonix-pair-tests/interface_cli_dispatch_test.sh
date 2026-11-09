#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dm-whonix-pair's --interface contract and the CLI functional-lane wiring (#29):
##   - --interface defaults to gui (existing GUI battery preserved); gui|cli parse, an unknown
##     value is REJECTED (SETUP_RC).
##   - functional mode dispatches main_functional_cli when interface=cli, main_functional (GUI)
##     otherwise -- asserted BEHAVIORALLY by stubbing both drivers and calling main.
##   - the CLI executor runs over guestcontrol (gc_run), NOT the OCR run_check; the CLI driver
##     routes-skips the GUI-login check (6, no compositor) in the guestcontrol battery, and runs
##     check 8 (systemcheck) via a REAL console login rather than skipping it -- never a silent green.
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
   grep --quiet --fixed-strings 'gc_run "${session}" "$3" "$4"' "${tool}"
assert "main_functional_cli drives the battery with the CLI callbacks" \
   grep --quiet --fixed-strings 'run_release_check_battery ws_func_cli_exec ws_func_cli_reboot_sysmaint' "${tool}"
# shellcheck disable=SC2016  ## intentional literal match of the source text (no expansion)
assert "CLI reboot confirms power-off before restart (wait_vm_off guard)" \
   grep --quiet --fixed-strings 'wait_vm_off "${ws}" 20' "${tool}"
assert "CLI reboot waits for the user guestcontrol channel after sysmaint boot (no sysmaint account)" \
   grep --quiet --fixed-strings 'wait_guestcontrol_ready user 300' "${tool}"
assert "CLI driver routes-skips the GUI-login check (6)" \
   grep --quiet --fixed-strings 'RELEASE_CHECK_SKIP_REASON[6]=' "${tool}"
assert "CLI driver routes-skips check 8 in the guestcontrol battery" \
   grep --quiet --fixed-strings 'RELEASE_CHECK_SKIP_REASON[8]=' "${tool}"
## ...but check 8 is RUN via a real console login, not left uncovered.
assert "main_functional_cli runs check 8 via a real console login" \
   grep --quiet --fixed-strings 'ws_cli_console_systemcheck' "${tool}"
# shellcheck disable=SC2016  ## intentional literal match of the source text (no expansion)
assert "console systemcheck runs the real systemcheck --cli --ci, captured to a FILE (no SIGPIPE)" \
   grep --quiet --fixed-strings 'systemcheck --cli --ci > ${log_file}' "${tool}"
assert "console systemcheck logs in via type-stdin (getty)" \
   grep --quiet --fixed-strings 'type-stdin' "${tool}"
## hardening canaries: verify the session account, use a per-run nonce, apply check 8's retries.
assert "console systemcheck verifies the session account (whoami)" \
   grep --quiet --fixed-strings 'whoami >' "${tool}"
assert "console systemcheck applies check 8's shared retry policy" \
   grep --quiet --fixed-strings 'RELEASE_CHECK_RETRIES[8]' "${tool}"
# shellcheck disable=SC2016  ## intentional literal match of the source text (no expansion)
assert "console systemcheck uses a per-run nonce in its result sinks" \
   grep --quiet --fixed-strings 'systemcheck-${nonce}' "${tool}"
## PER-ATTEMPT sink names (nonce carries the attempt index) so a timed-out prior attempt's late
## write cannot be read by a later attempt as a stale FAIL that masks a passing retry.
# shellcheck disable=SC2016  ## intentional literal match of the source text (no expansion)
assert "console systemcheck result sinks are per-attempt (nonce includes the attempt)" \
   grep --quiet --fixed-strings -- '-a${attempt}' "${tool}"
## restore_fresh verifies the RESTORED firmware (authoritative run-time state) so a stale EFI-baked
## snapshot cannot run under a mislabeled -bios result.
assert "restore_fresh verifies the restored firmware is the expected type" \
   grep --quiet --fixed-strings 'restored snapshot firmware' "${tool}"
## Before a (re)login the code interrupts a prior attempt's still-running systemcheck (Ctrl-C), so
## this attempt's keystrokes drive a fresh login + run instead of interleaving with a hung command.
assert "console systemcheck restores a known prompt before retry (Ctrl-C)" \
   grep --quiet --fixed-strings 'chord ctrl c' "${tool}"
## A failed check-8 read-back records a diagnostic (not a bare header) when the guest log is unreadable.
assert "console systemcheck notes an empty/unreadable check-8 log" \
   grep --quiet --fixed-strings 'empty or unreadable over guestcontrol' "${tool}"

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

## --- behavioral: drive ws_cli_console_systemcheck with a SIMULATED console (stub GUESTCTL +
##     gc_run) so this EXERCISES the command the code actually types, not just the source text. A
##     source-grep canary passes even if the live command pipes systemcheck into head (the SIGPIPE
##     regression); this does not. Checks the recorded verdict for a verbose PASS and a FAIL. ---
guestctl_stub="$(mktemp)"
cat > "${guestctl_stub}" <<'STUB'
#!/bin/bash
## record only the typed command text (type-stdin stdin); chord/shot are no-ops
[ "$2" = 'type-stdin' ] && cat >> "${GUESTCTL_RECORD}"
exit 0
STUB
chmod +x "${guestctl_stub}"
gc_rec="$(mktemp)"
export GUESTCTL="${guestctl_stub}" GUESTCTL_RECORD="${gc_rec}"
# shellcheck disable=SC2034  ## read as ${ws} inside the sourced function
ws='TESTVM'
# shellcheck disable=SC2034  ## read by the function (empty -> skip the check-log capture)
check_log=''
RELEASE_CHECK_RETRIES[8]=1
RELEASE_CHECK_RETRY_SLEEP[8]=0
## Simulated guest: whoami='user', rc-file present, rc=${SIM_RC}, a verbose log tail.
# shellcheck disable=SC2317  ## called indirectly by ws_cli_console_systemcheck
gc_run() {
   case "$2" in
      *'test -f'*)
         return 0
         ;;
      *'cat '*'.who'*)
         printf '%s\n' 'user'
         ;;
      *'cat '*'.rc'*)
         printf '%s\n' "${SIM_RC}"
         ;;
      *'head '*'.log'*)
         printf '%s\n' 'simulated verbose log tail'
         ;;
      *)
         return 0
         ;;
   esac
}
true > "${gc_rec}"
SIM_RC=0
ok_ret=0
ws_cli_console_systemcheck >/dev/null 2>&1 || ok_ret=$?
assert "console systemcheck returns 0 on a guest rc 0 (verbose pass, no false SIGPIPE 141)" \
   test "${ok_ret}" -eq 0
assert "console systemcheck TYPES a file-redirect command to the guest" \
   grep --quiet --fixed-strings 'systemcheck --cli --ci > ' "${gc_rec}"
sigpipe=0
grep --quiet --fixed-strings 'systemcheck --cli --ci 2>&1 | head' "${gc_rec}" && sigpipe=1
assert "console systemcheck does NOT pipe systemcheck into head (SIGPIPE regression)" \
   test "${sigpipe}" -eq 0
true > "${gc_rec}"
SIM_RC=1
bad_ret=0
( ws_cli_console_systemcheck ) >/dev/null 2>&1 || bad_ret=$?
assert "console systemcheck FAILS (nonzero exit) on a guest rc 1" test "${bad_ret}" -ne 0
safe-rm --force -- "${guestctl_stub}" "${gc_rec}"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1

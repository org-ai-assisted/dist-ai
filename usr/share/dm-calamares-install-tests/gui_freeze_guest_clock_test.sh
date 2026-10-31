#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins gui_freeze_guest_clock + guest_freeze_panel_snippet -- the in-guest GUEST panel-clock
## freeze in dm-calamares-install. The guest LXQt wall clock is the only tray element that
## changes run to run, so for a reproducible story frame the harness edits the guest user's
## ~/.config/lxqt/panel.conf (via the shared freeze-worldclock.awk pushed in) and RESTARTS
## lxqt-panel so the running session re-reads it.
##
## CRITICAL BEHAVIOUR GUARDED: the restart uses SIGKILL, not SIGTERM -- lxqt-session respawns a
## CRASHED module (renders) but NOT a cleanly-exited one, so a SIGTERM'd panel would stay dead and
## a frame would show NO panel (worse than a live clock; proven on a real Kicksecure LXQt session).
## The whole freeze is BEST-EFFORT: a hiccup (push/edit failure, or no respawn) WARNS and returns
## 0, never failing the install gate for a cosmetic frame enhancement.
##
## Drives the REAL functions (sourced define-only from the shipped script) with the guestcontrol
## boundaries stubbed: the vbox-exec-local push, gc_run and gc_wait_gui_started are recorded into
## one ordered log; the push rc, the edit rc, and gc_wait_gui_started's rc are scripted per-case to
## exercise the happy path and each best-effort warn path. No VM, no guest, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-calamares-install not found (set DM_CALAMARES_INSTALL)." >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

order="${work}/order"
export ORDER="${order}"

## vbox-exec-local stub: record the whole push argv so --role + the pushed awk are assertable.
## Honors PUSH_RC (exported per-case) so a failed push can be exercised.
# shellcheck disable=SC2016  ## the stub body expands ${ORDER}/${PUSH_RC} at ITS runtime, not here
printf '%s\n' '#!/bin/bash' 'printf "PUSH %s\n" "$*" >> "${ORDER}"' 'exit "${PUSH_RC:-0}"' > "${work}/vbox-exec-local"
chmod +x "${work}/vbox-exec-local"
export VBOX_EXEC_LOCAL="${work}/vbox-exec-local"

# shellcheck disable=SC1090
source "${subject}"

## Globals the function reads (consumed by the sourced function, not seen by shellcheck).
# shellcheck disable=SC2034
vm="testvm"

## gc_run stub: record role + snippet + timeout (no eval -- the awk EDIT behaviour is covered by
## freeze_worldclock_awk_test.sh; here we pin the control flow + the snippet SHAPE). The EDIT call
## (snippet names panel.conf) honors GCRUN_EDIT_RC so a failed edit can be exercised; the pkill
## restart call always succeeds.
# shellcheck disable=SC2317
gc_run() {
   printf '%s\n' "GCRUN role=$1 timeout=${3:-} snippet=$2" >> "${order}"
   case "$2" in
      *panel.conf*)
         return "${GCRUN_EDIT_RC:-0}"
         ;;
   esac
   return 0
}
## gc_wait_gui_started result is scripted per case: first call returns GC_WAIT_FIRST_RC, any later
## call returns GC_WAIT_REST_RC. WAIT_CALLS counts calls (a file, so it survives the function).
# shellcheck disable=SC2317
gc_wait_gui_started() {
   local calls
   calls="$(cat "${WAIT_CALLS}")"
   printf '%s' "$(( calls + 1 ))" > "${WAIT_CALLS}"
   printf '%s\n' "WAITSTART role=$1 pattern=$2 match=${4:-DEFAULT}" >> "${order}"
   if [ "${calls}" -eq 0 ]; then
      return "${GC_WAIT_FIRST_RC:-0}"
   fi
   return "${GC_WAIT_REST_RC:-0}"
}
# shellcheck disable=SC2317
gc_launch_gui() {
   printf '%s\n' "LAUNCHGUI role=$1 program=$2" >> "${order}"
   return 0
}

WAIT_CALLS="${work}/wait-calls"
export WAIT_CALLS

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
has() {
   case "$2" in
      *"$1"*)
         return 0
         ;;
      *)
         return 1
         ;;
   esac
}

## Reset per-case: ordered log + the gc_wait_gui_started call counter.
reset_case() {
   true > "${order}"
   printf '%s' 0 > "${WAIT_CALLS}"
}

## --- case 1: happy path (panel respawns) ----------------------------------------------------
reset_case
GC_WAIT_FIRST_RC=0 gui_freeze_guest_clock user
log="$(cat -- "${order}")"
push_line="$(grep -n '^PUSH ' -- "${order}" | head -1 | cut -d: -f1 || true)"
edit_line="$(grep -n 'snippet=.*panel.conf' -- "${order}" | head -1 | cut -d: -f1 || true)"

got=0
has 'PUSH testvm push --role user -- ' "${log}" || got=1
check "pushes the awk into the guest as --role user" "${got}"

got=0
has 'freeze-worldclock.awk' "${log}" || got=1
check "the pushed file is freeze-worldclock.awk (shared single source)" "${got}"

got=0
has "awk -v fmt='00:00' -v drop_volume=0 -f " "${log}" || got=1
check "the edit snippet runs the awk with drop_volume=0 (guest: freeze clock, keep tray)" "${got}"

got=0
## assert the LITERAL ${HOME} is present (it must expand in-guest, not here), so SC2016 is intended.
# shellcheck disable=SC2016
has 'panel="${HOME}/.config/lxqt/panel.conf"' "${log}" || got=1
check "the edit targets the guest account's ~/.config/lxqt/panel.conf" "${got}"

## SIGKILL, NOT SIGTERM: lxqt-session respawns a CRASHED module (renders), but treats a clean
## SIGTERM exit as intentional and leaves it dead -- a SIGTERM'd panel would vanish from the frame.
got=0
has 'snippet=pkill --signal KILL --exact lxqt-panel' "${log}" || got=1
check "the panel is restarted with SIGKILL so lxqt-session respawns + re-reads the frozen config" "${got}"

got=0
{ has 'signal TERM' "${log}" || has 'pkill -x lxqt-panel' "${log}"; } && got=1
check "the restart does NOT use SIGTERM (a cleanly-exited panel is not respawned)" "${got}"

got=0
{ [ -n "${push_line}" ] && [ -n "${edit_line}" ] && [ "${push_line}" -lt "${edit_line}" ]; } || got=1
check "the awk is pushed BEFORE the edit snippet runs" "${got}"

## The panel-respawn wait MUST ask for exact (-x) matching: this poll runs right after the
## SIGKILL, and a -f poll self-matches the invoking guest shell (its own command line carries
## 'lxqt-panel'), falsely reporting the panel up without a real respawn (pgrep self-match class).
got=0
has 'WAITSTART role=user pattern=lxqt-panel match=-x' "${log}" || got=1
check "the panel-respawn wait requests exact (-x) matching, not the default -f (self-match)" "${got}"
got=0
{ has 'match=-f' "${log}" || has 'match=DEFAULT' "${log}"; } && got=1
check "the panel wait does NOT use -f/default matching (would self-match)" "${got}"

## --- case 2: DM_STORY_CLOCK_TEXT override flows to fmt ---------------------------------------
reset_case
GC_WAIT_FIRST_RC=0 DM_STORY_CLOCK_TEXT='CI-SNAPSHOT' gui_freeze_guest_clock user
log="$(cat -- "${order}")"
got=0
has "awk -v fmt='CI-SNAPSHOT' -v drop_volume=0 -f " "${log}" || got=1
check "DM_STORY_CLOCK_TEXT overrides the frozen clock literal in the guest snippet" "${got}"

## --- case 2b: a single quote in DM_STORY_CLOCK_TEXT is ESCAPED for the guest shell ----------
## fmt embeds in a single-quoted guest-shell arg (fmt='...'); a benign "12 o'clock" would close
## the quote and corrupt (codex/grok injection finding). The snippet must POSIX-escape '->'\''.
reset_case
GC_WAIT_FIRST_RC=0 DM_STORY_CLOCK_TEXT="12 o'clock" gui_freeze_guest_clock user
log="$(cat -- "${order}")"
got=0
has "fmt='12 o'\\''clock'" "${log}" || got=1
check "a single quote in DM_STORY_CLOCK_TEXT is escaped ('->'\\'') in the guest snippet" "${got}"

## --- case 2c: a single quote in DM_GUEST_FREEZE_AWK_DEST is ESCAPED too ----------------------
reset_case
GC_WAIT_FIRST_RC=0 DM_GUEST_FREEZE_AWK_DEST="/var/tmp/x'y.awk" gui_freeze_guest_clock user
log="$(cat -- "${order}")"
got=0
has "-f '/var/tmp/x'\\''y.awk'" "${log}" || got=1
check "a single quote in DM_GUEST_FREEZE_AWK_DEST is escaped in the guest snippet" "${got}"

## --- case 3: account routing (sysmaint) -----------------------------------------------------
reset_case
GC_WAIT_FIRST_RC=0 gui_freeze_guest_clock sysmaint
log="$(cat -- "${order}")"
got=0
{ has 'PUSH testvm push --role sysmaint -- ' "${log}" \
  && has 'GCRUN role=sysmaint ' "${log}"; } || got=1
check "the account argument routes push + gc_run to that role (sysmaint)" "${got}"

## --- case 4: BEST-EFFORT -- panel does not respawn -> WARN, non-fatal, no manual relaunch -----
reset_case
rc=0
GC_WAIT_FIRST_RC=1 GC_WAIT_REST_RC=1 gui_freeze_guest_clock user 2>"${work}/err" || rc=$?
log="$(cat -- "${order}")"
got=0
[ "${rc}" -eq 0 ] || got=1
check "a panel that does not respawn is NON-FATAL (returns 0 -- a cosmetic freeze never fails the gate)" "${got}"
got=0
has 'did not respawn' "$(cat -- "${work}/err")" || got=1
check "a non-respawn is WARNED loudly on stderr" "${got}"
got=0
has 'LAUNCHGUI' "${log}" && got=1
check "no broken manual relaunch is attempted (lxqt-session owns the respawn)" "${got}"

## --- case 5: BEST-EFFORT -- awk push fails -> WARN, skip edit + restart, return 0 ------------
reset_case
rc=0
PUSH_RC=1 gui_freeze_guest_clock user 2>"${work}/err" || rc=$?
log="$(cat -- "${order}")"
got=0
{ [ "${rc}" -eq 0 ] && has 'awk push' "$(cat -- "${work}/err")"; } || got=1
check "a failed awk push is non-fatal + warned (frames just stay unfrozen)" "${got}"
got=0
has 'GCRUN' "${log}" && got=1
check "a failed push skips the edit + restart (no gc_run issued)" "${got}"

## --- case 6: BEST-EFFORT -- panel.conf edit fails -> WARN, skip restart, return 0 ------------
reset_case
rc=0
GCRUN_EDIT_RC=1 gui_freeze_guest_clock user 2>"${work}/err" || rc=$?
log="$(cat -- "${order}")"
got=0
{ [ "${rc}" -eq 0 ] && has 'panel.conf edit' "$(cat -- "${work}/err")"; } || got=1
check "a failed panel.conf edit is non-fatal + warned" "${got}"
got=0
has 'snippet=pkill' "${log}" && got=1
check "a failed edit skips the panel restart (no pkill issued)" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
exit 0

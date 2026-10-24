#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins the contract of dm-calamares-install's wait_ready resize-nudge fallback:
##   - the cooperative GA auto-resize is the normal path: if the desktop reaches full
##     resolution (>=1024 wide) on its own, NO setvideomodehint is issued and NO marker written;
##   - only if the desktop is STILL at the 800x600 framebuffer past the threshold is a ONE-SHOT
##     host setvideomodehint 1280x800 issued, and a RESIZE-NUDGE-USED marker recorded;
##   - the nudge is NOT a forced pass: if the guest never reaches full res even after the nudge,
##     wait_ready still FAILS (die) at the deadline;
##   - a guest that DOES honour the nudge then passes (models the resize actually working).
##
## Drives the REAL wait_ready (sourced define-only) with recording stubs. No VM, no root.

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
[ -n "${subject}" ] || { printf '%s\n' "FATAL: dm-calamares-install not found" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

vbox_log="${work}/vbox.calls"
res_mode="${work}/res-mode"
shots="${work}/shots"; mkdir -p -- "${shots}"
marker="${shots}/RESIZE-NUDGE-USED"

## GUESTCTL '<vm> res': prints a resolution per ${res_mode}. Mode 'nudge-fixes' returns the
## 800x600 framebuffer UNTIL the nudge marker appears, then full res -- modelling a guest that
## actually honours the host setvideomodehint.
guestctl_stub="${work}/guestctl"
cat > "${guestctl_stub}" <<STUB
#!/bin/bash
if [ "\${2:-}" = 'res' ]; then
   case "\$(cat '${res_mode}' 2>/dev/null)" in
      full)         printf '%s\n' '1280 800' ;;
      nudge-fixes)  if [ -e '${marker}' ]; then printf '%s\n' '1280 800'; else printf '%s\n' '800 600'; fi ;;
      *)            printf '%s\n' '800 600' ;;
   esac
fi
exit 0
STUB

## VBOXMANAGE: records argv (so the test can count the setvideomodehint nudge), and REJECTS the
## hint with exit 1 when ${work}/vbox-fail exists -- models a VM transiently locked / not running.
vbox_stub="${work}/vboxmanage"
cat > "${vbox_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> '${vbox_log}'
[ -e '${work}/vbox-fail' ] && exit 1
exit 0
STUB
chmod +x "${guestctl_stub}" "${vbox_stub}"

# shellcheck disable=SC1090
source "${subject}"

## Drive the real wait_ready with a no-op keypress + fast clock, and catch die instead of exiting.
died=0
# shellcheck disable=SC2317  ## called indirectly by the sourced wait_ready
gui_scan() { :; }
# shellcheck disable=SC2317  ## called indirectly by the sourced wait_ready
sleep() { command sleep 0.2; }
# shellcheck disable=SC2317  ## called indirectly by the sourced wait_ready
die() {
   died=1
   return 0
}

# shellcheck disable=SC2034
vm="testvm"
# shellcheck disable=SC2034
GUESTCTL="${guestctl_stub}"
# shellcheck disable=SC2034
VBOXMANAGE="${vbox_stub}"
# shellcheck disable=SC2034
shot_dir="${shots}"
## Short threshold + timeout so the test runs in seconds (nudge after 1s, give up at 3s).
export DM_CALAMARES_RESIZE_NUDGE_AFTER=1

pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
reset() { died=0; true > "${vbox_log}"; safe-rm --force -- "${marker}"; }
nudge_count() { grep -c 'setvideomodehint 1280 800' "${vbox_log}" 2>/dev/null || true; }

## --- auto-resize reaches full res: NO nudge, NO marker, returns 0 --------------------------
reset; printf '%s\n' full > "${res_mode}"
rc=0; wait_ready 3 || rc=1
check "auto-resize: wait_ready returns success" "${rc}"
got=0; [ "$(nudge_count)" -eq 0 ] || got=1
check "auto-resize: no setvideomodehint issued" "${got}"
got=0; [ ! -e "${marker}" ] || got=1
check "auto-resize: no RESIZE-NUDGE-USED marker" "${got}"
check "auto-resize: did not die" "${died}"

## --- stuck at 800x600 forever: nudge fires ONCE, marker written, STILL dies ----------------
reset; printf '%s\n' stuck > "${res_mode}"
rc=0; wait_ready 3 || rc=1
got=0; [ "$(nudge_count)" -ge 1 ] || got=1
check "stuck: a one-shot setvideomodehint nudge was issued" "${got}"
got=0; [ "$(nudge_count)" -eq 1 ] || got=1
check "stuck: the nudge fired exactly once (not every poll)" "${got}"
got=0; [ -s "${marker}" ] || got=1
check "stuck: RESIZE-NUDGE-USED marker written" "${got}"
check "stuck: wait_ready still FAILS (nudge is not a forced pass)" "$(( died == 1 ? 0 : 1 ))"

## --- guest honours the nudge: fire -> full res -> returns 0, marker recorded ---------------
reset; printf '%s\n' nudge-fixes > "${res_mode}"
rc=0; wait_ready 3 || rc=1
check "nudge-fixes: wait_ready returns success after the nudge" "${rc}"
got=0; [ "$(nudge_count)" -ge 1 ] || got=1
check "nudge-fixes: the nudge was issued" "${got}"
check "nudge-fixes: did not die" "${died}"
got=0; [ -s "${marker}" ] || got=1
check "nudge-fixes: RESIZE-NUDGE-USED marker records that a nudge was needed" "${got}"

## --- host REJECTS the hint: no false marker, RETRIED (one-shot not burned on failure), dies ---
reset; printf '%s\n' stuck > "${res_mode}"; true > "${work}/vbox-fail"
rc=0; wait_ready 3 || rc=1
got=0; [ "$(nudge_count)" -ge 2 ] || got=1
check "nudge-fail: a rejected nudge is RETRIED (not burned after one failure)" "${got}"
got=0; [ ! -e "${marker}" ] || got=1
check "nudge-fail: NO RESIZE-NUDGE-USED marker written for a failed nudge" "${got}"
check "nudge-fail: wait_ready still FAILS" "$(( died == 1 ? 0 : 1 ))"
safe-rm --force -- "${work}/vbox-fail"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0

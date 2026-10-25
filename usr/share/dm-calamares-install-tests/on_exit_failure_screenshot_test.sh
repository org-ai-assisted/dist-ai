#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-calamares-install's on_exit LAST-RESORT host-side screenshot.
##
## THE BUG IT GUARDS: a failure BEFORE any gui_wait_for ran (e.g. guestcontrol never came up
## because Secure Boot blocked the live Guest Additions modules) left NO ${HOME}/me-stuck.png,
## so on_exit published no screenshot and the results page showed a failure with zero frames.
## on_exit now grabs the host-side framebuffer (GUESTCTL shot -- the VBox IDisplay API, no guest
## additions needed) when no stuck frame exists yet, so EVERY failure publishes what was on
## screen. CANARY: pre-fix on_exit never took that shot, so no stuck.png was created and no
## 99-failure.png was published -- the assertions below fail.
##
## Drives the REAL on_exit (sourced define-only) with vm_started=true and stub GUESTCTL/VBOXMANAGE
## (no VM, no root, no network). keep_failed=false -> the teardown just powers off via the stub.

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

## Stub GUESTCTL: '<vm> shot <path>' writes a fake PNG to <path> and logs the call; any other
## subcommand is a harmless no-op. This is the host-side IDisplay capture, so it must succeed
## regardless of guest state -- exactly the property the fix relies on.
guestctl_stub="${work}/guestctl-stub"
guestctl_log="${work}/guestctl-calls"
cat > "${guestctl_stub}" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${GUESTCTL_LOG}"
if [ "${2:-}" = 'shot' ] && [ -n "${3:-}" ]; then
   printf '%s' 'PNGDATA' > "${3}"
fi
exit 0
STUB
chmod +x "${guestctl_stub}"

## Stub VBOXMANAGE: no-op success for the poweroff teardown.
vboxmanage_stub="${work}/vboxmanage-stub"
cat > "${vboxmanage_stub}" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x "${vboxmanage_stub}"

export GUESTCTL_LOG="${guestctl_log}"

# shellcheck disable=SC1090
source "${subject}"

## This pins on_exit's failure-screenshot publish, orthogonal to the window-vs-framebuffer capture
## mechanism (story_capture_test covers that dispatch). Drive the stubbable framebuffer path so
## capture_frame uses the GUESTCTL shot stub, not a real grim/compositor.
# shellcheck disable=SC2034
story_capture="framebuffer"

## Globals on_exit reads.
# shellcheck disable=SC2034
HOME="${work}"
check_log="${work}/checklog"
shot="${work}/firstboot.png"
shot_dir="${work}/shots"
mkdir -p -- "${shot_dir}"
# shellcheck disable=SC2034
vm="testvm"
# shellcheck disable=SC2034
live_account="user"
# shellcheck disable=SC2034
vm_started="true"
# shellcheck disable=SC2034
keep_failed="false"
# shellcheck disable=SC2034
GUESTCTL="${guestctl_stub}"
# shellcheck disable=SC2034
VBOXMANAGE="${vboxmanage_stub}"
# shellcheck disable=SC2034
die_reason="guestcontrol (VBoxService) never came up in the live session"

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi
}
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## No pre-existing stuck frame, no success shot: the failure is BEFORE any milestone capture.
true > "${check_log}"
rc=0
( bash -c 'exit 5' || on_exit ) >/dev/null 2>&1 || rc=$?

got=0; [ "${rc}" -eq 5 ] || got=1
check "on_exit preserves the exit status" "${got}"

## CANARY: the host-side shot was actually taken (pre-fix: never called -> log has no 'shot').
got=0; has 'shot' "$(cat -- "${guestctl_log}" 2>/dev/null)" || got=1
check "on_exit grabs a host-side framebuffer shot when no stuck frame exists" "${got}"

got=0; [ -s "${shot_dir}/99-failure.png" ] || got=1
check "the failure frame is published as 99-failure.png" "${got}"

got=0; [ -s "${shot}" ] || got=1
check "the --shot path receives the failure frame" "${got}"

got=0; has 'see the published screenshot' "$(cat -- "${check_log}")" || got=1
check "the check log points at the published screenshot" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0

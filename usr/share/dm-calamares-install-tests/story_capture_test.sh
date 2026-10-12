#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins the contract of the "full story" capture primitives in dm-calamares-install:
##   story_snap NN name   -- host-side framebuffer frame (GUESTCTL shot), NO quiesce, into
##                           ${shot_dir}/NN-name.png. For boot/firmware/LUKS/transient screens.
##   story_card NN name T  -- a rendered state card (VBoxManage showvminfo -> dm-text-to-png) at
##                           ${shot_dir}/NN-name.png, for points with no framebuffer.
## Both are best-effort: no ${shot_dir} -> no-op; a capture/render failure never fails the run.
##
## Drives the REAL functions (sourced define-only) with recording stubs. No VM, no root.

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

guestctl_log="${work}/guestctl.calls"
vbox_log="${work}/vbox.calls"
text_log="${work}/text.calls"

## GUESTCTL: '<vm> shot <path>' writes a fake PNG; records the call.
guestctl_stub="${work}/guestctl"
cat > "${guestctl_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> '${guestctl_log}'
if [ "\${2:-}" = 'shot' ] && [ -n "\${3:-}" ]; then printf PNG > "\${3}"; fi
exit 0
STUB

## VBOXMANAGE: 'showvminfo ... --machinereadable' returns fake machine-readable state; records.
vbox_stub="${work}/vboxmanage"
cat > "${vbox_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> '${vbox_log}'
case "\$*" in
   *showvminfo*machinereadable*) printf '%s\n' 'VMState="poweroff"' 'firmware="EFI"' 'memory=4096' ;;
esac
exit 0
STUB

## Stub standing in for the card renderer: emit a PNG at its OUTFILE so story_card's output
## check is satisfied, and record argv so the test can assert the card path was passed.
text_stub="${work}/dm-text-to-png"
cat > "${text_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> '${text_log}'
cat >/dev/null
[ -n "\${1:-}" ] && printf PNG > "\${1}"
exit 0
STUB
chmod +x "${guestctl_stub}" "${vbox_stub}" "${text_stub}"

# shellcheck disable=SC1090
source "${subject}"

# shellcheck disable=SC2034
vm="testvm"
# shellcheck disable=SC2034
GUESTCTL="${guestctl_stub}"
# shellcheck disable=SC2034
VBOXMANAGE="${vbox_stub}"
# shellcheck disable=SC2034
DM_TEXT_TO_PNG="${text_stub}"

pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## --- story_snap with a shot_dir: host-side frame, correct filename, NO quiesce --------------
# shellcheck disable=SC2034
shot_dir="${work}/shots"; mkdir -p -- "${shot_dir}"
true > "${guestctl_log}"
story_snap 20 live-grub-menu
got=0; [ -s "${shot_dir}/20-live-grub-menu.png" ] || got=1
check "story_snap writes shot_dir/NN-name.png" "${got}"
got=0; has 'testvm shot' "$(cat -- "${guestctl_log}")" || got=1
check "story_snap captures host-side via GUESTCTL shot" "${got}"
## No quiesce: story_snap must NOT invoke a gc_run pkill (that is snap()'s job; the quiesce
## round-trip would miss a transient boot screen). The only GUESTCTL call is the shot.
got=0; [ "$(grep -c . "${guestctl_log}")" -eq 1 ] || got=1
check "story_snap does a single GUESTCTL call (no quiesce round-trip)" "${got}"

## --- story_card: renders a state card from showvminfo via dm-text-to-png ---------------------
true > "${vbox_log}"; true > "${text_log}"
story_card 10 vm-defined "VM defined (pre-boot)"
got=0; [ -s "${shot_dir}/10-vm-defined.png" ] || got=1
check "story_card writes shot_dir/NN-name.png" "${got}"
got=0; has 'showvminfo' "$(cat -- "${vbox_log}")" && has 'machinereadable' "$(cat -- "${vbox_log}")" || got=1
check "story_card reads VBoxManage showvminfo --machinereadable" "${got}"
got=0; has "${shot_dir}/10-vm-defined.png" "$(cat -- "${text_log}")" || got=1
check "story_card renders the card via dm-text-to-png" "${got}"

## --- best-effort: no shot_dir -> both are silent no-ops -------------------------------------
# shellcheck disable=SC2034
shot_dir=""
true > "${guestctl_log}"; true > "${text_log}"
story_snap 99 nowhere
story_card 99 nowhere "x"
got=0; [ ! -s "${guestctl_log}" ] && [ ! -s "${text_log}" ] || got=1
check "no shot_dir -> story_snap/story_card are no-ops" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0

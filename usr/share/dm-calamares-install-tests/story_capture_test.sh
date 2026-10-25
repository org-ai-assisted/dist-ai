#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins the contract of the "full story" capture primitives in dm-calamares-install:
##   capture_frame PATH   -- window mode (default, operator "maximum faithful"): a grim grab of the
##                           compositor (full VBox VM window); framebuffer mode: a bare-guest grab
##                           via GUESTCTL shot. The one seam every milestone capture goes through.
##   start_vm_frontend    -- window mode: a maximized VirtualBoxVM --startvm GUI window; framebuffer
##                           mode: the legacy `VBoxManage startvm --type headless`.
##   story_snap NN name   -- a capture_frame into ${shot_dir}/NN-name.png, NO quiesce.
##   story_card NN name T -- a rendered state card (showvminfo -> dm-text-to-png), no framebuffer.
##   cb_gui_ns_reexec     -- coreboot+window only: re-exec into a mount namespace (no-op otherwise).
##   gui_compositor_stop  -- restore the global GUI/SuppressMessages the GUI capture overrode.
## Capture/card are best-effort: no ${shot_dir} -> no-op; a failure never fails the run.
##
## Drives the REAL functions (sourced define-only) with recording stubs. No VM, no root, no labwc.

## vm/shot_dir/coreboot_rom/gui_* are READ by the sourced subject, assigned here to seed it;
## shellcheck cannot see across the source. File-wide (before the first command).
# shellcheck disable=SC2034

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
grim_log="${work}/grim.calls"
frontend_log="${work}/frontend.calls"

## GUESTCTL: '<vm> shot <path>' writes a fake PNG; records the call.
guestctl_stub="${work}/guestctl"
cat > "${guestctl_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> '${guestctl_log}'
if [ "\${2:-}" = 'shot' ] && [ -n "\${3:-}" ]; then printf PNG > "\${3}"; fi
exit 0
STUB

## VBOXMANAGE: showvminfo returns fake machine-readable state incl. a UUID (gui_vm_launch parses
## it); getextradata returns a canned SuppressMessages value; everything records argv.
vbox_stub="${work}/vboxmanage"
cat > "${vbox_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> '${vbox_log}'
case "\$*" in
   *showvminfo*machinereadable*)
      printf '%s\n' 'UUID="5bfdfe22-933f-4875-a6a9-2b9ec88104c5"' 'VMState="poweroff"' 'firmware="EFI"' 'memory=4096'
      ;;
   *"getextradata global GUI/SuppressMessages"*)
      printf '%s\n' 'Value: oldsup'
      ;;
esac
exit 0
STUB

## Card renderer stub: emit a PNG at its OUTFILE and record argv.
text_stub="${work}/dm-text-to-png"
cat > "${text_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> '${text_log}'
cat >/dev/null
[ -n "\${1:-}" ] && printf PNG > "\${1}"
exit 0
STUB

## grim stub: write a fake PNG at its last arg (the OUTFILE) and record the call.
grim_stub="${work}/grim"
cat > "${grim_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> '${grim_log}'
for a in "\$@"; do out="\$a"; done
[ -n "\${out:-}" ] && printf PNG > "\${out}"
exit 0
STUB

## VirtualBoxVM frontend stub: record argv; the window frontend is launched in the background.
frontend_stub="${work}/VirtualBoxVM"
cat > "${frontend_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> '${frontend_log}'
exit 0
STUB
chmod +x "${guestctl_stub}" "${vbox_stub}" "${text_stub}" "${grim_stub}" "${frontend_stub}"

## grim is resolved from PATH (capture_frame calls it bare); front-load the stub dir.
PATH="${work}:${PATH}"

# shellcheck disable=SC1090
source "${subject}"

vm="testvm"
GUESTCTL="${guestctl_stub}"
VBOXMANAGE="${vbox_stub}"
DM_TEXT_TO_PNG="${text_stub}"
VBOX_VM_BIN="${frontend_stub}"

pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

shot_dir="${work}/shots"; mkdir -p -- "${shot_dir}"

## --- capture_frame dispatch: window -> grim, framebuffer -> GUESTCTL shot --------------------
story_capture="window"
true > "${grim_log}"; true > "${guestctl_log}"
capture_frame "${shot_dir}/cf-window.png"
got=0; [ -s "${shot_dir}/cf-window.png" ] && has "${shot_dir}/cf-window.png" "$(cat -- "${grim_log}")" || got=1
check "capture_frame window mode grabs via grim" "${got}"
got=0; [ ! -s "${guestctl_log}" ] || got=1
check "capture_frame window mode does NOT touch GUESTCTL" "${got}"

story_capture="framebuffer"
true > "${grim_log}"; true > "${guestctl_log}"
capture_frame "${shot_dir}/cf-fb.png"
got=0; [ -s "${shot_dir}/cf-fb.png" ] && has 'testvm shot' "$(cat -- "${guestctl_log}")" || got=1
check "capture_frame framebuffer mode grabs via GUESTCTL shot" "${got}"
got=0; [ ! -s "${grim_log}" ] || got=1
check "capture_frame framebuffer mode does NOT invoke grim" "${got}"

## --- story_snap: capture_frame into shot_dir/NN-name.png, NO quiesce (window default) --------
story_capture="window"
true > "${grim_log}"; true > "${guestctl_log}"
story_snap 20 live-grub-menu
got=0; [ -s "${shot_dir}/20-live-grub-menu.png" ] || got=1
check "story_snap writes shot_dir/NN-name.png (window/grim)" "${got}"
## No quiesce: story_snap must do exactly ONE grim grab, no GUESTCTL round-trip (that is snap()'s).
got=0; [ "$(grep -c . "${grim_log}")" -eq 1 ] && [ ! -s "${guestctl_log}" ] || got=1
check "story_snap is a single grab with no quiesce round-trip" "${got}"

## --- start_vm_frontend dispatch -------------------------------------------------------------
story_capture="window"
true > "${frontend_log}"; true > "${vbox_log}"; gui_vm_pid=""
start_vm_frontend
[ -z "${gui_vm_pid}" ] || wait "${gui_vm_pid}" 2>/dev/null || true
got=0; has '--startvm 5bfdfe22-933f-4875-a6a9-2b9ec88104c5' "$(cat -- "${frontend_log}")" || got=1
check "start_vm_frontend window mode launches VirtualBoxVM --startvm <uuid>" "${got}"
got=0; has 'startvm testvm --type headless' "$(cat -- "${vbox_log}")" && got=1
check "start_vm_frontend window mode does NOT use the headless startvm" "${got}"

story_capture="framebuffer"
true > "${frontend_log}"; true > "${vbox_log}"
start_vm_frontend
got=0; has 'startvm testvm --type headless' "$(cat -- "${vbox_log}")" || got=1
check "start_vm_frontend framebuffer mode uses VBoxManage startvm --type headless" "${got}"
got=0; [ ! -s "${frontend_log}" ] || got=1
check "start_vm_frontend framebuffer mode does NOT launch a GUI window" "${got}"

## --- cb_gui_ns_reexec guard: a NO-OP unless window + coreboot --------------------------------
## (window without a coreboot rom, and framebuffer, must return 0 without re-exec'ing. A real
## re-exec would replace this process, so a return proves the guard held.)
story_capture="window"; coreboot_rom=""
cb_gui_ns_reexec; rc=$?
check "cb_gui_ns_reexec is a no-op for a stock (non-coreboot) window lane" "$(( rc == 0 ? 0 : 1 ))"
story_capture="framebuffer"; coreboot_rom="/some/rom"
cb_gui_ns_reexec; rc=$?
check "cb_gui_ns_reexec is a no-op in framebuffer mode" "$(( rc == 0 ? 0 : 1 ))"

## --- gui_compositor_stop: restore the overridden global GUI/SuppressMessages -----------------
## was-set -> restored to the saved value; absent -> deleted (setextradata with no value).
story_capture="window"; gui_vm_pid=""; gui_labwc_pid=""; gui_xdg_dir=""; gui_cfg_dir=""
true > "${vbox_log}"
gui_supmsg_was_set="yes"; gui_supmsg_saved="oldsup"
gui_compositor_stop
got=0; has 'setextradata global GUI/SuppressMessages oldsup' "$(cat -- "${vbox_log}")" || got=1
check "gui_compositor_stop restores a previously-set SuppressMessages" "${got}"
true > "${vbox_log}"
gui_supmsg_was_set="no"; gui_supmsg_saved=""
gui_compositor_stop
got=0; has 'setextradata global GUI/SuppressMessages' "$(cat -- "${vbox_log}")" || got=1
check "gui_compositor_stop deletes SuppressMessages when it was absent" "${got}"
## framebuffer mode: gui_compositor_stop is a no-op (nothing was overridden).
story_capture="framebuffer"
true > "${vbox_log}"
gui_compositor_stop
got=0; [ ! -s "${vbox_log}" ] || got=1
check "gui_compositor_stop is a no-op in framebuffer mode" "${got}"

## --- story_card: renders a state card from showvminfo via dm-text-to-png ---------------------
true > "${vbox_log}"; true > "${text_log}"
story_card 10 vm-defined "VM defined (pre-boot)"
got=0; [ -s "${shot_dir}/10-vm-defined.png" ] || got=1
check "story_card writes shot_dir/NN-name.png" "${got}"
got=0; has 'showvminfo' "$(cat -- "${vbox_log}")" && has 'machinereadable' "$(cat -- "${vbox_log}")" || got=1
check "story_card reads VBoxManage showvminfo --machinereadable" "${got}"
got=0; has "${shot_dir}/10-vm-defined.png" "$(cat -- "${text_log}")" || got=1
check "story_card renders the card via dm-text-to-png" "${got}"

## --- best-effort: no shot_dir -> capture/card are silent no-ops ------------------------------
shot_dir=""
story_capture="window"
true > "${grim_log}"; true > "${guestctl_log}"; true > "${text_log}"
story_snap 99 nowhere
story_card 99 nowhere "x"
got=0; [ ! -s "${grim_log}" ] && [ ! -s "${guestctl_log}" ] && [ ! -s "${text_log}" ] || got=1
check "no shot_dir -> story_snap/story_card are no-ops" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0

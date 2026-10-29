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
##   story_card NN name T -- a state card emitted as TEXT (showvminfo -> NN-name.card.txt), no image.
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
      printf '%s\n' 'UUID="5bfdfe22-933f-4875-a6a9-2b9ec88104c5"' "VMState=\"\${STUB_VMSTATE:-running}\"" 'firmware="EFI"' 'memory=4096'
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

## image-blank-check stub: record argv (so a test can assert --uniform-only vs rich) and pass (0 =
## content present / not degenerate), so story_snap_nonblank returns on its first poll.
ibc_log="${work}/ibc.calls"
ibc_stub="${work}/image-blank-check"
cat > "${ibc_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> '${ibc_log}'
exit 0
STUB
chmod +x "${guestctl_stub}" "${vbox_stub}" "${text_stub}" "${grim_stub}" "${frontend_stub}" "${ibc_stub}"

## grim is resolved from PATH (capture_frame calls it bare); front-load the stub dir.
PATH="${work}:${PATH}"

# shellcheck disable=SC1090
source "${subject}"

vm="testvm"
GUESTCTL="${guestctl_stub}"
VBOXMANAGE="${vbox_stub}"
DM_TEXT_TO_PNG="${text_stub}"
VBOX_VM_BIN="${frontend_stub}"
IMAGE_BLANK_CHECK="${ibc_stub}"

pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

shot_dir="${work}/shots"; mkdir -p -- "${shot_dir}"

## --- capture_frame dispatch: window -> grim, framebuffer -> GUESTCTL shot --------------------
story_capture="window"
true > "${grim_log}"; true > "${guestctl_log}"
capture_frame "${shot_dir}/cf-window.png"
got=0; [ -s "${shot_dir}/cf-window.png" ] && has "${shot_dir}/cf-window.png" "$(cat -- "${grim_log}")" || got=1
check "capture_frame window mode publishes the full window via grim" "${got}"
## window mode ALSO writes a bare-guest gate sibling in .gate/ via GUESTCTL -- honest blank-gate
## input (the published window grab's chrome would defeat image-blank-check).
got=0; [ -s "${shot_dir}/.gate/cf-window.png" ] && has "${shot_dir}/.gate/cf-window.png" "$(cat -- "${guestctl_log}")" || got=1
check "capture_frame window mode writes a bare-guest gate sibling via GUESTCTL" "${got}"
## gate_check_path points the gates at the guest sibling in window mode, the published frame in fb.
got=0; [ "$(gate_check_path "${shot_dir}/cf-window.png")" = "${shot_dir}/.gate/cf-window.png" ] || got=1
check "gate_check_path returns the guest sibling in window mode" "${got}"
## leak guard: a window capture OUTSIDE shot_dir (the failure stuck shot / --shot) writes NO gate
## sibling -- it is never gated, and a ${HOME}/.gate would leak uncleaned by on_exit.
true > "${guestctl_log}"
capture_frame "${work}/outside-stuck.png"
got=0; { [ -s "${work}/outside-stuck.png" ] && [ ! -e "${work}/.gate" ] && [ ! -s "${guestctl_log}" ]; } || got=1
check "capture_frame window mode writes NO gate sibling outside shot_dir" "${got}"

story_capture="framebuffer"
true > "${grim_log}"; true > "${guestctl_log}"
capture_frame "${shot_dir}/cf-fb.png"
got=0; [ -s "${shot_dir}/cf-fb.png" ] && has 'testvm shot' "$(cat -- "${guestctl_log}")" || got=1
check "capture_frame framebuffer mode grabs via GUESTCTL shot" "${got}"
got=0; [ ! -s "${grim_log}" ] || got=1
check "capture_frame framebuffer mode does NOT invoke grim" "${got}"
got=0; [ "$(gate_check_path "${shot_dir}/cf-fb.png")" = "${shot_dir}/cf-fb.png" ] || got=1
check "gate_check_path returns the published frame in framebuffer mode" "${got}"

## --- story_snap: capture_frame into shot_dir/NN-name.png, NO quiesce (window default) --------
story_capture="window"
true > "${grim_log}"; true > "${guestctl_log}"
story_snap 20 live-grub-menu
got=0; [ -s "${shot_dir}/20-live-grub-menu.png" ] || got=1
check "story_snap writes the published shot_dir/NN-name.png (window/grim)" "${got}"
got=0; [ -s "${shot_dir}/.gate/20-live-grub-menu.png" ] || got=1
check "story_snap writes the bare-guest gate sibling" "${got}"
## No quiesce: one grim grab + the gate shot, but NONE of snap()'s move/key wake round-trip.
got=0; { [ "$(grep -c . "${grim_log}")" -eq 1 ] && ! grep --quiet --extended-regexp 'move|key' "${guestctl_log}"; } || got=1
check "story_snap does one grab + gate shot, no quiesce move/key" "${got}"

## --- story_snap_nonblank rich: poll with the near-blank (rich) check + a DPMS Shift tap --------
story_capture="window"
true > "${grim_log}"; true > "${guestctl_log}"; true > "${ibc_log}"
story_snap_nonblank 73 vt-graphical-restored 5 1 rich
got=0; [ -s "${shot_dir}/73-vt-graphical-restored.png" ] || got=1
check "story_snap_nonblank rich writes the published milestone" "${got}"
got=0; has 'testvm key 2a aa' "$(cat -- "${guestctl_log}")" || got=1
check "story_snap_nonblank rich taps Shift to wake a DPMS-blanked panel" "${got}"
## rich uses image-blank-check's near-blank mode (NO --uniform-only), matching main's rich gate.
got=0; ! grep --quiet -- '--uniform-only' "${ibc_log}" || got=1
check "story_snap_nonblank rich checks near-blank (no --uniform-only)" "${got}"
## control: the DEFAULT (uniform) mode passes --uniform-only and does NOT tap Shift.
true > "${ibc_log}"; true > "${guestctl_log}"
story_snap_nonblank 11 firmware-logo 5 1
got=0; grep --quiet -- '--uniform-only' "${ibc_log}" || got=1
check "story_snap_nonblank default mode checks uniform-only" "${got}"
got=0; ! grep --quiet --extended-regexp 'key 2a aa' "${guestctl_log}" || got=1
check "story_snap_nonblank default mode does NOT tap Shift" "${got}"

## --- story_snap_nonblank capture-mode override ($7) -------------------------------------------
## $7='framebuffer' publishes the GUEST framebuffer (GUESTCTL shot) instead of grim's window grab,
## even though the run is in window mode -- the VBox EFI splash renders in the guest, which grim
## lags. Window mode (above, line "default mode") grim-grabs; the override flips it to GUESTCTL.
story_capture="window"
## Clear the stale 11-firmware-logo.png (+ gate sibling) from the window-mode "default mode" case
## above (SAME NN+name) -- else the non-blank [ -s ] assertion could pass on that stale frame, not
## this capture.
# shellcheck disable=SC2154  ## gate_subdir is set by the sourced subject (dm-calamares-install)
safe-rm --force -- "${shot_dir}/11-firmware-logo.png" "${shot_dir}/${gate_subdir}/11-firmware-logo.png" 2>/dev/null || true
true > "${grim_log}"; true > "${guestctl_log}"
fb_rc=0
story_snap_nonblank 11 firmware-logo 1 1 content '' framebuffer || fb_rc=$?
## Assert ALL of: returned success, captured via GUESTCTL (not grim), AND wrote a non-blank frame.
## Grepping the log alone could pass even if the capture then timed out / produced no frame.
got=0
if ! { [ "${fb_rc}" -eq 0 ] && has 'testvm shot' "$(cat -- "${guestctl_log}")" \
      && [ -s "${shot_dir}/11-firmware-logo.png" ]; }; then got=1; fi
check "story_snap_nonblank framebuffer override captures the GUEST (GUESTCTL shot, rc 0, non-blank)" "${got}"
got=0; ! grep --quiet 'firmware-logo' "${grim_log}" || got=1
check "story_snap_nonblank framebuffer override does NOT grim-grab the window" "${got}"

## --- story_snap_nonblank TIMEOUT discard is OPT-IN ($6) ---------------------------------------
## A frame that never passes the check (ibc always degenerate) times out. With the discard opt-in,
## the leftover frame + its gate sibling are REMOVED (a lenient cleanup cannot then publish a missed
## firmware splash as evidence). WITHOUT the opt-in, the frame is KEPT -- a milestone whose presence
## is later REQUIRED (vt-graphical-restored -> require_vt_captures) must not vanish on a slow render.
fail_ibc="${work}/ibc-fail"
cat > "${fail_ibc}" <<'STUB'
#!/bin/bash
exit 1
STUB
chmod +x -- "${fail_ibc}"
# shellcheck disable=SC2154  ## gate_subdir is set by the sourced subject (dm-calamares-install)
gate_sibling="${shot_dir}/${gate_subdir}/11-firmware-logo.png"
## Opt-in discard: frame + gate sibling removed on timeout.
true > "${grim_log}"; true > "${guestctl_log}"
rc=0
IMAGE_BLANK_CHECK="${fail_ibc}" story_snap_nonblank 11 firmware-logo 1 1 content discard || rc=$?
got=0; [ "${rc}" -ne 0 ] || got=1
check "story_snap_nonblank content timeout returns non-zero" "${got}"
got=0; [ -e "${shot_dir}/11-firmware-logo.png" ] && got=1
check "story_snap_nonblank timeout with opt-in DISCARDS the degenerate frame" "${got}"
got=0; [ -e "${gate_sibling}" ] && got=1
check "story_snap_nonblank timeout with opt-in DISCARDS the gate sibling too" "${got}"
## Default (no opt-in): the frame is KEPT (non-vacuous -- proves $6 gates the discard, and that the
## required-capture lanes are unaffected).
true > "${grim_log}"; true > "${guestctl_log}"
IMAGE_BLANK_CHECK="${fail_ibc}" story_snap_nonblank 11 firmware-logo 1 1 content || true
got=0; [ -e "${shot_dir}/11-firmware-logo.png" ] || got=1
check "story_snap_nonblank timeout WITHOUT opt-in KEEPS the frame" "${got}"

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

## Finding 2 regression: window-mode start FAILS FAST (exit FAIL_RC) when the VM never reaches
## 'running' (STUB_VMSTATE=poweroff, the frontend stub exits) -- not a misleading downstream
## "GRUB menu not detected" ~40s later. FAILS on pre-fix fire-and-forget code (it returned 0).
story_capture="window"; gui_vm_pid=""
export STUB_VMSTATE="poweroff" DM_GUI_READY_TIMEOUT="2"
rc=0
( start_vm_frontend ) >/dev/null 2>&1 || rc=$?
unset STUB_VMSTATE DM_GUI_READY_TIMEOUT
# shellcheck disable=SC2154  ## FAIL_RC is set by the sourced subject (dm-calamares-install)
check "start_vm_frontend window mode dies fast when the VM never reaches running" "$(( rc == FAIL_RC ? 0 : 1 ))"

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
story_capture="window"; vm_kept=""; gui_vm_pid=""; gui_labwc_pid=""; gui_xdg_dir=""; gui_cfg_dir=""
true > "${vbox_log}"
gui_supmsg_was_set="yes"; gui_supmsg_saved="oldsup"
gui_compositor_stop
got=0; has 'setextradata global GUI/SuppressMessages oldsup' "$(cat -- "${vbox_log}")" || got=1
check "gui_compositor_stop restores a previously-set SuppressMessages" "${got}"
true > "${vbox_log}"
gui_supmsg_was_set="no"; gui_supmsg_saved=""
gui_compositor_stop
## EXACT line, not a substring: a set-with-value ('... SuppressMessages oldsup') also CONTAINS the
## bare string, so a substring check would miss a failure-to-delete. Delete records it with no value.
got=0; grep --quiet --line-regexp 'setextradata global GUI/SuppressMessages' "${vbox_log}" || got=1
check "gui_compositor_stop deletes SuppressMessages when it was absent (exact, no value)" "${got}"
## framebuffer mode: gui_compositor_stop is a no-op (nothing was overridden).
story_capture="framebuffer"
true > "${vbox_log}"
gui_compositor_stop
got=0; [ ! -s "${vbox_log}" ] || got=1
check "gui_compositor_stop is a no-op in framebuffer mode" "${got}"

## --- vm_kept: a KEPT --keep-failed VM must NOT have its in-process window frontend killed -----
## (killing VirtualBoxVM would abort the very VM being kept for inspection). Stand in for the
## frontend with a real sleep; vm_kept=true leaves it alive, vm_kept unset kills it.
story_capture="window"; gui_labwc_pid=""; gui_xdg_dir=""; gui_cfg_dir=""
gui_supmsg_was_set="no"; gui_supmsg_saved=""
vm_kept="true"
sleep 30 & keep_pid=$!
gui_vm_pid="${keep_pid}"
gui_compositor_stop
got=0; kill -0 "${keep_pid}" 2>/dev/null || got=1
check "gui_compositor_stop leaves the frontend ALIVE when vm_kept=true" "${got}"
kill "${keep_pid}" 2>/dev/null || true; wait "${keep_pid}" 2>/dev/null || true
vm_kept=""
sleep 30 & kill_pid=$!
gui_vm_pid="${kill_pid}"
gui_compositor_stop
wait "${kill_pid}" 2>/dev/null || true
got=0; kill -0 "${kill_pid}" 2>/dev/null && got=1
check "gui_compositor_stop KILLS the frontend when vm_kept is unset" "${got}"

## --- story_card: emits a state card as TEXT (showvminfo -> NN-name.card.txt), NO image --------
## The synthetic cards publish their text directly: no PNG, no dm-text-to-png round-trip (the page
## renders a text panel). Canary: the pre-refinement card wrote a dm-text-to-png PNG.
true > "${vbox_log}"; true > "${text_log}"
story_card 10 vm-defined "VM defined (pre-boot)"
got=0; [ -s "${shot_dir}/10-vm-defined.card.txt" ] || got=1
check "story_card writes shot_dir/NN-name.card.txt (text, not an image)" "${got}"
got=0; [ ! -e "${shot_dir}/10-vm-defined.png" ] || got=1
check "story_card writes NO PNG" "${got}"
got=0; has 'showvminfo' "$(cat -- "${vbox_log}")" && has 'machinereadable' "$(cat -- "${vbox_log}")" || got=1
check "story_card reads VBoxManage showvminfo --machinereadable" "${got}"
got=0; [ ! -s "${text_log}" ] || got=1
check "story_card does NOT call dm-text-to-png" "${got}"
got=0; has 'VM defined (pre-boot)' "$(cat -- "${shot_dir}/10-vm-defined.card.txt")" || got=1
check "story_card card text carries the title" "${got}"
got=0; has 'not a screenshot' "$(cat -- "${shot_dir}/10-vm-defined.card.txt")" || got=1
check "story_card card text is labelled 'not a screenshot'" "${got}"

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

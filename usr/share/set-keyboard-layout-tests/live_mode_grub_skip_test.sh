#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## set-grub-keymap must NOT build GRUB keymaps in a live-mode boot: a live
## system boots from a fixed, pre-built GRUB configuration that update-grub does
## not regenerate, so the work has no persistent effect. The fix makes
## build_all_grub_keymaps (and set_grub_keymap) detect live mode via the shared
## live-mode.sh (live_status_detected) and skip with a 'log info' message.
##
## TWO cases, so a code that ALWAYS skips cannot pass:
##   live       -> skip: the info message appears AND grub-kbdcomp is never run.
##   persistent -> proceed: grub-kbdcomp IS run and no skip message appears.
##
## Live mode is forced deterministically by injecting the inputs live-mode.sh
## reads (proc_mount_contents / kernel_cmdline / writable_fs_lists_str /
## livecheck_lsblk_contents); no real /proc, no get_writable_fs_lists.sh call.
## The real production wrapper usr/bin/set-grub-keymap is driven end to end.
## 'id' is stubbed root so the wrapper's own root gate passes; grub-kbdcomp and
## update-grub are stubbed so no GRUB tooling or /boot write is required, and
## grub_kb_layout_dir is redirected to a tempdir so the persistent case is
## hermetic. 'log info' is below the default threshold, so log_level=info is set
## to make the skip message observable.
##
## No root, no network, no real GRUB.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v SET_KEYBOARD_LAYOUT_REPO ] || SET_KEYBOARD_LAYOUT_REPO=""

if [ -n "${SET_KEYBOARD_LAYOUT_REPO}" ]; then
   repo="${SET_KEYBOARD_LAYOUT_REPO}"
elif [ -n "${HELPER_SCRIPTS_PATH:-}" ]; then
   repo="${HELPER_SCRIPTS_PATH}"
else
   repo=""
fi

subject=""
if [ -n "${repo}" ] && [ -r "${repo}/usr/bin/set-grub-keymap" ]; then
   subject="${repo}/usr/bin/set-grub-keymap"
elif [ -r '/usr/bin/set-grub-keymap' ]; then
   subject='/usr/bin/set-grub-keymap'
   repo="${repo:-/}"
fi

if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: set-grub-keymap not found" >&2
   printf '%s\n' "set SET_KEYBOARD_LAYOUT_REPO or HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install the package" >&2
   exit 1
fi

## The wrapper sources the library from HELPER_SCRIPTS_PATH; keep both pointed at
## the same tree so the subject under test is the checkout, not the installed copy.
helper_scripts_path="${HELPER_SCRIPTS_PATH:-${repo}}"

work_dir="$(mktemp --directory -- "${TMP}/set-keyboard-layout-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

ok() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "  ok: $1"
}
notok() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "  NOT OK: $1" >&2
}

## Build the stub bin once. Stubs win over the real tools because this dir is
## first on PATH.
stub_bin="${work_dir}/bin"
mkdir --parents -- "${stub_bin}"

printf '%s\n' \
   '#!/bin/bash' \
   '## Always report root so the wrapper root gate passes.' \
   'printf "%s\n" 0' >"${stub_bin}/id"

printf '%s\n' \
   '#!/bin/bash' \
   '## Minimal keymap list; args (--no-pager list-x11-keymap-layouts) ignored.' \
   'printf "%s\n" us de' >"${stub_bin}/localectl-static"

printf '%s\n' \
   '#!/bin/bash' \
   '## Record every invocation so the test can assert it did / did not run.' \
   'printf "called: %s\n" "$*" >>"${GRUB_KBDCOMP_MARKER}"' \
   'exit 0' >"${stub_bin}/grub-kbdcomp"

printf '%s\n' \
   '#!/bin/bash' \
   'exit 0' >"${stub_bin}/update-grub"

printf '%s\n' \
   '#!/bin/bash' \
   '## Not a chroot.' \
   'exit 1' >"${stub_bin}/ischroot"

chmod 0755 -- \
   "${stub_bin}/id" \
   "${stub_bin}/localectl-static" \
   "${stub_bin}/grub-kbdcomp" \
   "${stub_bin}/update-grub" \
   "${stub_bin}/ischroot"

## Run set-grub-keymap --build-all in a controlled environment.
## $1: live | persistent
## Prints combined stdout+stderr; sets run_rc and the marker file per case.
run_build_all() {
   local mode case_dir marker out_file rc
   mode="$1"
   case_dir="${work_dir}/${mode}"
   mkdir --parents -- "${case_dir}"
   marker="${case_dir}/grub-kbdcomp.calls"
   printf '' >"${marker}"
   out_file="${case_dir}/output.txt"

   local proc_mounts cmdline writable_lists
   if [ "${mode}" = 'live' ]; then
      ## iso-live: LiveOS_rootfs mounted at / plus rd.live.image, and no
      ## danger-writable '/', so live-mode.sh reports live_status_detected=true.
      proc_mounts='LiveOS_rootfs / iso9660 ro 0 0'
      cmdline='BOOT_IMAGE=/vmlinuz rd.live.image quiet'
      writable_lists=$'\n'
   else
      ## persistent: a normally writable root filesystem.
      proc_mounts='/dev/sda1 / ext4 rw 0 0'
      cmdline='BOOT_IMAGE=/vmlinuz quiet'
      writable_lists=$'\n/'
   fi

   rc=0
   env \
      PATH="${stub_bin}:${repo}/usr/bin:${repo}/usr/libexec/helper-scripts:/usr/bin:/bin" \
      HELPER_SCRIPTS_PATH="${helper_scripts_path}" \
      GRUB_KBDCOMP_MARKER="${marker}" \
      grub_kb_layout_dir="${case_dir}/kb_layouts" \
      log_level='info' \
      proc_mount_contents="${proc_mounts}" \
      kernel_cmdline="${cmdline}" \
      writable_fs_lists_str="${writable_lists}" \
      livecheck_lsblk_contents='1' \
      "${subject}" --build-all >"${out_file}" 2>&1 || rc=$?

   run_rc="${rc}"
   run_out_file="${out_file}"
   run_marker="${marker}"
}

skip_re='Live mode detected. Skipping GRUB keyboard layout setting'

printf '%s\n' "== case: live -> skip =="
run_build_all live
if [ "${run_rc}" -eq 0 ]; then
   ok "exit 0"
else
   notok "expected exit 0, got ${run_rc}"
   cat -- "${run_out_file}" >&2 || true
fi
if grep --quiet --fixed-strings -- "${skip_re}" "${run_out_file}"; then
   ok "live: emitted the skip info message"
else
   notok "live: skip info message missing"
   cat -- "${run_out_file}" >&2 || true
fi
if [ -s "${run_marker}" ]; then
   notok "live: grub-kbdcomp was invoked despite live mode"
   cat -- "${run_marker}" >&2 || true
else
   ok "live: grub-kbdcomp not invoked"
fi

printf '%s\n' "== case: persistent -> proceed =="
run_build_all persistent
if [ "${run_rc}" -eq 0 ]; then
   ok "exit 0"
else
   notok "expected exit 0, got ${run_rc}"
   cat -- "${run_out_file}" >&2 || true
fi
if grep --quiet --fixed-strings -- "${skip_re}" "${run_out_file}"; then
   notok "persistent: unexpectedly skipped GRUB keymap build"
   cat -- "${run_out_file}" >&2 || true
else
   ok "persistent: did not emit the live-mode skip message"
fi
if [ -s "${run_marker}" ]; then
   ok "persistent: grub-kbdcomp was invoked"
else
   notok "persistent: grub-kbdcomp was not invoked"
   cat -- "${run_out_file}" >&2 || true
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]

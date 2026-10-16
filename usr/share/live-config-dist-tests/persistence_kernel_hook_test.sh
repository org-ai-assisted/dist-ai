#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## zz-live-persistence-boot-sync: the kernel postinst.d hook that, under a
## persistent live overlay, copies the just-installed kernel+initrd onto the
## unencrypted persistbootx boot area and rewrites its grub.cfg. Drives the REAL
## hook and the REAL persistent-boot.sh helper. The hook gates on the overlay
## token on the kernel cmdline and resolves the boot device via a seam, so the
## only stubs needed are the root mount/umount/mountpoint commands (pure
## isolation). No root, no device, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""
if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   hook="${LIVE_CONFIG_DIST_REPO}/etc/kernel/postinst.d/zz-live-persistence-boot-sync"
else
   hook='/etc/kernel/postinst.d/zz-live-persistence-boot-sync'
fi
if [ ! -r "${hook}" ]; then
   printf '%s\n' "FATAL: hook not readable: ${hook}" >&2
   exit 1
fi

[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -z "${HELPER_SCRIPTS_PATH}" ] && [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   HELPER_SCRIPTS_PATH="$(dirname -- "${LIVE_CONFIG_DIST_REPO}")/helper-scripts"
fi
if [ ! -r "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/persistent-boot.sh" ]; then
   printf '%s\n' "FATAL: persistent-boot.sh not under HELPER_SCRIPTS_PATH='${HELPER_SCRIPTS_PATH}'" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1"; }

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Stub the root-only commands. mount records its target and no-ops (the hook then
## writes into that real dir); mountpoint is always false so the hook's EXIT trap
## leaves the populated dir for inspection.
sb="${work}/bin"
mkdir --parents -- "${sb}"
printf '%s\n' '#!/bin/bash' "printf '%s\\n' \"\$3\" > \"${work}/mountdir\"" 'exit 0' > "${sb}/mount"
printf '%s\n' '#!/bin/bash' 'exit 1' > "${sb}/mountpoint"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${sb}/umount"
chmod +x "${sb}/mount" "${sb}/mountpoint" "${sb}/umount"

srcboot="${work}/srcboot"
mkdir --parents -- "${srcboot}"
printf '%s' 'KERNEL' > "${srcboot}/vmlinuz-9.9.9"
printf '%s' 'INITRD' > "${srcboot}/initrd.img-9.9.9"

cmd_plain="${work}/cmd_plain"
printf '%s\n' 'BOOT_IMAGE=/live/vmlinuz root=live:CDLABEL=DM_LIVE rd.live.overlay.overlayfs=1 rd.live.overlay=LABEL=persistence:/live/overlay quiet' > "${cmd_plain}"
cmd_enc="${work}/cmd_enc"
printf '%s\n' 'BOOT_IMAGE=/live/vmlinuz root=live:CDLABEL=DM_LIVE rd.live.overlay.overlayfs=1 rd.live.overlay=LABEL=persistence:/live/overlay rd.luks.uuid=40e273d7-4e63-4459-b16f-ba3df4374905 quiet' > "${cmd_enc}"
cmd_notlive="${work}/cmd_notlive"
printf '%s\n' 'BOOT_IMAGE=/vmlinuz root=/dev/sda2 ro quiet' > "${cmd_notlive}"
## dracut allows the overlay label WITHOUT a subpath -- the gate must still fire.
cmd_pathless="${work}/cmd_pathless"
printf '%s\n' 'BOOT_IMAGE=/live/vmlinuz rd.live.image rd.live.overlay=LABEL=persistence rd.live.overlay.overlayfs=1 quiet' > "${cmd_pathless}"
## A different label that merely has 'persistence' as a prefix must NOT match.
cmd_substr="${work}/cmd_substr"
printf '%s\n' 'BOOT_IMAGE=/live/vmlinuz rd.live.image rd.live.overlay=LABEL=persistence-old:/x rd.live.overlay.overlayfs=1 quiet' > "${cmd_substr}"

## Run the hook with the mount stubs on PATH, the boot device forced via the seam,
## the cmdline and kernel source pointed at the fixtures. TMPDIR stays in the
## workdir so the hook's own mktemp mount_dir is cleaned up with it.
## HOOK_RC carries the hook's exit code out of run_hook (its own subshell would
## otherwise lose it). A kernel postinst.d hook MUST exit 0 on EVERY path -- a
## nonzero return aborts the kernel upgrade (half-configured dpkg). This is the
## hook's whole best-effort contract, so assert_rc0 is checked after every
## scenario, not only the sync ones.
HOOK_RC=0
run_hook() {
   HOOK_RC=0
   safe-rm --force -- "${work}/mountdir"
   PATH="${sb}:${PATH}" \
      TMPDIR="${work}" \
      HELPER_SCRIPTS_PATH="${2}" \
      LIVE_PERSISTENCE_KERNEL_SRC="${srcboot}" \
      PERSISTENT_BOOT_CMDLINE_FILE="${1}" \
      PERSISTENT_BOOT_DEVICE=/dev/fake-persistbootx \
      bash "${hook}" 9.9.9 > /dev/null 2>&1 || HOOK_RC=$?
}
assert_rc0() {
   if [ "${HOOK_RC}" -eq 0 ]; then
      pass "$1: hook exited 0 (never aborts the kernel upgrade)"
   else
      fail "$1: hook exited ${HOOK_RC} (would abort dpkg)"
   fi
}

LAST_CFG=''
assert_synced() {
   local label mount_dir cfg
   label="$1"
   LAST_CFG=''
   if [ ! -r "${work}/mountdir" ]; then
      fail "${label}: hook did not mount a boot device"
      return
   fi
   mount_dir="$(cat -- "${work}/mountdir")"
   if [ -e "${mount_dir}/boot/vmlinuz-9.9.9" ] && [ -e "${mount_dir}/boot/initrd.img-9.9.9" ]; then
      pass "${label}: kernel+initrd copied into the boot area"
   else
      fail "${label}: kernel+initrd not copied"
   fi
   cfg="${mount_dir}/boot/grub/grub.cfg"
   if [ -r "${cfg}" ] && grep --quiet 'vmlinuz-9.9.9' "${cfg}" \
      && grep --quiet 'rd.live.overlay=LABEL=persistence:/live/overlay' "${cfg}"; then
      pass "${label}: grub.cfg written for the new kernel"
      LAST_CFG="${cfg}"
   else
      fail "${label}: grub.cfg missing or wrong"
   fi
}

## --- plaintext: no rd.luks.uuid ---------------------------------------------
run_hook "${cmd_plain}" "${HELPER_SCRIPTS_PATH}"
assert_rc0 'plaintext'
assert_synced 'plaintext'
if [ -n "${LAST_CFG}" ] && ! grep --quiet 'rd.luks.uuid=' "${LAST_CFG}"; then
   pass "plaintext: no rd.luks.uuid in the boot cmdline"
else
   fail "plaintext: unexpected rd.luks.uuid (or no cfg)"
fi

## --- encrypted: rd.luks.uuid carried from the cmdline -----------------------
run_hook "${cmd_enc}" "${HELPER_SCRIPTS_PATH}"
assert_rc0 'encrypted'
assert_synced 'encrypted'
if [ -n "${LAST_CFG}" ] && grep --quiet 'rd.luks.uuid=40e273d7-4e63-4459-b16f-ba3df4374905' "${LAST_CFG}"; then
   pass "encrypted: rd.luks.uuid carried into the boot cmdline"
else
   fail "encrypted: rd.luks.uuid not carried"
fi

## --- gate: a non-persistent (installed/amnesic) cmdline is a no-op ----------
run_hook "${cmd_notlive}" "${HELPER_SCRIPTS_PATH}"
assert_rc0 'gate-notlive'
if [ ! -r "${work}/mountdir" ]; then
   pass "gate: no overlay token on the cmdline -> hook does nothing"
else
   fail "gate: hook acted without the overlay token"
fi

## --- gate: pathless overlay token still fires -------------------------------
run_hook "${cmd_pathless}" "${HELPER_SCRIPTS_PATH}"
assert_rc0 'gate-pathless'
if [ -r "${work}/mountdir" ]; then
   pass "gate: pathless 'LABEL=persistence' (no subpath) still syncs"
else
   fail "gate: pathless overlay token wrongly skipped"
fi
## The pathless gate must not just MOUNT -- it must fully sync (copy + grub.cfg).
assert_synced 'pathless'

## --- gate: a prefix-only label (persistence-old) is NOT matched -------------
run_hook "${cmd_substr}" "${HELPER_SCRIPTS_PATH}"
assert_rc0 'gate-substr'
if [ ! -r "${work}/mountdir" ]; then
   pass "gate: 'persistence-old' does not match the exact label"
else
   fail "gate: prefix label wrongly matched"
fi

## --- best-effort: a missing helper never aborts (and does not mount) --------
run_hook "${cmd_plain}" "${work}/no-helper-here"
assert_rc0 'missing-helper'
if [ ! -r "${work}/mountdir" ]; then
   pass "missing helper: hook exits without syncing (dpkg not aborted)"
else
   fail "missing helper: hook proceeded"
fi

printf '%s\n' ""
printf '%s\n' "===== persistence kernel hook: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]

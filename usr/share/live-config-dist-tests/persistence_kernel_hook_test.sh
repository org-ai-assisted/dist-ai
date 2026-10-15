#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 50_live-persistence-boot-sync: the kernel postinst.d hook that, under a
## persistent live overlay, copies the just-installed kernel+initrd into the
## grub-readable boot area and rewrites its grub.cfg. Drives the REAL hook and
## the REAL persistent-boot.sh helper; stubs the device/live-status commands that
## need root or a live boot (blkid/mount/mountpoint/umount + live-mode.sh). The
## stubs only ISOLATE -- they force the hook's persistence-active branch and
## report a fake boot device; all copy + grub.cfg logic is the real code.
## No root, no device, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""
if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   hook="${LIVE_CONFIG_DIST_REPO}/etc/kernel/postinst.d/50_live-persistence-boot-sync"
else
   hook='/etc/kernel/postinst.d/50_live-persistence-boot-sync'
fi
if [ ! -r "${hook}" ]; then
   printf '%s\n' "FATAL: hook not readable: ${hook}" >&2
   exit 1
fi

[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -z "${HELPER_SCRIPTS_PATH}" ] && [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   HELPER_SCRIPTS_PATH="$(dirname -- "${LIVE_CONFIG_DIST_REPO}")/helper-scripts"
fi
real_persistent_boot="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/persistent-boot.sh"
if [ ! -r "${real_persistent_boot}" ]; then
   printf '%s\n' "FATAL: persistent-boot.sh not readable: ${real_persistent_boot}" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1"; }

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Fake helper dir: a stub live-mode.sh (forces the persistence-active branch)
## beside a symlink to the REAL persistent-boot.sh (so the grub.cfg logic is real).
fh="${work}/fh/usr/libexec/helper-scripts"
mkdir --parents -- "${fh}"
ln --symbolic -- "${real_persistent_boot}" "${fh}/persistent-boot.sh"
printf '%s\n' '#!/bin/bash' "printf '%s\\n' \"live_status_persistence_active='true'\"" > "${fh}/live-mode.sh"
chmod +x "${fh}/live-mode.sh"

## Stub the root/device commands. blkid reports a boot device by label; mount
## records its target and no-ops; mountpoint is always false so the hook's EXIT
## trap leaves the populated dir for inspection.
sb="${work}/bin"
mkdir --parents -- "${sb}"
## The stub bodies below are literal shell written to files; their ${...} must
## NOT expand now (they expand when the stub runs).
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/bash' 'label="$2"' 'case "${label}" in' \
   '   persistbootx) if [ -n "${STUB_PERSISTBOOTX:-}" ]; then printf "%s\n" /dev/fake-persistbootx; exit 0; fi; exit 1 ;;' \
   '   persistence) printf "%s\n" /dev/fake-persistence; exit 0 ;;' \
   'esac' 'exit 1' > "${sb}/blkid"
printf '%s\n' '#!/bin/bash' "printf '%s\\n' \"\$3\" > \"${work}/mountdir\"" 'exit 0' > "${sb}/mount"
printf '%s\n' '#!/bin/bash' 'exit 1' > "${sb}/mountpoint"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${sb}/umount"
chmod +x "${sb}/blkid" "${sb}/mount" "${sb}/mountpoint" "${sb}/umount"

srcboot="${work}/srcboot"
mkdir --parents -- "${srcboot}"
printf '%s' 'KERNEL' > "${srcboot}/vmlinuz-9.9.9"
printf '%s' 'INITRD' > "${srcboot}/initrd.img-9.9.9"

cmdfile="${work}/cmdline"
printf '%s\n' 'BOOT_IMAGE=/live/vmlinuz root=live:CDLABEL=DM_LIVE rd.live.overlay.overlayfs=1 rd.luks.uuid=40e273d7-4e63-4459-b16f-ba3df4374905 quiet' > "${cmdfile}"

## Run the hook with the stubs on PATH and the test seams set. TMPDIR is pointed
## into the workdir so the hook's own mktemp mount_dir is cleaned up with it.
run_hook() {
   safe-rm --force -- "${work}/mountdir"
   PATH="${sb}:${PATH}" \
      TMPDIR="${work}" \
      HELPER_SCRIPTS_PATH="${work}/fh" \
      LIVE_PERSISTENCE_KERNEL_SRC="${srcboot}" \
      PERSISTENT_BOOT_CMDLINE_FILE="${cmdfile}" \
      STUB_PERSISTBOOTX="$1" \
      bash "${hook}" 9.9.9 > /dev/null 2>&1 || true
}

## Sets the global LAST_CFG to the written grub.cfg path (empty on failure); the
## PASS/FAIL prints would otherwise pollute a stdout-returned value.
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

## --- plaintext: no persistbootx -> persistence partition, no luks uuid -------
run_hook ""
assert_synced 'plaintext'
if [ -n "${LAST_CFG}" ] && ! grep --quiet 'rd.luks.uuid=' "${LAST_CFG}"; then
   pass "plaintext: no rd.luks.uuid in the boot cmdline"
else
   fail "plaintext: unexpected rd.luks.uuid (or no cfg)"
fi

## --- encrypted: persistbootx present -> luks uuid carried from the cmdline ---
run_hook "1"
assert_synced 'encrypted'
if [ -n "${LAST_CFG}" ] && grep --quiet 'rd.luks.uuid=40e273d7-4e63-4459-b16f-ba3df4374905' "${LAST_CFG}"; then
   pass "encrypted: rd.luks.uuid carried into the boot cmdline"
else
   fail "encrypted: rd.luks.uuid not carried (or no cfg)"
fi

printf '%s\n' ""
printf '%s\n' "===== persistence kernel hook: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]

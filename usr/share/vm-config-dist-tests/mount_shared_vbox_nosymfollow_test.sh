#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: R-003 -- 3-space to match the vm-config-dist-tests siblings.

## vm-config-dist's mount-shared mounts the "shared" transfer folder. The VBox
## branch cannot pass nosymfollow to mount.vboxsf (it rejects unknown options, so
## the share would stay UNMOUNTED), yet vboxsf DOES present a host-side symlink to
## the guest as a real symlink inode the guest follows -- verified on a booted
## guest (SharedFoldersEnableSymlinksCreate gates only guest CREATION, not
## FOLLOWING of host symlinks). So the branch re-applies symlink-follow protection
## at the VFS layer via a self-bind of /mnt/shared carrying nosymfollow, reaching
## 9p/virtiofs parity.
##
## This is the CHEAP static guard against the realistic regression -- a silent
## revert that drops the self-bind, or a naive move of nosymfollow onto the
## mount.vboxsf line (which would unmount the share). The runtime effect (a host
## symlink becomes ELOOP after the bind) is verified separately on a booted vbox
## guest; vboxsf cannot run under GitHub CI.
##
## No root, no network, no VirtualBox.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v VM_CONFIG_DIST_REPO ] || VM_CONFIG_DIST_REPO=""

rel="usr/libexec/vm-config-dist/mount-shared"
if [ -n "${VM_CONFIG_DIST_REPO}" ]; then
   subject="${VM_CONFIG_DIST_REPO}/${rel}"
else
   subject="/${rel}"
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: mount-shared not found at '${subject}'" >&2
   printf '%s\n' "set VM_CONFIG_DIST_REPO to a checkout, or install the package" >&2
   exit 1
fi

## Isolate the MOUNT vbox) case arm so an assertion cannot accidentally match the
## kvm branch (which legitimately passes nosymfollow to its 9p/virtiofs mounts).
## mount-shared has TWO "case ${virt_type}" blocks (the first only picks the group
## name), so buffer each "vbox)"..";;" arm and keep the one that performs the
## mount. R-070 keeps ";;" on its own line, so the arm boundary is reliable.
vbox_arm="$(awk '
   /^[[:space:]]*vbox\)[[:space:]]*$/ { inarm=1; buf=""; next }
   inarm && /^[[:space:]]*;;[[:space:]]*$/ {
      if (buf ~ /mount -t vboxsf/) { printf "%s", buf; exit }
      inarm=0; next
   }
   inarm { buf = buf $0 "\n" }
' "${subject}")"

if [ -z "${vbox_arm}" ]; then
   printf '%s\n' "FATAL: could not isolate the vbox) case arm in '${subject}'" >&2
   exit 1
fi

pass_count=0
fail_count=0

## assert <description> <grep-args...>: PASS iff grep MATCHES the vbox arm. Run in an
## if-condition so a no-match (the RED case) does not trip errexit -- a guard that
## aborted on a revert instead of FAILING would be a false green.
assert() {
   local desc="$1"
   shift
   if printf '%s\n' "${vbox_arm}" | grep "$@"; then
      printf '%s\n' "PASS: ${desc}"
      pass_count=$(( pass_count + 1 ))
   else
      printf '%s\n' "FAIL: ${desc}"
      fail_count=$(( fail_count + 1 ))
   fi
}

## refute <description> <grep-args...>: PASS iff grep does NOT match (pattern absent).
refute() {
   local desc="$1"
   shift
   if printf '%s\n' "${vbox_arm}" | grep "$@"; then
      printf '%s\n' "FAIL: ${desc}"
      fail_count=$(( fail_count + 1 ))
   else
      printf '%s\n' "PASS: ${desc}"
      pass_count=$(( pass_count + 1 ))
   fi
}

## The vboxsf mount keeps its base hardening.
assert "vboxsf mount carries nosuid,nodev,noexec" \
   --quiet --extended-regexp 'mount -t vboxsf .*nosuid,nodev,noexec'

## nosymfollow must NOT be on the mount.vboxsf line -- it rejects the unknown
## option and would leave the share unmounted. Guards a naive "just add it" revert.
refute "nosymfollow is NOT passed to mount -t vboxsf (would unmount the share)" \
   --quiet --extended-regexp 'mount -t vboxsf .*nosymfollow'

## The self-bind must exist: bind /mnt/shared onto itself, then re-apply the flags.
assert "self-bind of /mnt/shared onto itself is present" \
   --quiet --fixed-strings 'mount --bind /mnt/shared /mnt/shared'

## The canary: the remount re-applies the FULL restrictive set including
## nosymfollow. Dropping nosymfollow (or any of the four) FAILS here. remount,bind
## resets any per-mount flag not restated, so all four must be listed.
assert "remount,bind re-applies nosuid,nodev,noexec,nosymfollow at the VFS layer" \
   --quiet --extended-regexp 'remount,bind,nosuid,nodev,noexec,nosymfollow'

printf '%s\n' "===== mount_shared_vbox_nosymfollow: ${pass_count} pass, ${fail_count} fail ====="
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi

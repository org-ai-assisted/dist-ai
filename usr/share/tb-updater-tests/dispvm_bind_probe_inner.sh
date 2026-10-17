#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Runs INSIDE a private mount namespace (the caller entered it via
## run_in_mount_namespace). Proves whether a root 'mount --bind' onto a
## SYMLINKED target follows the symlink (the CWE-59 LPE) or is refused.
##
## Arg convention is run_in_mount_namespace's: $1 = staged subject path
## (unused here), $2 = mode (plain|flag|opt). A refused mount returns nonzero
## on purpose; its status is captured with '|| rc=$?', so errexit stays on.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

mode="$2"

## The mount namespace isolates the MOUNT, not the filesystem: base lives on the
## real /tmp, so clean it up (else every run leaks a dir on a long-lived host).
base=""
cleanup() {
   [ -z "${base}" ] && return 0
   ## A follow case binds onto base/victim; detach it (lazy) before removing, or
   ## safe-rm hits a busy mountpoint and leaves the dir on the real /tmp.
   umount --lazy -- "${base}/victim" 2>/dev/null || true
   safe-rm --recursive --force -- "${base}" 2>/dev/null || true
}
trap cleanup EXIT

base="$(mktemp --directory)"
mkdir -- "${base}/src" "${base}/victim"
printf '%s\n' "SRC" > "${base}/src/marker_src"
printf '%s\n' "VICTIM" > "${base}/victim/marker_victim"
## tgt is a symlink to victim -- the unprivileged user's pre-planted mountpoint.
ln -s "${base}/victim" "${base}/tgt"

rc=0
case "${mode}" in
   plain)
      mount --bind -o nosuid,nodev -- "${base}/src" "${base}/tgt" 2>/dev/null || rc=$?
      ;;
   flag)
      mount --no-canonicalize --bind -o nosuid,nodev -- "${base}/src" "${base}/tgt" 2>/dev/null || rc=$?
      ;;
   opt)
      mount --bind -o nosuid,nodev,X-mount.nocanonicalize -- "${base}/src" "${base}/tgt" 2>/dev/null || rc=$?
      ;;
   opt_slash)
      ## Envelope limit: a TRAILING SLASH makes the kernel resolve THROUGH the
      ## symlink at mount(2) time, so no-canonicalize does NOT refuse it. dispvm
      ## avoids this by passing bare dir-symlink targets.
      mount --bind -o nosuid,nodev,X-mount.nocanonicalize -- "${base}/src" "${base}/tgt/" 2>/dev/null || rc=$?
      ;;
   *)
      printf '%s\n' "VERDICT=BAD_MODE"
      exit 2
      ;;
esac

if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "VERDICT=REFUSED_SAFE"
elif [ -e "${base}/victim/marker_src" ]; then
   ## src's marker is now visible under victim -> the bind landed on the victim.
   printf '%s\n' "VERDICT=FOLLOWED_VULNERABLE"
else
   printf '%s\n' "VERDICT=MOUNTED_BUT_VICTIM_UNTOUCHED"
fi

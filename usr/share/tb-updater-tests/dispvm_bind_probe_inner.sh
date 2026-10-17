#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Runs INSIDE a private mount namespace (the caller entered it via
## run_in_mount_namespace). Proves whether a root 'mount --bind' onto a
## SYMLINKED target follows the symlink (the CWE-59 LPE) or is refused.
##
## Arg convention is run_in_mount_namespace's: $1 = staged subject path
## (unused here), $2 = mode (plain|flag|opt|opt_slash). A refused mount returns
## nonzero on purpose; its status is captured with '|| rc=$?', so errexit stays on.
##
## POSITIVE CONTROL: each mode first binds a NORMAL (non-symlink) dir target,
## which MUST succeed. Only then is REFUSED_SAFE meaningful -- it means "refused
## the symlink", not "failed for any reason" (an unsupported option or a broken
## env would otherwise read as a vacuous REFUSED_SAFE).

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
   ## A follow case binds onto base/victim (and the control onto base/normal);
   ## detach both (lazy) before removing, or safe-rm hits a busy mountpoint and
   ## leaves the dir on the real /tmp.
   umount --lazy -- "${base}/victim" 2>/dev/null || true
   umount --lazy -- "${base}/normal" 2>/dev/null || true
   safe-rm --recursive --force -- "${base}" 2>/dev/null || true
}
trap cleanup EXIT

base="$(mktemp --directory)"
mkdir -- "${base}/src" "${base}/victim" "${base}/normal"
printf '%s\n' "SRC" > "${base}/src/marker_src"
printf '%s\n' "VICTIM" > "${base}/victim/marker_victim"
## tgt is a symlink to victim -- the unprivileged user's pre-planted mountpoint.
ln -s "${base}/victim" "${base}/tgt"

## Bind the mode's directive onto target $1. Caller captures rc via '|| rc=$?'.
do_mount() {
   case "${mode}" in
      plain)
         mount --bind -o nosuid,nodev -- "${base}/src" "$1" 2>/dev/null
         ;;
      flag)
         mount --no-canonicalize --bind -o nosuid,nodev -- "${base}/src" "$1" 2>/dev/null
         ;;
      opt|opt_slash)
         mount --bind -o nosuid,nodev,X-mount.nocanonicalize -- "${base}/src" "$1" 2>/dev/null
         ;;
      *)
         printf '%s\n' "VERDICT=BAD_MODE"
         exit 2
         ;;
   esac
}

## Positive control: the mount FORM must successfully bind a normal dir target.
ctl=0
do_mount "${base}/normal" || ctl=$?
if [ "${ctl}" -ne 0 ]; then
   printf '%s\n' "VERDICT=CONTROL_FAILED"
   exit 0
fi
umount -- "${base}/normal" 2>/dev/null || true

## Symlink case: a trailing slash (opt_slash) makes the kernel resolve THROUGH
## the symlink at mount(2) time, outside no-canonicalize -- the envelope limit
## dispvm avoids by passing bare dir-symlink targets.
target="${base}/tgt"
[ "${mode}" = "opt_slash" ] && target="${base}/tgt/"
rc=0
do_mount "${target}" || rc=$?

if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "VERDICT=REFUSED_SAFE"
elif [ -e "${base}/victim/marker_src" ]; then
   ## src's marker is now visible under victim -> the bind landed on the victim.
   printf '%s\n' "VERDICT=FOLLOWED_VULNERABLE"
else
   printf '%s\n' "VERDICT=MOUNTED_BUT_VICTIM_UNTOUCHED"
fi

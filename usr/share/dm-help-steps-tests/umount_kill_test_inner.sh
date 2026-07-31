#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Mount-namespace half of 'umount_kill_test.sh': asserts that the reaper
## unmounts STRICTLY UNDER the tree and never the tree's own root mount.
## unchroot-raw calls it on '$CHROOT_FOLDER' (the ext4 root that mount-raw
## placed) between install-packages chroot cycles purely to reap lingering
## processes; unmounting that root drops the next chroot into an empty
## directory ("chroot: failed to run command 'mkdir': No such file or
## directory").
##
## $1 -- the 'umount_kill.sh' script under test

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

subject_path="$1"

mount_tree="$(mktemp --directory)"

## A tmpfs AT the tree root, plus a genuine child mount created inside it.
mount --types tmpfs tmpfs-umk-base "${mount_tree}"
mkdir --parents -- "${mount_tree}/sub"
mount --types tmpfs tmpfs-umk-sub "${mount_tree}/sub"

bash "${subject_path}" "${mount_tree}" >/dev/null 2>&1 || true

## Read the state the way the tool under test does. 'mountpoint' misreports a
## '--lazy'-detached mount as still mounted; findmnt (which reads mountinfo,
## as umount_kill.sh does) reflects the lazy detach immediately. Exact
## whole-line match so 'base' does not accidentally match 'base/sub'.
mounts_now="$(findmnt --raw --noheadings --output TARGET)"

if printf '%s\n' "${mounts_now}" | grep --max-count=1 --line-regexp --fixed-strings -- "${mount_tree}/sub" >/dev/null 2>&1; then
   printf '%s\n' "RESULT sub NOT_UNMOUNTED"
else
   printf '%s\n' "RESULT sub UNMOUNTED"
fi

if printf '%s\n' "${mounts_now}" | grep --max-count=1 --line-regexp --fixed-strings -- "${mount_tree}" >/dev/null 2>&1; then
   printf '%s\n' "RESULT base PRESERVED"
else
   printf '%s\n' "RESULT base UNMOUNTED"
fi

printf '%s\n' "RESULT inner DONE"

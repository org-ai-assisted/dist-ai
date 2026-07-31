#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Mount-namespace half of 'unmount_tree_test.sh': builds the mount fixtures,
## runs the subject against them and reports each outcome as a 'RESULT <name>
## <verdict>' line for the outer test to assert on. Runs inside
## 'unshare --user --map-root-user --mount' (see 'help_steps_test_lib.bsh'),
## so every mount it makes is private and disappears with the namespace.
##
## $1 -- the 'unmount-tree' script under test
## $2 -- a scratch directory created by the caller

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

subject_path="$1"
scratch_base="$2"

tab_character=$'\t'

## Read the mount points currently under '$1', decoding mountinfo's octal
## escaping. Deliberately does NOT reuse the subject's own reader: a bug
## shared between tool and test would cancel itself out.
is_mounted_at() {
   local wanted_path mountinfo_fields decoded_path

   wanted_path="$1"
   mountinfo_fields=()
   while read -r -a mountinfo_fields; do
      ## mountinfo field 5 (index 4) is the mount point, proc_pid_mountinfo(5).
      printf -v decoded_path '%b' "${mountinfo_fields[4]}"
      if [ "${decoded_path}" = "${wanted_path}" ]; then
         return 0
      fi
   done < /proc/self/mountinfo
   return 1
}

## How many mount points remain strictly under '$1'. Used where the identity
## of the leftovers does not matter, only that there are none -- and where two
## mounts can share one path (an over-mount), which 'is_mounted_at' cannot
## distinguish.
count_mounts_under() {
   local tree mountinfo_fields decoded_path mount_count

   tree="$1"
   mount_count=0
   mountinfo_fields=()
   while read -r -a mountinfo_fields; do
      printf -v decoded_path '%b' "${mountinfo_fields[4]}"
      case "${decoded_path}" in
         "${tree}"/*)
            mount_count=$((mount_count + 1))
            ;;
      esac
   done < /proc/self/mountinfo
   printf '%s\n' "${mount_count}"
}

report() {
   local marker_name checked_path

   marker_name="$1"
   checked_path="$2"

   if is_mounted_at "${checked_path}"; then
      printf '%s\n' "RESULT ${marker_name} MOUNTED"
   else
      printf '%s\n' "RESULT ${marker_name} UNMOUNTED"
   fi
}

## ---- phase 1: sweep submounts, preserve the tree's own root and a sibling ----

target_tree="${scratch_base}/tree"
## '<target>2' is a deliberate string-prefix collision of the target.
sibling_tree="${scratch_base}/tree2"
mkdir --parents -- "${target_tree}" "${sibling_tree}/sub"

## A tmpfs AT the tree root: it belongs to the caller and must SURVIVE.
mount --types tmpfs tmpfs-ut-root "${target_tree}"
mkdir --parents -- "${target_tree}/sub" "${target_tree}/deep"
mount --types tmpfs tmpfs-ut-sub "${target_tree}/sub"

## Nested chain: a parent unmounted before its child would leave the child
## behind ("target is busy"), so this pins the deepest-first ordering.
mount --types tmpfs tmpfs-ut-deep "${target_tree}/deep"
mkdir --parents -- "${target_tree}/deep/er"
mount --types tmpfs tmpfs-ut-deep-er "${target_tree}/deep/er"
mkdir --parents -- "${target_tree}/deep/er/est"
mount --types tmpfs tmpfs-ut-deep-er-est "${target_tree}/deep/er/est"

## Whitespace in a mount point: 'findmnt --raw' renders a space as '\x20' and
## 'findmnt --list' renders a tab as '\x09', and the escaped string handed to
## 'umount' does not name any mount, so a findmnt-based sweep reports success
## while leaving these mounted.
mkdir --parents -- "${target_tree}/has space" "${target_tree}/has${tab_character}tab"
mount --types tmpfs tmpfs-ut-space "${target_tree}/has space"
mount --types tmpfs tmpfs-ut-tab "${target_tree}/has${tab_character}tab"

mount --types tmpfs tmpfs-ut-sibling "${sibling_tree}/sub"

phase_one_rc=0
bash "${subject_path}" "${target_tree}" >/dev/null 2>&1 || phase_one_rc="$?"
printf '%s\n' "RESULT exit ${phase_one_rc}"

report sub      "${target_tree}/sub"
report deepest  "${target_tree}/deep/er/est"
report deepmid  "${target_tree}/deep/er"
report deeproot "${target_tree}/deep"
report space    "${target_tree}/has space"
report tab      "${target_tree}/has${tab_character}tab"
report root     "${target_tree}"
report sibling  "${sibling_tree}/sub"

## ---- phase 2: a symlinked tree argument resolves to the real path ----

link_target="${scratch_base}/linktarget"
link_name="${scratch_base}/linkname"
mkdir --parents -- "${link_target}/sub"
mount --types tmpfs tmpfs-ut-link "${link_target}/sub"
ln --symbolic -- "${link_target}" "${link_name}"

bash "${subject_path}" "${link_name}" >/dev/null 2>&1 || true
report symlink "${link_target}/sub"

## ---- phase 3: '--' end-of-options with a dash-leading relative tree ----

dash_tree="${scratch_base}/-dashtree"
mkdir --parents -- "${dash_tree}/sub"
mount --types tmpfs tmpfs-ut-dash "${dash_tree}/sub"
( cd -- "${scratch_base}" && bash "${subject_path}" -- "-dashtree" >/dev/null 2>&1 ) || true
report dash "${dash_tree}/sub"

## ---- phase 4: fail CLOSED when the unmounts do not take effect ----

## A 'umount' that reports success without detaching anything stands in for a
## kernel that refuses the detach. The sweep must then exit non-zero rather
## than let a caller proceed to a recursive delete across a live mount.
stub_dir="${scratch_base}/stub-bin"
stub_tree="${scratch_base}/stubtree"
mkdir --parents -- "${stub_dir}" "${stub_tree}/sub"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${stub_dir}/umount"
chmod 0755 -- "${stub_dir}/umount"
mount --types tmpfs tmpfs-ut-stub "${stub_tree}/sub"

stub_rc=0
PATH="${stub_dir}:${PATH}" bash "${subject_path}" "${stub_tree}" >/dev/null 2>&1 || stub_rc="$?"
if [ "${stub_rc}" = "0" ]; then
   printf '%s\n' "RESULT failclosed EXIT_ZERO"
else
   printf '%s\n' "RESULT failclosed EXIT_NONZERO"
fi

## Detach the still-mounted fixture so the caller's scratch cleanup cannot
## cross it.
umount --lazy -- "${stub_tree}/sub" || true

## ---- phase 5: deepest-first ORDER of the umount calls ----

## Observing the resulting mount table cannot see the ordering: '--lazy'
## detaches a parent that still has children under it, and the sweep's retry
## pass would clear any leftovers anyway, so a parent-first implementation
## reaches the same end state. Record the calls instead.
real_umount="$(type -P umount)"
order_dir="${scratch_base}/order-bin"
order_tree="${scratch_base}/ordertree"
order_log="${scratch_base}/umount-order.log"
mkdir --parents -- "${order_dir}" "${order_tree}"
true > "${order_log}"

## Logs the target (the last argument) and then performs the real unmount.
printf '%s\n' \
   '#!/bin/bash' \
   'printf "%s\n" "${!#}" >> "${UNMOUNT_ORDER_LOG}"' \
   "${real_umount} \"\$@\"" > "${order_dir}/umount"
chmod 0755 -- "${order_dir}/umount"

mount --types tmpfs tmpfs-ut-order-a "${order_tree}"
mkdir --parents -- "${order_tree}/b"
mount --types tmpfs tmpfs-ut-order-b "${order_tree}/b"
mkdir --parents -- "${order_tree}/b/c"
mount --types tmpfs tmpfs-ut-order-c "${order_tree}/b/c"

PATH="${order_dir}:${PATH}" UNMOUNT_ORDER_LOG="${order_log}" \
   bash "${subject_path}" "${order_tree}" >/dev/null 2>&1 || true

## The child must be logged before its parent.
order_seen=""
while IFS="" read -r order_line; do
   case "${order_line}" in
      "${order_tree}/b/c")
         order_seen="${order_seen}c"
         ;;
      "${order_tree}/b")
         order_seen="${order_seen}b"
         ;;
   esac
done < "${order_log}"

if [ "${order_seen}" = "cb" ]; then
   printf '%s\n' "RESULT order DEEPEST_FIRST"
else
   printf '%s\n' "RESULT order WRONG:${order_seen}"
fi

## ---- phase 6: shadowed over-mount ----

## A child mounted BEFORE something is mounted over its parent keeps the
## now-hidden LOWER parent as its parent mount, so detaching the topmost
## parent does not detach the child. Sorting cannot fix this -- only
## re-reading the mount table until it stops changing does.
shadow_base="${scratch_base}/shadowbase"
mkdir --parents -- "${shadow_base}/a"
mount --types tmpfs tmpfs-ut-lower "${shadow_base}/a"
mkdir --parents -- "${shadow_base}/a/child"
mount --types tmpfs tmpfs-ut-child "${shadow_base}/a/child"
## Hides the lower mount, and with it the child's parent.
mount --types tmpfs tmpfs-ut-upper "${shadow_base}/a"

bash "${subject_path}" "${shadow_base}" >/dev/null 2>&1 || true
printf '%s\n' "RESULT shadow REMAINING=$(count_mounts_under "${shadow_base}")"

## ---- phase 7: backslash and newline in a mount point name ----

## mountinfo escapes ' ', '\t', '\n' and '\' as '\040', '\011', '\012',
## '\134'. A decoder that mishandles the backslash case corrupts the path and
## the unmount silently misses.
hostile_base="${scratch_base}/hostilebase"
hostile_backslash="${hostile_base}/has\\back"
hostile_newline="${hostile_base}/has
newline"
mkdir --parents -- "${hostile_backslash}" "${hostile_newline}"
mount --types tmpfs tmpfs-ut-bs "${hostile_backslash}"
mount --types tmpfs tmpfs-ut-nl "${hostile_newline}"

bash "${subject_path}" "${hostile_base}" >/dev/null 2>&1 || true
printf '%s\n' "RESULT hostile REMAINING=$(count_mounts_under "${hostile_base}")"

## ---- phase 8: shared-mount propagation does not reach outside the tree ----

## umount(2) NOTES warn that unmounting one peer of a SHARED mount can unmount
## its peers, and the sweep falls back to '--lazy'. That would make the
## strictly-below guarantee hold for what is targeted but not for what the
## kernel then does to peers elsewhere. Pin that it does not happen, so the
## sweep never needs a 'mount --make-rprivate' that would itself mutate the
## caller's mount tree.
shared_base="${scratch_base}/sharedbase"
shared_src="${shared_base}/src"
shared_tree="${shared_base}/tree"
shared_outside="${shared_base}/outside"
mkdir --parents -- "${shared_src}" "${shared_tree}/inside" "${shared_outside}"
mount --types tmpfs tmpfs-ut-shared "${shared_src}"
## Shared, then bound both under the tree and outside it: one peer group.
mount --make-shared "${shared_src}"
mount --bind "${shared_src}" "${shared_tree}/inside"
mount --bind "${shared_src}" "${shared_outside}"

bash "${subject_path}" "${shared_tree}" >/dev/null 2>&1 || true

if is_mounted_at "${shared_outside}"; then
   printf '%s\n' "RESULT peer OUTSIDE_SURVIVED"
else
   printf '%s\n' "RESULT peer OUTSIDE_UNMOUNTED"
fi
printf '%s\n' "RESULT sharedtree REMAINING=$(count_mounts_under "${shared_tree}")"

printf '%s\n' "RESULT inner DONE"

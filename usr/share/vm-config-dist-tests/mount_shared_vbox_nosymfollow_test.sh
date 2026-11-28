#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: R-003 -- 3-space to match the vm-config-dist-tests siblings.

## vm-config-dist's mount-shared hardens the "shared" transfer folder. The vbox
## branch cannot pass nosymfollow to mount.vboxsf (it rejects unknown options, so
## the share would stay UNMOUNTED), yet vboxsf presents a host-side symlink to the
## guest as a real symlink inode the guest FOLLOWS -- verified on a booted guest
## (SharedFoldersEnableSymlinksCreate gates only guest CREATION of symlinks, not
## FOLLOWING of host ones). So the branch re-applies nosymfollow at the VFS layer
## with a remount,bind on /mnt/shared, reaching 9p/virtiofs parity.
##
## This guard RUNS the real mount-shared vbox branch under a recording `mount`
## stub and asserts on the ACTUAL mount calls bash makes -- NOT a text grep of the
## source. A text grep cannot tell a comment / heredoc / continuation line from a
## live command, cannot resolve option order or the mount TARGET, and so
## green-lights insecure refactors; letting bash parse the script and inspecting
## the real calls closes that gap. It checks the SECURITY EFFECT (nosymfollow
## effective on the /mnt/shared vboxsf mount), so it is implementation-agnostic.
## The runtime effectiveness (a host symlink becomes ELOOP) is proven separately
## on a booted vbox guest; vboxsf cannot run under GitHub CI. The umount-peel
## resilience of the remount,bind design is likewise a runtime (guest) property.
##
## CANARY: a vbox branch that drops the remount (or its nosymfollow), passes
## nosymfollow to mount.vboxsf, inverts a flag, or targets a subdir, FAILS here.
##
## Runs headless as a normal user: `id -u` and every privileged command are
## stubbed, so nothing touches the real /mnt/shared.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
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

## mount-shared sources this at a hardcoded absolute path; it is a hard dependency
## of the vm-config-dist runtime, so its absence is an ENVIRONMENT bug, not a skip.
as_root_lib="/usr/libexec/helper-scripts/as_root.sh"
if [ ! -r "${as_root_lib}" ]; then
   printf '%s\n' "FATAL: ${as_root_lib} not found (helper-scripts dependency)" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/mount-shared-vbox-test.XXXXXX")"
test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap test_cleanup_handler EXIT

stub_dir="${work_dir}/bin"
calls_dir="${work_dir}/mountcalls"
mkdir --parents -- "${stub_dir}" "${calls_dir}"

## SC2016: the stub bodies below are LITERAL shell code written into files; the $
## must NOT expand here.
# shellcheck disable=SC2016
create_stubs() {
   local noop

   ## Recording stub: one file per mount invocation, one argv element per line, so
   ## multi-word and repeated options survive intact for last-wins analysis.
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' "calls_dir='${calls_dir}'"
      printf '%s\n' 'n="$(find "${calls_dir}" -maxdepth 1 -type f | wc -l)"'
      printf '%s\n' 'f="${calls_dir}/$(printf "%04d" "${n}")"'
      printf '%s\n' 'for a in "$@"; do printf "%s\n" "${a}"; done >"${f}"'
      printf '%s\n' 'exit 0'
   } >"${stub_dir}/mount"

   ## `id -u` must read 0 so mount-shared's as_root() does not die; delegate the
   ## rest to the real id.
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'if [ "${1:-}" = "-u" ]; then'
      printf '%s\n' '   printf "%s\n" 0'
      printf '%s\n' '   exit 0'
      printf '%s\n' 'fi'
      printf '%s\n' 'exec /usr/bin/id "$@"'
   } >"${stub_dir}/id"

   ## Group already exists (skip addgroup); users are NOT members (skip adduser);
   ## the vboxsf gid resolves to a fixed number.
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'case "${2:-}" in'
      printf '%s\n' '   is-group) exit 0 ;;'
      printf '%s\n' '   is-user) exit 1 ;;'
      printf '%s\n' '   get-entry) printf "%s\n" 990; exit 0 ;;'
      printf '%s\n' 'esac'
      printf '%s\n' 'exit 0'
   } >"${stub_dir}/accountctl"

   ## Privileged no-ops: never touch the real filesystem. mountpoint reports NOT
   ## mounted so the mkdir/chown/chmod setup path runs.
   for noop in cp chown chmod mkdir; do
      printf '%s\n' '#!/bin/bash' 'exit 0' >"${stub_dir}/${noop}"
   done
   printf '%s\n' '#!/bin/bash' 'exit 1' >"${stub_dir}/mountpoint"

   chmod +x "${stub_dir}"/*
}

create_stubs

## Run the REAL vbox branch; bash does all script parsing.
PATH="${stub_dir}:${PATH}" bash "${subject}" vbox >"${work_dir}/run.out" 2>&1 || true

pass_count=0
fail_count=0

assert() {
   local desc="$1"
   shift
   if "$@"; then
      printf '%s\n' "PASS: ${desc}"
      pass_count=$(( pass_count + 1 ))
   else
      printf '%s\n' "FAIL: ${desc}"
      fail_count=$(( fail_count + 1 ))
   fi
}

refute() {
   local desc="$1"
   shift
   if "$@"; then
      printf '%s\n' "FAIL: ${desc}"
      fail_count=$(( fail_count + 1 ))
   else
      printf '%s\n' "PASS: ${desc}"
      pass_count=$(( pass_count + 1 ))
   fi
}

## Concatenate every `-o` value of a recorded mount call (comma-joined), so a
## continuation-line `-o x` folds into the same call's option set.
collect_opts() {
   local -a a=( "$@" )
   local i opts=""
   for (( i = 0; i < ${#a[@]}; i++ )); do
      if [ "${a[i]}" = "-o" ] && [ $(( i + 1 )) -lt ${#a[@]} ]; then
         i=$(( i + 1 ))
         if [ -n "${opts}" ]; then
            opts="${opts},${a[i]}"
         else
            opts="${a[i]}"
         fi
      fi
   done
   printf '%s' "${opts}"
}

is_vboxsf() {
   local -a a=( "$@" )
   local i
   for (( i = 0; i + 1 < ${#a[@]}; i++ )); do
      if [ "${a[i]}" = "-t" ] && [ "${a[i+1]}" = "vboxsf" ]; then
         return 0
      fi
   done
   return 1
}

token_present() {
   local opts="$1" token="$2" tok
   local IFS=,
   for tok in ${opts}; do
      if [ "${tok}" = "${token}" ]; then
         return 0
      fi
   done
   return 1
}

## Effective state of a toggle flag under mount's last-option-wins rule: set only
## if its last mention is the flag, not its inverse.
flag_effective() {
   local opts="$1" flag="$2" inverse="$3" tok state="unset"
   local IFS=,
   for tok in ${opts}; do
      if [ "${tok}" = "${flag}" ]; then
         state="set"
      elif [ "${tok}" = "${inverse}" ]; then
         state="unset"
      fi
   done
   [ "${state}" = "set" ]
}

vbox_found=no
vbox_opts=""
remount_found=no
remount_opts=""

shopt -s nullglob
for call_file in "${calls_dir}"/*; do
   mapfile -t call_args <"${call_file}"
   [ "${#call_args[@]}" -gt 0 ] || continue
   target="${call_args[-1]}"
   opts="$(collect_opts "${call_args[@]}")"
   if is_vboxsf "${call_args[@]}" && [ "${target}" = /mnt/shared ]; then
      vbox_found=yes
      vbox_opts="${opts}"
   fi
   if [ "${target}" = /mnt/shared ] \
      && token_present "${opts}" remount \
      && token_present "${opts}" bind; then
      remount_found=yes
      remount_opts="${opts}"
   fi
done

## The vbox branch actually mounts vboxsf on /mnt/shared.
assert "vbox branch mounts vboxsf on /mnt/shared" \
   test "${vbox_found}" = yes

## nosymfollow must NOT reach mount.vboxsf -- it rejects the unknown option and the
## share would stay unmounted. (Catches a continuation-line -o nosymfollow too.)
refute "nosymfollow is NOT passed to mount.vboxsf (would unmount the share)" \
   token_present "${vbox_opts}" nosymfollow

## The vboxsf mount keeps its base hardening.
assert "vboxsf mount is effectively nosuid" flag_effective "${vbox_opts}" nosuid suid
assert "vboxsf mount is effectively nodev" flag_effective "${vbox_opts}" nodev dev
assert "vboxsf mount is effectively noexec" flag_effective "${vbox_opts}" noexec exec

## A remount,bind re-applies the flags to /mnt/shared itself (not a subdir).
assert "a remount,bind targets /mnt/shared" \
   test "${remount_found}" = yes

## CANARY: the remount makes nosymfollow effective -- dropping it, or inverting it
## with a later symfollow, FAILS here.
assert "remount makes nosymfollow effective on /mnt/shared" \
   flag_effective "${remount_opts}" nosymfollow symfollow

## The remount must also keep the other three effective (remount,bind resets any
## per-mount flag not restated).
assert "remount keeps nosuid effective" flag_effective "${remount_opts}" nosuid suid
assert "remount keeps nodev effective" flag_effective "${remount_opts}" nodev dev
assert "remount keeps noexec effective" flag_effective "${remount_opts}" noexec exec

printf '%s\n' "===== mount_shared_vbox_nosymfollow: ${pass_count} pass, ${fail_count} fail ====="
if [ "${fail_count}" -gt 0 ]; then
   printf '%s\n' "--- mount-shared output ---"
   cat -- "${work_dir}/run.out"
   printf '%s\n' "--- recorded mount calls ---"
   for call_file in "${calls_dir}"/*; do
      printf '%s\n' "$(basename -- "${call_file}"): $(tr '\n' ' ' <"${call_file}")"
   done
   exit 1
fi

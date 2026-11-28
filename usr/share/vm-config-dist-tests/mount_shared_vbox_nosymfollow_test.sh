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
## live command, cannot resolve option order, option FORM or the mount TARGET, and
## so green-lights insecure refactors; letting bash parse the script and
## inspecting the real calls closes that gap.
##
## It models the EFFECTIVE state: mount applies flags in order and the LAST mount
## (new mount or remount) that covers /mnt/shared sets the per-mount flag set path
## resolution sees, so the final such call is what the security assertions judge.
## Option forms `-o X`, `-oX`, `--options X`, `--options=X` are all collected, and
## a toggle flag is resolved last-wins (`symfollow` cancels `nosymfollow`). Exotic
## forms (fstab lookup, -O propagation, LIBMOUNT env) are out of scope -- the
## booted-guest test is the effectiveness proof; vboxsf cannot run under CI.
##
## CANARY: a vbox branch that drops the remount (or its nosymfollow), passes
## nosymfollow to mount.vboxsf, inverts a flag, targets a subdir, or re-mounts
## vboxsf over the hardened mount, FAILS here.
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
## must NOT expand here. The recording dir reaches the stub via the environment
## (MOUNT_CALLS_DIR), never interpolated into the body, so an odd ${TMP} cannot
## break or inject the stub.
# shellcheck disable=SC2016
create_stubs() {
   local noop

   ## Recording stub: one file per mount invocation, one argv element per line, so
   ## multi-word and repeated options survive intact for the option analysis.
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'n="$(find "${MOUNT_CALLS_DIR}" -maxdepth 1 -type f | wc -l)"'
      printf '%s\n' 'f="${MOUNT_CALLS_DIR}/$(printf "%04d" "${n}")"'
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
MOUNT_CALLS_DIR="${calls_dir}" PATH="${stub_dir}:${PATH}" \
   bash "${subject}" vbox >"${work_dir}/run.out" 2>&1 || true

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

## Parse a recorded mount call (one argv element per line) into globals:
##   CALL_TARGET     -- the mount target (last positional, trailing slash stripped)
##   CALL_OPTS       -- every option value, comma-joined, from -o / -oX /
##                      --options / --options= (so a continuation or long form
##                      folds into the same set)
##   CALL_IS_VBOXSF  -- yes if this call mounts the vboxsf filesystem
CALL_TARGET=""
CALL_OPTS=""
CALL_IS_VBOXSF="no"
parse_call() {
   local -a args=()
   mapfile -t args <"$1"
   CALL_TARGET=""
   CALL_OPTS=""
   CALL_IS_VBOXSF="no"
   local -a positional=()
   local i tok
   for (( i = 0; i < ${#args[@]}; i++ )); do
      tok="${args[i]}"
      case "${tok}" in
         -t)
            i=$(( i + 1 ))
            if [ "${args[i]:-}" = "vboxsf" ]; then
               CALL_IS_VBOXSF="yes"
            fi
            ;;
         -t*)
            if [ "${tok#-t}" = "vboxsf" ]; then
               CALL_IS_VBOXSF="yes"
            fi
            ;;
         -o|--options)
            i=$(( i + 1 ))
            if [ -n "${CALL_OPTS}" ]; then
               CALL_OPTS="${CALL_OPTS},${args[i]:-}"
            else
               CALL_OPTS="${args[i]:-}"
            fi
            ;;
         --options=*)
            if [ -n "${CALL_OPTS}" ]; then
               CALL_OPTS="${CALL_OPTS},${tok#--options=}"
            else
               CALL_OPTS="${tok#--options=}"
            fi
            ;;
         -o*)
            if [ -n "${CALL_OPTS}" ]; then
               CALL_OPTS="${CALL_OPTS},${tok#-o}"
            else
               CALL_OPTS="${tok#-o}"
            fi
            ;;
         -*)
            : ## other flags carry no per-mount security option
            ;;
         *)
            positional+=( "${tok}" )
            ;;
      esac
   done
   if [ "${#positional[@]}" -gt 0 ]; then
      CALL_TARGET="${positional[-1]}"
      while [ "${CALL_TARGET}" != "/" ] && [ "${CALL_TARGET%/}" != "${CALL_TARGET}" ]; do
         CALL_TARGET="${CALL_TARGET%/}"
      done
   fi
}

## Walk the recorded calls IN ORDER (the stub names them 0000, 0001, ...). The
## LAST call that targets /mnt/shared decides the effective per-mount flags.
final_seen="no"
final_opts=""
vboxsf_on_share="no"
vboxsf_opts=""
vboxsf_passed_nosymfollow="no"

shopt -s nullglob
for call_file in "${calls_dir}"/*; do
   parse_call "${call_file}"
   [ "${CALL_TARGET}" = "/mnt/shared" ] || continue
   final_seen="yes"
   final_opts="${CALL_OPTS}"
   if [ "${CALL_IS_VBOXSF}" = "yes" ]; then
      vboxsf_on_share="yes"
      vboxsf_opts="${CALL_OPTS}"
      if token_present "${CALL_OPTS}" nosymfollow; then
         vboxsf_passed_nosymfollow="yes"
      fi
   fi
done

## The vbox branch actually mounts vboxsf on /mnt/shared.
assert "vbox branch mounts vboxsf on /mnt/shared" \
   test "${vboxsf_on_share}" = "yes"

## nosymfollow must NOT reach mount.vboxsf -- it rejects the unknown option and the
## share would stay unmounted. (Catches -o / --options continuation forms too.)
refute "nosymfollow is NOT passed to mount.vboxsf (would unmount the share)" \
   test "${vboxsf_passed_nosymfollow}" = "yes"

## The vboxsf mount itself keeps the base hardening, so the best-effort degraded
## state (remount failed) is still nosuid,nodev,noexec.
assert "vboxsf mount is effectively nosuid" flag_effective "${vboxsf_opts}" nosuid suid
assert "vboxsf mount is effectively nodev" flag_effective "${vboxsf_opts}" nodev dev
assert "vboxsf mount is effectively noexec" flag_effective "${vboxsf_opts}" noexec exec

## A mount operation finalizes /mnt/shared (not a subdir, and not left with a
## trailing vboxsf mount over the hardened one).
assert "a mount operation finalizes /mnt/shared" \
   test "${final_seen}" = "yes"

## CANARY: the final /mnt/shared mount is effectively nosymfollow -- dropping it,
## inverting it with a later symfollow, or re-mounting vboxsf on top FAILS here.
assert "final /mnt/shared mount is effectively nosymfollow" \
   flag_effective "${final_opts}" nosymfollow symfollow

## The final mount must also keep the other three effective.
assert "final /mnt/shared mount is effectively nosuid" flag_effective "${final_opts}" nosuid suid
assert "final /mnt/shared mount is effectively nodev" flag_effective "${final_opts}" nodev dev
assert "final /mnt/shared mount is effectively noexec" flag_effective "${final_opts}" noexec exec

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

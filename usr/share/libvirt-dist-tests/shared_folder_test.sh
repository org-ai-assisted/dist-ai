#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai behaviour test for libvirt-dist's per-user setup (user-setup): it
## creates the host shared folder and attaches it to Whonix-Gateway and
## Whonix-Workstation. The security guarantees under test:
##   - the shared folder is $HOME/shared at mode 0700 (owner-private), NEVER a
##     world-writable dir and NEVER under world-traversable /mnt;
##   - it is attached with 9p accessmode='mapped' (guest ownership in host
##     xattrs, so no world/group permissions are needed);
##   - a re-run does not append a duplicate filesystem device (dup guard).
##
## Drives the REAL user-setup via qemu:///session (define/attach never open an
## image, so no VM images and no KVM are needed; user-setup rewrites 'kvm' ->
## 'qemu' itself when KVM is absent). qemu:///session auto-spawns a per-USER
## libvirtd, so it must NOT run as root; when invoked as root it re-execs via
## runuser as a throwaway unprivileged user.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Resolve the shipped user-setup: a checkout via LIBVIRT_DIST_REPO, else the
## installed package. user-setup honours LIBVIRT_DIST_REPO for its own XML too.
if [ -n "${LIBVIRT_DIST_REPO:-}" ] && [ -x "${LIBVIRT_DIST_REPO}/usr/libexec/libvirt-dist/user-setup" ]; then
   user_setup="${LIBVIRT_DIST_REPO}/usr/libexec/libvirt-dist/user-setup"
elif [ -x /usr/libexec/libvirt-dist/user-setup ]; then
   user_setup='/usr/libexec/libvirt-dist/user-setup'
else
   printf '%s\n' "SKIP: libvirt-dist user-setup not found (set LIBVIRT_DIST_REPO or install libvirt-dist)" >&2
   exit 77  ## style-ok: allow-skip: libvirt/qemu stack is an opt-in apt set, absent in the core lane
fi

## The libvirt/qemu stack is an opt-in apt set; a lane without it SKIPs (77),
## never fails. Self-contained -- sources no helper-scripts, so it detects tools
## with command -v rather than has():
## style-ok: no-has
missing=''
for cmd in virsh virt-xml qemu-img runuser safe-rm; do
   command -v "${cmd}" >/dev/null 2>&1 || missing="${missing} ${cmd}"
done
if [ -n "${missing}" ]; then
   printf '%s\n' "SKIP: missing required command(s):${missing}" >&2
   exit 77  ## style-ok: allow-skip: libvirt/qemu stack is an opt-in apt set, absent in the core lane
fi

## qemu:///session needs a non-root user; re-exec as a throwaway one when root.
if [ "$(id -u)" -eq 0 ]; then
   test_user='libvirtdisttest'
   if ! id -u "${test_user}" >/dev/null 2>&1; then
      adduser --disabled-password --gecos '' "${test_user}" >/dev/null 2>&1 \
         || { printf '%s\n' "SKIP: cannot create a non-root user for qemu:///session" >&2; exit 77; }  ## style-ok: allow-skip: qemu:///session needs a non-root user; unprivileged lane cannot create one
   fi
   runtime_dir="/run/user/$(id -u "${test_user}")"
   install -d -m 0700 -o "${test_user}" -g "${test_user}" "${runtime_dir}"
   reexec_rc=0
   runuser -u "${test_user}" -- env \
      LIBVIRT_DIST_REPO="${LIBVIRT_DIST_REPO:-}" \
      XDG_RUNTIME_DIR="${runtime_dir}" \
      "$(readlink --canonicalize -- "$0")" "$@" || reexec_rc="$?"
   exit "${reexec_rc}"
fi

## --- running as an unprivileged user with a session runtime dir ---

domain_list=(Whonix-Gateway Whonix-Workstation Kicksecure)
test_home=''
test_failures=0
pass_count=0

pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   test_failures=$(( test_failures + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

cleanup() {
   local vm
   for vm in "${domain_list[@]}"; do
      virsh -c qemu:///session undefine "${vm}" &>/dev/null || true
   done
   [ -z "${test_home}" ] || safe-rm --recursive --force -- "${test_home}"
}

## Count filesystem devices on a domain whose source dir is the shared folder.
shared_fs_count() {
   local vm="$1" dir="$2"
   virsh -c qemu:///session dumpxml --inactive "${vm}" \
      | grep --fixed-strings "dir='${dir}'" \
      | grep --count --fixed-strings 'source' || true
}

main() {
   local vm

   ## Refuse to touch a real Whonix / Kicksecure host's domains.
   for vm in "${domain_list[@]}"; do
      if virsh -c qemu:///session dominfo "${vm}" &>/dev/null; then
         printf '%s\n' "FAIL: refusing to overwrite existing qemu:///session domain '${vm}'" >&2
         exit 1
      fi
   done

   trap cleanup EXIT
   test_home="$(mktemp --directory)"
   local shared_dir="${test_home}/shared"

   ## Drive the real user-setup with an isolated HOME.
   HOME="${test_home}" XDG_STATE_HOME="${test_home}/.local/state" "${user_setup}"

   ## 1. Shared folder exists, is a directory, owner-private 0700.
   local mode
   if [ -d "${shared_dir}" ]; then
      mode="$(stat --format='%a' -- "${shared_dir}")"
      if [ "${mode}" = "700" ]; then
         pass "shared folder is ${shared_dir} at mode 0700"
      else
         fail "shared folder mode is ${mode}, want 700 (must not be world/group accessible)"
      fi
   else
      fail "shared folder ${shared_dir} was not created"
   fi

   ## 2. Not under /mnt (world-traversable); the former world-writable location.
   for vm in "${domain_list[@]}"; do
      local xml_mnt
      xml_mnt="$(virsh -c qemu:///session dumpxml --inactive "${vm}")"
      if grep --quiet --fixed-strings "dir='/mnt/" <<< "${xml_mnt}"; then
         fail "${vm} still references a /mnt shared folder"
      else
         pass "${vm} shared folder is not under /mnt"
      fi
   done

   ## 3. Attached once per domain, accessmode='mapped', source=$HOME/shared.
   for vm in "${domain_list[@]}"; do
      local xml count
      xml="$(virsh -c qemu:///session dumpxml --inactive "${vm}")"
      count="$(shared_fs_count "${vm}" "${shared_dir}")"
      if [ "${count}" = "1" ] \
         && grep --quiet --fixed-strings "accessmode='mapped'" <<< "${xml}"; then
         pass "${vm}: one mapped filesystem on ${shared_dir}"
      else
         fail "${vm}: want 1 mapped filesystem on ${shared_dir}, got count=${count}"
      fi
   done

   ## 4. Dup guard: a second run adds no duplicate filesystem device.
   HOME="${test_home}" XDG_STATE_HOME="${test_home}/.local/state" "${user_setup}"
   for vm in "${domain_list[@]}"; do
      local count
      count="$(shared_fs_count "${vm}" "${shared_dir}")"
      if [ "${count}" = "1" ]; then
         pass "${vm}: re-run did not duplicate the filesystem device"
      else
         fail "${vm}: re-run left ${count} filesystem device(s), want 1"
      fi
   done

   if [ "${test_failures}" -ne 0 ]; then
      printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
      exit 1
   fi
   printf '%s\n' "OK: shared-folder behaviour (${pass_count} assertions)."
}

main "$@"

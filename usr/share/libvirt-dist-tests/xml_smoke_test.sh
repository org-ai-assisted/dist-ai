#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai smoke test for libvirt-dist: assert that libvirt parses and accepts
## each shipped domain XML, and that a throwaway dir storage pool imports an
## image. Adapted from the package's former in-repo ci_test.
##
## define/undefine never opens a disk image (that only happens on domain start),
## so this runs with no VM images and where KVM is unavailable (CI / Qubes /
## nested virt). qemu:///session auto-spawns a per-USER libvirtd, so it must NOT
## run as root (root's session targets the systemd system socket, absent in a
## container); when invoked as root it re-execs itself via runuser.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## Resolve the component's shipped XML: a checkout via LIBVIRT_DIST_REPO, else
## the installed package.
if [ -n "${LIBVIRT_DIST_REPO:-}" ] && [ -d "${LIBVIRT_DIST_REPO}/usr/share/libvirt-dist/xml" ]; then
   xml_source_dir="${LIBVIRT_DIST_REPO}/usr/share/libvirt-dist/xml"
elif [ -d /usr/share/libvirt-dist/xml ]; then
   xml_source_dir='/usr/share/libvirt-dist/xml'
else
   printf '%s\n' "SKIP: libvirt-dist XML not found (set LIBVIRT_DIST_REPO or install libvirt-dist)" >&2
   exit 77
fi

## The libvirt/qemu stack is an opt-in apt set; a lane without it SKIPs (77),
## never fails. This suite is deliberately self-contained -- it sources no
## helper-scripts -- so it detects its tools with command -v rather than has():
## style-ok: no-has
missing=''
for cmd in virsh virt-xml-validate qemu-img runuser safe-rm; do
   command -v "${cmd}" >/dev/null 2>&1 || missing="${missing} ${cmd}"
done
if [ -n "${missing}" ]; then
   printf '%s\n' "SKIP: missing required command(s):${missing}" >&2
   exit 77
fi

## qemu:///session needs a non-root user; re-exec as a throwaway one when root.
if [ "$(id -u)" -eq 0 ]; then
   test_user='libvirtdisttest'
   if ! id -u "${test_user}" >/dev/null 2>&1; then
      adduser --disabled-password --gecos '' "${test_user}" >/dev/null 2>&1 \
         || { printf '%s\n' "SKIP: cannot create a non-root user for qemu:///session" >&2; exit 77; }
   fi
   runtime_dir="/run/user/$(id -u "${test_user}")"
   install -d -m 0700 -o "${test_user}" -g "${test_user}" "${runtime_dir}"
   reexec_rc=0
   runuser -u "${test_user}" -- env \
      LIBVIRT_DIST_REPO="${LIBVIRT_DIST_REPO:-}" \
      XDG_RUNTIME_DIR="${runtime_dir}" \
      HOME="/home/${test_user}" \
      "$(readlink --canonicalize -- "$0")" "$@" || reexec_rc="$?"
   exit "${reexec_rc}"
fi

## --- running as an unprivileged user with a session runtime dir ---

domain_list=(Whonix-Gateway Whonix-Workstation Whonix-Custom-Workstation Kicksecure)
test_pool='libvirt-dist-ci-test'
sep='------------------------------------------------------------'
work_dir=''
home_image=''

cleanup() {
   virsh -c qemu:///session pool-destroy "${test_pool}" &>/dev/null || true
   virsh -c qemu:///session pool-undefine "${test_pool}" &>/dev/null || true
   [ -z "${home_image}" ] || safe-rm --force -- "${home_image}"
   [ -z "${work_dir}" ] || safe-rm --recursive --force -- "${work_dir}"
}

## Literal (non-regex) replace of NEEDLE with REPL in a file. Pure bash, so the
## suite carries no helper-scripts dependency.
file_replace() {
   local needle="$1" repl="$2" file="$3" content
   content="$(cat -- "${file}")"
   printf '%s' "${content//"${needle}"/"${repl}"}" >"${file}"
}

main() {
   local vm pool_target image_name
   trap cleanup EXIT

   work_dir="$(mktemp --directory)"
   home_image="${work_dir}/import.qcow2"
   cp -r -- "${xml_source_dir}" "${work_dir}/xml"

   printf '%s\n' "${sep}"
   ## Without KVM (CI / nested virt) libvirt refuses domain type 'kvm'; since
   ## define/undefine never starts the VM, the 'qemu' type validates identically.
   if virsh -c qemu:///session capabilities | grep --quiet -- "<domain type='kvm'/\?>"; then
      printf '%s\n' "KVM available: testing the XML unmodified."
   else
      printf '%s\n' "KVM unavailable: rewriting domain type 'kvm' -> 'qemu'."
      for vm in "${domain_list[@]}"; do
         file_replace "<domain type='kvm'>" "<domain type='qemu'>" "${work_dir}/xml/${vm}.xml"
         file_replace "<cpu mode='host-passthrough'/>" "" "${work_dir}/xml/${vm}.xml"
      done
   fi

   printf '%s\n' "${sep}"
   for vm in "${domain_list[@]}"; do
      test -f "${work_dir}/xml/${vm}.xml"
   done

   printf '%s\n' "${sep}"
   ## Explicit 'domain' schema: autodetection is unreliable across libxml2. A
   ## schema violation must fail the test.
   for vm in "${domain_list[@]}"; do
      virt-xml-validate "${work_dir}/xml/${vm}.xml" domain
   done

   printf '%s\n' "${sep}"
   ## The assertion: libvirt accepts and registers each domain. Refuse to
   ## clobber a pre-existing domain (a real Whonix / Kicksecure host).
   for vm in "${domain_list[@]}"; do
      if virsh -c qemu:///session dominfo "${vm}" &>/dev/null; then
         printf '%s\n' "FAIL: refusing to overwrite existing qemu:///session domain '${vm}'" >&2
         exit 1
      fi
      virsh -c qemu:///session define "${work_dir}/xml/${vm}.xml"
      virsh -c qemu:///session undefine "${vm}"
   done

   printf '%s\n' "${sep}"
   ## Import a throwaway image into a dedicated dir pool under work_dir.
   pool_target="${work_dir}/pool"
   qemu-img create -f qcow2 "${home_image}" 4M >/dev/null
   image_name="$(basename -- "${home_image}")"
   virsh -c qemu:///session pool-create-as "${test_pool}" dir --target "${pool_target}" --build
   mv -- "${home_image}" "${pool_target}/"
   home_image=''
   virsh -c qemu:///session pool-refresh "${test_pool}"
   virsh -c qemu:///session vol-list "${test_pool}" \
      | grep --quiet --fixed-strings -- "${image_name}" \
      || { printf '%s\n' "FAIL: imported image not registered as a pool volume" >&2; exit 1; }

   printf '%s\n' "${sep}"
   printf '%s\n' "PASS: all libvirt-dist XML smoke checks passed."
}

main "$@"

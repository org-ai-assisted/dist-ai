#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Behavioural test for libvirt-dist's boot-time disk-mode flip scripts:
## live-mode-to-read-only and persistent-mode-to-read-write. They flip every
## VM's disk image between read-only and writable, and their design RECORDS a
## per-VM failure and keeps going (an ERR trap + accumulator) so one broken VM
## does not stop the rest -- which plain errexit would have broken. This test
## drives that guarantee with a virt-xml that fails, a missing image, a failing
## virsh, and a VM whose name is a substring of another, and asserts the exact
## exit status and the number of VMs actually touched.
##
## virsh, virt-xml, the images and the live-mode probe are all stubbed; nothing
## touches a real VM, no libvirt stack is needed, and it runs as any user.
##
## Self-contained (sources no helper-scripts): detects tools with command -v.
## style-ok: no-has

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Resolve the shipped scripts: a checkout via LIBVIRT_DIST_REPO, else the
## installed package.
if [ -n "${LIBVIRT_DIST_REPO:-}" ] && [ -d "${LIBVIRT_DIST_REPO}/usr/libexec/libvirt-dist" ]; then
   libexec_source="${LIBVIRT_DIST_REPO}/usr/libexec/libvirt-dist"
elif [ -d /usr/libexec/libvirt-dist ]; then
   libexec_source='/usr/libexec/libvirt-dist'
else
   printf '%s\n' "SKIP: libvirt-dist libexec not found (set LIBVIRT_DIST_REPO or install libvirt-dist)" >&2
   exit 77  ## style-ok: allow-skip: libvirt/qemu stack is an opt-in apt set, absent in the core lane
fi

for cmd in bash sed timeout grep safe-rm; do
   if ! command -v "${cmd}" >/dev/null 2>&1; then
      printf '%s\n' "FATAL: '${cmd}' missing; a hard requirement of this test." >&2
      exit 1
   fi
done

work_dir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

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

## prepare <root> <live> <vm-list> <virt-xml-exit> <images> <virsh-exit>
## Build an isolated sandbox: the shipped scripts with their helper-scripts and
## image paths redirected into <root>, plus stub virsh / virt-xml on PATH.
prepare() {
   local root live vm_list virt_xml_exit images virsh_exit
   root="$1"; live="$2"; vm_list="$3"; virt_xml_exit="$4"; images="$5"
   virsh_exit="${6:-0}"
   safe-rm --recursive --force -- "${root}"
   mkdir --parents -- "${root}/usr/libexec/helper-scripts" \
      "${root}/var/lib/libvirt/images" "${root}/stubs"
   cp --archive -- "${libexec_source}" "${root}/usr/libexec/libvirt-dist"

   printf '%s\n' "live_status_detected=${live}" \
      > "${root}/usr/libexec/helper-scripts/live-mode.sh"

   ## Real 'virsh list --all' is COLUMNAR (Id, Name, State); the scripts take the
   ## name with awk '{print $2}'. A single-column stub makes every name empty, so
   ## the loop never runs and cases pass while testing nothing -- the vms= count
   ## in each assertion exists to make that visible. A failing virsh must NOT look
   ## like "no VMs". The columnar table is a plain data file the stub cats, so no
   ## nested printf is emitted into the stub.
   {
      printf '%s\n' ' Id   Name                 State'
      printf '%s\n' '----------------------------------'
      local index name
      index=0
      for name in ${vm_list}; do
         index=$(( index + 1 ))
         printf '%s\n' " ${index}    ${name}   running"
      done
   } > "${root}/stubs/virsh.data"
   cat > "${root}/stubs/virsh" <<VIRSH_STUB
#!/bin/bash
cat -- '${root}/stubs/virsh.data'
exit ${virsh_exit}
VIRSH_STUB
   cat > "${root}/stubs/virt-xml" <<VIRTXML_STUB
#!/bin/bash
printf '%s\n' "STUB virt-xml \$*"
exit ${virt_xml_exit}
VIRTXML_STUB
   chmod 0755 -- "${root}/stubs/virsh" "${root}/stubs/virt-xml"

   local image
   for image in ${images}; do
      printf '%s\n' 'IMAGE' > "${root}/var/lib/libvirt/images/${image}.qcow2"
   done

   local script
   for script in "${root}"/usr/libexec/libvirt-dist/*; do
      sed --in-place \
         --expression='/^set -x$/d' \
         --expression="s|/usr/libexec/helper-scripts/|${root}/usr/libexec/helper-scripts/|g" \
         --expression="s|/var/lib/libvirt/images/|${root}/var/lib/libvirt/images/|g" \
         -- "${script}"
      chmod 0755 -- "${script}"
   done
}

## expect <description> <script> <live> <vm-list> <virt-xml-exit> <virsh-exit> \
##        <want-exit> <want-vms> <images>
## Run the shipped script in the sandbox and assert exit status + VMs touched.
expect() {
   local description script live vm_list virt_xml_exit virsh_exit want_exit want_vms images
   description="$1"; script="$2"; live="$3"; vm_list="$4"; virt_xml_exit="$5"
   virsh_exit="$6"; want_exit="$7"; want_vms="$8"; images="${9:-Whonix-Gateway Whonix-Workstation}"

   local root out status calls
   root="${work_dir}/run"
   prepare "${root}" "${live}" "${vm_list}" "${virt_xml_exit}" "${images}" "${virsh_exit}"
   status=0
   out="$(PATH="${root}/stubs:${PATH}" timeout --kill-after=15 15 \
      bash "${root}/usr/libexec/libvirt-dist/${script}" 2>&1)" || status="$?"
   ## VMs actually disk-edited -- the property the accumulator design guarantees.
   calls="$(printf '%s\n' "${out}" | grep --count 'STUB virt-xml' || true)"

   if [ "${status}" = "${want_exit}" ] && [ "${calls}" = "${want_vms}" ]; then
      pass "${description} (exit=${status} vms=${calls})"
   else
      fail "${description} -- wanted exit ${want_exit} / vms ${want_vms}, got exit ${status} / vms ${calls}"
      printf '%s\n' "--- output ---" >&2
      printf '%s\n' "${out}" | sed 's/^/    /' >&2
   fi
}

vms='Whonix-Gateway Whonix-Workstation'

## --- baseline record-and-continue behaviour --------------------------------
## The flip is a no-op unless the boot state matches (live for read-only,
## persistent for read-write), so the wrong state must touch zero VMs.
expect 'live-mode: not live does nothing' \
   live-mode-to-read-only false "${vms}" 0 0 0 0
expect 'live-mode: both VMs switched' \
   live-mode-to-read-only true "${vms}" 0 0 0 2
## The accumulator's whole point: a failing virt-xml still tries ALL VMs, then
## reports failure (exit 1), rather than stopping after the first.
expect 'live-mode: virt-xml fails, all VMs still tried' \
   live-mode-to-read-only true "${vms}" 1 0 1 2
expect 'live-mode: no VMs defined' \
   live-mode-to-read-only true '' 0 0 0 0

## Same guarantees for the read-write direction.
expect 'persistent-mode: is live does nothing' \
   persistent-mode-to-read-write true "${vms}" 0 0 0 0
expect 'persistent-mode: both VMs switched' \
   persistent-mode-to-read-write false "${vms}" 0 0 0 2
expect 'persistent-mode: virt-xml fails, all VMs still tried' \
   persistent-mode-to-read-write false "${vms}" 1 0 1 2

## --- security-relevant guarantees ------------------------------------------
## 'grep -v Name' once SUBSTRING-matched, so a VM called NameServer was silently
## dropped and left writable in live mode. Both VMs must now be switched.
expect 'a VM named NameServer is switched too' \
   live-mode-to-read-only true 'NameServer Whonix-Gateway' 0 0 0 2 'NameServer Whonix-Gateway'

## A failing virsh -- libvirtd down, or no permission -- must NOT look like "no
## VMs to switch". The old '|| true' let the script exit 0 having enforced
## nothing; it must now report the failure (exit 1). The security guarantee is
## that non-zero exit; the vms count is incidental (the stub still emits names).
expect 'virsh failure is reported, not swallowed (live)' \
   live-mode-to-read-only true "${vms}" 0 1 1 2
expect 'virsh failure is reported, not swallowed (persistent)' \
   persistent-mode-to-read-write false "${vms}" 0 1 1 2

## A not-installed VM image is SKIPPED (test -f guard), not counted as a chmod
## failure. With only Whonix-Workstation present, both VMs are still disk-edited
## and the missing Whonix-Gateway image does not force exit 1.
expect 'persistent-mode: missing image skipped, not a failure' \
   persistent-mode-to-read-write false "${vms}" 0 0 0 2 'Whonix-Workstation'

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: mode-flip behaviour (${pass_count} assertions)."

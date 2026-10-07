#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-guest-installer's find_latest_installed_kernel(): the chroot branch sets
## TARGET_VER from it, and fails closed if the result is empty.
##
## Its contract:
##   - globs /boot for 'vmlinuz-*' regular files (not config-*, initrd.img-*, ...);
##   - returns the FULL release (the 'vmlinuz-' basename minus the prefix:
##     '<version>-<abi>-<flavour>', i.e. the uname -r / /lib/modules/<release> name),
##     because vboxadd consumes it as TARGET_VER (/lib/modules/"${TARGET_VER}"/build);
##   - picks the version-sorted newest. No architecture filter.
## It takes NO argument -- its one call site (the chroot branch) passes none.
##
## /boot is bind-mounted from a fixture, so the result does not depend on which
## kernels the test host happens to have installed -- so newest-wins is decidable.
## The host arch is read at runtime only to name realistic fixtures.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v VM_CONFIG_DIST_REPO ] || VM_CONFIG_DIST_REPO=""

if [ -n "${VM_CONFIG_DIST_REPO}" ]; then
   subject="${VM_CONFIG_DIST_REPO}/usr/bin/vbox-guest-installer"
else
   subject='/usr/bin/vbox-guest-installer'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: vbox-guest-installer not found at '${subject}'" >&2
   printf '%s\n' "set VM_CONFIG_DIST_REPO to a checkout, or install the package" >&2
   exit 1
fi

if ! grep --quiet -- '^find_latest_installed_kernel() {' "${subject}"; then
   printf '%s\n' "FATAL: no find_latest_installed_kernel definition in '${subject}'" >&2
   printf '%s\n' "the extraction anchor no longer matches; this test would pass vacuously" >&2
   exit 1
fi

## Name fixtures with the host arch so they look like real installed kernels.
host_arch="$(dpkg --print-architecture)"

work_dir="$(mktemp --directory -- "${TMP}/vbox-newest-kernel-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the driver body is LITERAL code written into a file.
# shellcheck disable=SC2016
run_newest_kernel() {
   local base boot name

   base="${work_dir}/case"
   safe-rm --recursive --force -- "${base}"
   boot="${base}/boot"
   mkdir --parents -- "${boot}"
   for name in "$@"; do
      if [ -n "${name}" ]; then
         true >"${boot}/${name}"
      fi
   done

   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail' \
         'set -o errtrace' 'shopt -s inherit_errexit'
      sed -n '/^find_latest_installed_kernel() {/,/^}/p' "${subject}"
      printf '%s\n' 'result="$(find_latest_installed_kernel)"'
      printf '%s\n' 'printf "%s\n" "TARGET_VER=[${result}]"'
   } >"${base}/driver"

   bwrap --dev-bind / / --bind "${boot}" /boot \
      -- timeout 20 bash "${base}/driver" 2>&1 || true
}

## check <description> <expected TARGET_VER line> <boot file names...>
check() {
   local description want output verdict

   description="$1"
   want="$2"
   shift 2
   output="$(run_newest_kernel "$@")"

   verdict=PASS
   ## A refused bwrap means the driver never ran; every assertion would then be
   ## measuring nothing.
   if printf '%s\n' "${output}" | grep --extended-regexp -- '^bwrap:' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: the driver never ran"
   elif printf '%s\n' "${output}" | grep --fixed-strings -- 'unbound variable' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: nounset abort"
   elif ! printf '%s\n' "${output}" | grep --fixed-strings -- "${want}" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: expected '${want}'"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

## One kernel -- the real no-arg call site. Only the 'vmlinuz-' prefix is stripped;
## the full release (incl. the '-<flavour>' suffix) is what vboxadd needs.
check 'one kernel -- the real no-arg call site' "TARGET_VER=[6.1.0-13-${host_arch}]" \
   "vmlinuz-6.1.0-13-${host_arch}"
## Newest of three wins, by version-sort.
check 'three kernels: the newest wins' "TARGET_VER=[6.1.0-18-${host_arch}]" \
   "vmlinuz-6.1.0-13-${host_arch}" "vmlinuz-6.1.0-18-${host_arch}" \
   "vmlinuz-5.10.0-26-${host_arch}"
## The higher-versioned config-/initrd.img-/System.map- files must be ignored by
## the 'vmlinuz-' glob; only the vmlinuz entry counts.
check 'non-vmlinuz /boot entries are ignored' "TARGET_VER=[6.1.0-13-${host_arch}]" \
   "vmlinuz-6.1.0-13-${host_arch}" "config-9.9.9-9-${host_arch}" \
   "initrd.img-9.9.9-9-${host_arch}" "System.map-9.9.9-9-${host_arch}"
## No vmlinuz at all: an empty result, with no nounset abort on the empty array.
check 'no vmlinuz in /boot -- empty result' 'TARGET_VER=[]'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]

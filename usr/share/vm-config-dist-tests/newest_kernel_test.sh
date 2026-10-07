#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-guest-installer's find_latest_installed_kernel(): the chroot branch sets
## TARGET_VER from it, and fails closed if the result is empty.
##
## Its contract:
##   - globs /boot for 'vmlinuz-*' regular files;
##   - keeps only a release whose /lib/modules/<release> tree is installed (so a
##     backup name like vmlinuz-*.dpkg-bak, and any image with no buildable modules,
##     is skipped);
##   - returns the FULL release ('<version>-<abi>-<flavour>', the uname -r /
##     /lib/modules/<release> name) because vboxadd consumes it as TARGET_VER
##     (/lib/modules/"${TARGET_VER}"/build) -- flavour included, no arch filter;
##   - picks the newest by dpkg --compare-versions (correct for Debian ABI revisions
##     like +debN / +debN+M, which a plain version-sort gets wrong).
## It takes NO argument -- its one call site (the chroot branch) passes none.
##
## /boot and /lib/modules are bind-mounted from fixtures, so the result does not
## depend on the test host's installed kernels and newest-wins is decidable.
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

work_dir="$(mktemp --directory -- "${TMP}/vbox-newest-kernel-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## Each argument is 'K:<release>' (an installed kernel: a /boot/vmlinuz-<release>
## file AND a /lib/modules/<release> tree) or 'B:<name>' (a bare /boot/<name> with
## NO module tree -- a backup, a non-vmlinuz file, or a foreign-arch image).
## SC2016: the driver body is LITERAL code written into a file.
# shellcheck disable=SC2016
run_newest_kernel() {
   local base boot modules spec kind value

   base="${work_dir}/case"
   safe-rm --recursive --force -- "${base}"
   boot="${base}/boot"
   modules="${base}/modules"
   mkdir --parents -- "${boot}" "${modules}"
   for spec in "$@"; do
      kind="${spec%%:*}"
      value="${spec#*:}"
      case "${kind}" in
         K)
            true >"${boot}/vmlinuz-${value}"
            mkdir --parents -- "${modules}/${value}"
            ;;
         B)
            true >"${boot}/${value}"
            ;;
      esac
   done

   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail' \
         'set -o errtrace' 'shopt -s inherit_errexit'
      sed -n '/^find_latest_installed_kernel() {/,/^}/p' "${subject}"
      printf '%s\n' 'result="$(find_latest_installed_kernel)"'
      printf '%s\n' 'printf "%s\n" "TARGET_VER=[${result}]"'
   } >"${base}/driver"

   bwrap --dev-bind / / --bind "${boot}" /boot --bind "${modules}" /lib/modules \
      -- timeout 20 bash "${base}/driver" 2>&1 || true
}

## check <description> <expected TARGET_VER line> <K:/B: specs...>
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

## One installed kernel -- the real no-arg call site. The full release (flavour
## included) is returned, matching /lib/modules/<release>.
check 'one installed kernel' 'TARGET_VER=[6.1.0-13-amd64]' "K:6.1.0-13-amd64"
## Newest of three wins.
check 'newest installed kernel wins' 'TARGET_VER=[6.1.0-18-amd64]' \
   "K:6.1.0-13-amd64" "K:6.1.0-18-amd64" "K:5.10.0-26-amd64"
## Debian ABI-revision ordering: +deb13+1 is newer than +deb13 (a plain
## version-sort gets this backwards; dpkg --compare-versions does not).
check 'ABI +debN+M revision ordering' 'TARGET_VER=[6.12.74+deb13+1-amd64]' \
   "K:6.12.74+deb13-amd64" "K:6.12.74+deb13+1-amd64"
## A /boot backup name and non-vmlinuz files have no module tree -> ignored, even
## though they sort higher.
check 'backup and non-vmlinuz /boot entries ignored' 'TARGET_VER=[6.1.0-13-amd64]' \
   "K:6.1.0-13-amd64" "B:vmlinuz-9.9.9-9-amd64.dpkg-bak" \
   "B:config-9.9.9-9-amd64" "B:initrd.img-9.9.9-9-amd64"
## A foreign-arch vmlinuz has no installed module tree -> ignored.
check 'foreign-arch vmlinuz without a module tree ignored' 'TARGET_VER=[6.1.0-13-amd64]' \
   "K:6.1.0-13-amd64" "B:vmlinuz-9.9.9-9-arm64"
## A SAME-arch, valid-looking, higher-versioned vmlinuz with no module tree must
## also be skipped -- this pins the /lib/modules check specifically: a selector that
## instead filtered on the arch suffix or a backup extension would wrongly pick it.
check 'same-arch vmlinuz without a module tree ignored' 'TARGET_VER=[6.1.0-13-amd64]' \
   "K:6.1.0-13-amd64" "B:vmlinuz-9.9.9-9-amd64"
## No installed kernel -- empty result (the call site then fails closed).
check 'no installed kernel -- empty result' 'TARGET_VER=[]'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]

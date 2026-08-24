#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-guest-installer's _get_newest_kernel_debian(): it must work when
## called the way its ONE call site calls it.
##
## THE BUG: the function reads $1 on its first loop iteration, but its only
## caller -- the chroot branch -- passes no argument. Under nounset that
## aborted on the first /boot/config-* found, which is every run on a normal
## image build.
##
## /boot is bind-mounted from a fixture, so the result does not depend on which
## kernels the test host happens to have installed -- and so the
## newest-wins case is decidable at all.
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

if ! grep --quiet -- '^_get_newest_kernel_debian() {' "${subject}"; then
   printf '%s\n' "FATAL: no _get_newest_kernel_debian definition in '${subject}'" >&2
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

## SC2016: the driver body is LITERAL code written into a file.
# shellcheck disable=SC2016
run_newest_kernel() {
   local call_args base boot name

   call_args="$1"
   shift

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
      sed -n '/^_get_newest_kernel_debian() {/,/^}/p' "${subject}"
      printf '%s\n' "result=\"\$(_get_newest_kernel_debian ${call_args})\""
      printf '%s\n' 'printf "%s\n" "TARGET_VER=[${result}]"'
   } >"${base}/driver"

   bwrap --dev-bind / / --bind "${boot}" /boot \
      -- timeout 20 bash "${base}/driver" 2>&1 || true
}

## check <description> <expected TARGET_VER, or ''> <call args> <config names...>
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
      printf '%s\n' "FAIL: ${description}: nounset abort -- this is the bug"
   elif [ -n "${want}" ] \
      && ! printf '%s\n' "${output}" | grep --fixed-strings -- "${want}" >/dev/null; then
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

## The real call site passes NO argument. Both of these aborted.
check 'no argument, one kernel -- the real call site' 'TARGET_VER=[6.1.0-13-amd64]' \
   '' 'config-6.1.0-13-amd64'
check 'no argument, three kernels: the newest wins' 'TARGET_VER=[6.1.0-18-amd64]' \
   '' 'config-6.1.0-13-amd64' 'config-6.1.0-18-amd64' 'config-5.10.0-26-amd64'
## The argument form was never broken; asserted so the fix cannot be bought by
## ignoring the argument.
check 'an explicit argument still works' '' '0.0.0-0' 'config-6.1.0-13-amd64'
check 'no /boot/config-* at all' '' '0.0.0-0'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]

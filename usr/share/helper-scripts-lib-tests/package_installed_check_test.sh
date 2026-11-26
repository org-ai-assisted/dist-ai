#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: R-003 - 3-space indent matches the helper-scripts-lib-tests siblings.

## package_installed_check.sh: pkg_installed parses 'dpkg-query --showformat
## ${Status}' (want / error-flag / status). A fully installed package reports
## status 'installed'; the want field is 'install' normally and 'hold' when the
## package is version-pinned. A held package IS installed, so pkg_installed must
## accept 'hold ok installed' -- requiring want=install reported a held package
## as missing, so callers would try to reinstall a package that is present.
##
## Sources the real package_installed_check.sh and stubs dpkg-query on PATH to
## feed a chosen Status string. No root, no network, no dpkg database read.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/package_installed_check.sh"
else
   subject='/usr/libexec/helper-scripts/package_installed_check.sh'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: package_installed_check.sh not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

## shellcheck resolves the file statically from dist-ai's own tree, which has no
## helper-scripts copy, so there is nothing to point 'source=' at.
# shellcheck disable=SC1090,SC1091
source "${subject}"

if [ ! "$(type -t pkg_installed)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' defined no 'pkg_installed' function" >&2
   exit 1
fi

## dpkg-query stub: echo the Status fed via STUB_STATUS, ignore all args. An
## empty STUB_STATUS models an unknown package (dpkg-query prints nothing).
stub_dir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${stub_dir}"
}
trap cleanup EXIT
cat > "${stub_dir}/dpkg-query" <<'STUB'
#!/bin/sh
printf '%s' "${STUB_STATUS}"
STUB
chmod +x -- "${stub_dir}/dpkg-query"
export PATH="${stub_dir}:${PATH}"
export STUB_STATUS=""

pass_count=0
fail_count=0

## $1 label, $2 Status string fed to the stub, $3 expected rc (0 installed).
check_status() {
   local rc=0
   export STUB_STATUS="$2"
   pkg_installed pkgname >/dev/null 2>&1 || rc=$?
   if [ "${rc}" = "$3" ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: $1 (Status='$2' -> rc ${rc})"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: $1 (Status='$2' -> rc ${rc}, want $3)"
   fi
}

check_status "normal install is installed"        'install ok installed'        0
check_status "held package is installed"          'hold ok installed'           0
check_status "half-configured is not installed"   'install ok half-configured'  1
check_status "deinstall-pending is not installed" 'deinstall ok installed'      1
check_status "reinst-required flag is not ok"     'install reinstreq installed' 1
check_status "unknown package is not installed"   ''                            1

## CANARY: the held-package case is the regression the fix closes. A version
## requiring want=install reports 'hold ok installed' as missing (rc 1).
export STUB_STATUS='hold ok installed'
if pkg_installed pkgname >/dev/null 2>&1; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: canary: held package accepted (a want=install-only check would reject it)"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: canary: held package rejected -- pkg_installed requires want=install again"
fi

printf '%s\n' ""
printf '%s\n' "===== package_installed_check: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]

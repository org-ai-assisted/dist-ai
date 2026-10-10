#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## rebuild-dkms-modules rebuilds + reinstalls every INSTALLED DKMS module (so the
## per-machine MOK signs them). Drives the REAL source-able script (the `sourceable`
## skill): sourcing defines rebuild_dkms_modules WITHOUT running it; the top-level
## log/has/as_root sources come along. The external 'dkms' is stubbed and the root
## check is a no-op.
##
## Covered: an 'installed' status line is rebuilt+reinstalled; a non-'installed'
## line is skipped (canary: 'dkms build' is NOT invoked for it); empty status hits
## the 'nothing to do' branch.
##
## A missing subject/dep is an ENVIRONMENT BUG -> exit 1 (FATAL), never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/sbin/rebuild-dkms-modules"
   export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
else
   subject='/usr/sbin/rebuild-dkms-modules'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

## Drift-guard: the summary lines this test keys on.
for sentinel in \
   'No DKMS modules to rebuild, ok.' \
   'Done rebuilding DKMS modules.'; do
   if ! grep --quiet --fixed-strings -- "${sentinel}" "${subject}"; then
      printf '%s\n' "FATAL: sentinel '${sentinel}' not found in '${subject}'; it drifted -- update this test." >&2
      exit 1
   fi
done

# shellcheck disable=SC1090,SC1091
source "${subject}"
if [ "$(type -t rebuild_dkms_modules)" != 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' defined no 'rebuild_dkms_modules' function" >&2
   exit 1
fi
if ! has safe-rm; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi
## Not root in the test: the root check is stubbed to a no-op.
as_root() { :; }

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

bindir="${work}/bin"
build_sentinel="${work}/dkms.build.invoked"
install_sentinel="${work}/dkms.install.invoked"
mkdir --parents -- "${bindir}"

## dkms stub: 'status' prints a controlled listing; 'build'/'install' RECORD THEIR
## FULL ARGV so a test can assert the subject parsed the right module + kernel. The
## real script parses dkms 3.x 'name/version, kernel, arch: status' lines.
cat > "${bindir}/dkms" <<'STUB'
#!/bin/bash
case "${1:-}" in
   status)
      if [ -n "${DKMS_STATUS_OUTPUT:-}" ]; then
         printf '%s\n' "${DKMS_STATUS_OUTPUT}"
      fi
      ;;
   build)   printf '%s\n' "$*" > "${DKMS_BUILD_SENTINEL:-/dev/null}" 2>/dev/null || true ;;
   install) printf '%s\n' "$*" > "${DKMS_INSTALL_SENTINEL:-/dev/null}" 2>/dev/null || true ;;
esac
exit 0
STUB
chmod +x -- "${bindir}/dkms"
export PATH="${bindir}:${PATH}"
export DKMS_BUILD_SENTINEL="${build_sentinel}"
export DKMS_INSTALL_SENTINEL="${install_sentinel}"

pass=0
fail=0
check() {
   local label="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: ${label}"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
   fi
}
contains() {
   case "$1" in
      *"$2"*)
         printf '%s' "yes"
         ;;
      *)
         printf '%s' "no"
         ;;
   esac
}

reset_state() {
   safe-rm --force -- "${build_sentinel}" "${install_sentinel}"
}

## --- an 'installed' module is rebuilt + reinstalled -------------------------
## Realistic dkms 3.x status line ('name/version, kernel, arch: status').
reset_state
export DKMS_STATUS_OUTPUT='tirdad/1.0, 6.1.0-18-amd64, x86_64: installed'
out="$(rebuild_dkms_modules 2>&1)"
built='no'
[ -e "${build_sentinel}" ] && built='yes'
installed='no'
[ -e "${install_sentinel}" ] && installed='yes'
build_cmd=''
[ -e "${build_sentinel}" ] && build_cmd="$(cat -- "${build_sentinel}")"
check "installed module -> dkms build invoked"   "${built}"     "yes"
check "installed module -> dkms install invoked" "${installed}" "yes"
check "installed module -> build targets the real kernel" "$(contains "${build_cmd}" '-k 6.1.0-18-amd64')" "yes"
check "installed module -> 'Done rebuilding'"    "$(contains "${out}" 'Done rebuilding DKMS modules.')" "yes"

## --- a non-'installed' module is skipped (canary: no build) -----------------
reset_state
export DKMS_STATUS_OUTPUT='tirdad/1.0, 6.1.0-18-amd64, x86_64: added'
out="$(rebuild_dkms_modules 2>&1)"
built='no'
[ -e "${build_sentinel}" ] && built='yes'
check "canary: non-installed module -> dkms build NOT invoked" "${built}" "no"
check "non-installed module -> 'No DKMS modules to rebuild'"   "$(contains "${out}" 'No DKMS modules to rebuild, ok.')" "yes"

## --- empty status -> nothing-to-do branch -----------------------------------
reset_state
export DKMS_STATUS_OUTPUT=''
rc=0
out="$(rebuild_dkms_modules 2>&1)" || rc=$?
check "empty status -> rc 0"                       "${rc}" "0"
check "empty status -> 'No DKMS modules to rebuild'" "$(contains "${out}" 'No DKMS modules to rebuild, ok.')" "yes"

printf '%s\n' ""
printf '%s\n' "===== rebuild_dkms_modules: ${pass} pass, ${fail} fail, 0 skip ====="
[ "${fail}" -eq 0 ]

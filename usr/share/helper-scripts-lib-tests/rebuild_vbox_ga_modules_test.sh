#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## rebuild-vbox-ga-modules rebuilds + MOK-signs the Oracle VirtualBox Guest
## Additions kernel modules via 'rcvboxadd setup' (they are NOT DKMS, so
## rebuild-dkms-modules does not reach them). Drives the REAL source-able script
## (the `sourceable` skill): sourcing defines rebuild_vbox_ga_modules WITHOUT
## running it; the test requires the real log/has and stubs the root check and
## the external 'rcvboxadd'.
##
## Covered: GA not installed ('rcvboxadd' absent) is a no-op success and does NOT
## invoke 'rcvboxadd setup'; GA present + setup success -> rc 0; canary: setup
## failure -> rc 1.
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
   subject="${HELPER_SCRIPTS_REPO}/usr/sbin/rebuild-vbox-ga-modules"
   libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
   export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
else
   subject='/usr/sbin/rebuild-vbox-ga-modules'
   libdir='/usr/libexec/helper-scripts'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
for lib in log_run_die.sh as_root.sh has.bsh; do
   if [ ! -r "${libdir}/${lib}" ]; then
      printf '%s\n' "FATAL: helper-scripts lib '${lib}' not readable under '${libdir}'" >&2
      exit 1
   fi
done

## Drift-guard: the three user-facing verdicts.
for sentinel in \
   'nothing to rebuild or sign, ok.' \
   'Successfully rebuilt + signed VirtualBox Guest Additions' \
   'may be unsigned and fail to load under Secure Boot'; do
   if ! grep --quiet --fixed-strings -- "${sentinel}" "${subject}"; then
      printf '%s\n' "FATAL: sentinel '${sentinel}' not found in '${subject}'; it drifted -- update this test." >&2
      exit 1
   fi
done

## Sentinel-variant source-able form: sourcing does NOT pull in log/has/as_root, so
## the test provides the REAL log/has and a no-op root check.
# shellcheck disable=SC1090,SC1091
source "${libdir}/as_root.sh"
# shellcheck disable=SC1090,SC1091
source "${libdir}/has.bsh"
# shellcheck disable=SC1090,SC1091
source "${subject}"
if [ "$(type -t rebuild_vbox_ga_modules)" != 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' defined no 'rebuild_vbox_ga_modules' function" >&2
   exit 1
fi
if ! has safe-rm; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi
## Not root in the test: the root check is stubbed to a no-op.
as_root() { :; }

base_path="${PATH}"
work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

bindir="${work}/bin"
## A controlled EMPTY bindir is the ONLY PATH entry for the GA-absent case, so
## 'has rcvboxadd' is false regardless of whether the host has the real tool -- the
## suite must run on a VirtualBox guest too. log/log_run resolve stecho via
## HELPER_SCRIPTS_PATH (absolute), not PATH, so an empty PATH is fine here.
empty_bin="${work}/empty-bin"
setup_sentinel="${work}/rcvboxadd.setup.invoked"
mkdir --parents -- "${bindir}" "${empty_bin}"

cat > "${bindir}/rcvboxadd" <<'STUB'
#!/bin/bash
if [ "${1:-}" = 'setup' ]; then
   printf '%s\n' invoked > "${RCVBOXADD_SENTINEL:-/dev/null}" 2>/dev/null || true
   if [ "${RCVBOXADD_MODE:-ok}" = 'fail' ]; then
      exit 1
   fi
fi
exit 0
STUB
chmod +x -- "${bindir}/rcvboxadd"
export RCVBOXADD_SENTINEL="${setup_sentinel}"

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
         printf 'yes'
         ;;
      *)
         printf 'no'
         ;;
   esac
}

## $1 = 'present'|'absent'. Echoes 'rc\n<output>'. 'present' prepends the stub dir.
run_vbox() {
   local rc=0 out path
   safe-rm --force -- "${setup_sentinel}"
   if [ "$1" = 'present' ]; then
      path="${bindir}:${base_path}"
   else
      path="${empty_bin}"
   fi
   out="$(PATH="${path}" rebuild_vbox_ga_modules 2>&1)" || rc=$?
   printf '%s\n%s' "${rc}" "${out}"
}

## --- GA not installed -> no-op success, 'rcvboxadd setup' NOT invoked -------
export RCVBOXADD_MODE='ok'
res="$(run_vbox absent)"
rc="${res%%$'\n'*}"
out="${res#*$'\n'}"
invoked='no'
[ -e "${setup_sentinel}" ] && invoked='yes'
check "GA absent -> rc 0"                       "${rc}"      "0"
check "GA absent -> 'nothing to rebuild or sign'" "$(contains "${out}" 'nothing to rebuild or sign, ok.')" "yes"
check "GA absent -> 'rcvboxadd setup' NOT invoked" "${invoked}" "no"

## --- GA present + setup succeeds -> rc 0, setup invoked ---------------------
export RCVBOXADD_MODE='ok'
res="$(run_vbox present)"
rc="${res%%$'\n'*}"
out="${res#*$'\n'}"
invoked='no'
[ -e "${setup_sentinel}" ] && invoked='yes'
check "GA present + setup ok -> rc 0"                "${rc}"      "0"
check "GA present + setup ok -> 'rcvboxadd setup' invoked" "${invoked}" "yes"
check "GA present + setup ok -> 'Successfully rebuilt + signed'" "$(contains "${out}" 'Successfully rebuilt + signed VirtualBox Guest Additions')" "yes"

## --- CANARY: setup failure -> rc 1 ------------------------------------------
## Only the stub's exit flips here; a 1 proves the failure branch is live (a
## dropped result-check would report success).
export RCVBOXADD_MODE='fail'
res="$(run_vbox present)"
rc="${res%%$'\n'*}"
out="${res#*$'\n'}"
check "canary: GA present + setup fails -> rc 1" "${rc}" "1"
check "canary: setup failure -> 'may be unsigned'" "$(contains "${out}" 'may be unsigned and fail to load under Secure Boot')" "yes"

printf '%s\n' ""
printf '%s\n' "===== rebuild_vbox_ga_modules: ${pass} pass, ${fail} fail, 0 skip ====="
[ "${fail}" -eq 0 ]

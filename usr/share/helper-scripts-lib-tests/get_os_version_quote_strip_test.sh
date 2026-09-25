#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## get_os.sh: /etc/os-release VERSION_ID / VERSION_CODENAME are quoted (Debian 13
## ships VERSION_ID="13"). get_os() must strip the surrounding quotes for
## distro_version / distro_codename as it does for distro (PRETTY_NAME). In a
## fresh cowbuilder chroot there is no lsb_release, so the os-release fallback runs
## and an unstripped distro_version '"13"' (quotes intact) makes the is_integer
## version check die 101 before any build (the --dry-run VirtualBox failure).
## This drives the REAL get_os against a fixture os-release, forcing the fallback
## branch, and asserts the quotes are stripped (13, not "13") with no die 101.
##
## Sources the INSTALLED helper-scripts by default; HELPER_SCRIPTS_REPO points it at
## a checkout, which is what the suite runner wires in CI. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

## get_os.sh sources its siblings (has.bsh, log_run_die.sh, ...) via
## "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/...; point that at the same checkout so
## the code under test -- not an installed copy -- is what runs.
HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
export HELPER_SCRIPTS_PATH

hs_base="${HELPER_SCRIPTS_PATH:-}"
strings_bsh_path="${hs_base}/usr/libexec/helper-scripts/strings.bsh"
get_os_path="${hs_base}/usr/libexec/helper-scripts/get_os.sh"

for lib_path in "${strings_bsh_path}" "${get_os_path}"; do
   if [ ! -r "${lib_path}" ]; then
      printf '%s\n' "FATAL: helper-scripts library not readable: '${lib_path}'" >&2
      printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
      exit 1
   fi
done

## is_integer (get_os's version check) lives in strings.bsh, which get_os.sh does
## not source itself -- the real caller does. Provide it, then get_os.sh.
# shellcheck disable=SC1090,SC1091
source "${strings_bsh_path}"
# shellcheck disable=SC1090,SC1091
source "${get_os_path}"

if [ ! "$(type -t get_os)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${get_os_path}' defined no 'get_os' function" >&2
   exit 1
fi

## Force the os-release fallback branch: with lsb_release "absent" (has -> false),
## get_os parses os_release_file -- exactly the cowbuilder-chroot code path.
has() {
   return 1
}

test_dir="$(mktemp --directory)"
test_cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}
trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## Run the REAL get_os against a fixture os-release, echoing the parsed
## version|codename. Command substitution runs a subshell, so a die 101 (old code)
## exits it with 101 and prints nothing; the fixed code prints the stripped values
## and exits 0.
run_get_os() {
   local fixture="$1"
   os_release_file="${fixture}" get_os >/dev/null 2>&1
   ## distro_version / distro_codename are globals get_os assigns.
   # shellcheck disable=SC2154
   printf '%s|%s' "${distro_version}" "${distro_codename}"
}

check_parses() {
   local desc="$1" fixture="$2" want_version="$3" want_codename="$4"
   local seen rc=0 got_version got_codename
   ## A die 101 (old code) makes the subshell exit non-zero; capture that without
   ## toggling errexit.
   seen="$(run_get_os "${fixture}")" || rc=$?
   got_version="${seen%%|*}"
   got_codename="${seen#*|}"
   if [ "${rc}" -eq 0 ] \
      && [ "${got_version}" = "${want_version}" ] \
      && [ "${got_codename}" = "${want_codename}" ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${desc}: version='${got_version}' codename='${got_codename}', no die"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${desc}: rc=${rc} version='${got_version}' codename='${got_codename}', wanted version='${want_version}' codename='${want_codename}' rc 0"
   fi
}

## --- fixtures --------------------------------------------------------------
quoted_release="${test_dir}/os-release.quoted"
printf '%s\n' \
   'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"' \
   'VERSION_ID="13"' \
   'VERSION_CODENAME="trixie"' \
   > "${quoted_release}"

unquoted_release="${test_dir}/os-release.unquoted"
printf '%s\n' \
   'PRETTY_NAME=Debian' \
   'VERSION_ID=12' \
   'VERSION_CODENAME=bookworm' \
   > "${unquoted_release}"

## --- assertions ------------------------------------------------------------
## The regression: quoted Debian 13 os-release must yield a bare integer version.
check_parses 'quoted Debian 13 os-release' "${quoted_release}" '13' 'trixie'
## A no-op on already-unquoted values (guards against over-stripping).
check_parses 'unquoted os-release passes through' "${unquoted_release}" '12' 'bookworm'

## --- CANARY: this is exactly the failure the fix closes ---------------------
## Against the pre-fix get_os.sh, the quoted fixture leaves distro_version as '"13"',
## which is_integer rejects -> die 101 -> run_get_os's subshell exits 101 and prints
## nothing, so the first assertion FAILS. If both assertions pass, the quote strip is
## in place for distro_version AND distro_codename.
if [ "${fail_count}" -eq 0 ]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: canary: quoted os-release no longer dies 101 (pre-fix get_os would here)"
else
   printf '%s\n' "FAIL: canary: quoted os-release still mishandled -- distro_version quote strip missing"
fi

printf '%s\n' ""
printf '%s\n' "===== get_os version quote strip: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]

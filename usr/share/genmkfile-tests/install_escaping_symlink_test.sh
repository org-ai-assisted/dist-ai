#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 'genmkfile install' rsyncs the source tree with '--safe-links', which SILENTLY DROPS a
## symlink pointing outside the copied tree (absolute, or via '..'). The install loop then
## 'stat's every source entry at its destination; for a dropped symlink the destination does
## not exist, so 'stat' aborts under 'set -o errexit' with a cryptic error. make_helper must
## instead FAIL LOUD with a clear packaging-bug message, and SKIP a legitimately dangling
## in-tree symlink rather than stat-crash on it. This drives the REAL make_helper.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

locate_helper() {
   local candidate from_bin=''
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      from_bin="$(dirname -- "$(dirname -- "${GENMKFILE_BIN}")")/share/genmkfile/make-helper-one.bsh"
   fi
   for candidate in \
      "${GENMKFILE_SHARE:-}/make-helper-one.bsh" \
      "${from_bin}" \
      "${HOME:-}/derivative-maker/packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh" \
      "/usr/share/genmkfile/make-helper-one.bsh"
   do
      [ -n "${candidate}" ] || continue
      case "${candidate}" in
         '/make-helper-one.bsh' )
            continue
            ;;
      esac
      if test -r "${candidate}"; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

if ! helper_file="$(locate_helper)"; then
   printf '%s\n' 'FATAL: make-helper-one.bsh not found (set GENMKFILE_SHARE).' >&2
   exit 1
fi
if ! type -P rsync >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: rsync is required.' >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() {
   safe-rm -r -f -- "${work}"
}
trap cleanup EXIT

## Extract the real make_helper; stub only the reporting/guard helpers.
{
   printf '%s\n' 'die() { printf "DIE: %s\n" "$2" >&2; exit "$1"; }'
   printf '%s\n' 'make_require() { :; }'
   printf '%s\n' 'make_output_info() { :; }'
   printf '%s\n' 'make_output_warn() { :; }'
   printf '%s\n' 'in_array() { return 1; }'
   sed -n '/^make_helper()/,/^}/p' -- "${helper_file}"
} > "${work}/fn.sh"
if ! grep --quiet '^make_helper()' "${work}/fn.sh"; then
   printf '%s\n' 'ERROR: could not extract make_helper.' >&2
   exit 1
fi
# shellcheck disable=SC1091
source "${work}/fn.sh"

shopt -s globstar nullglob

tests_total=0
tests_failed=0

## make_helper globs "${PWD}/${source_directory}"/** with globstar.
run_install() {
   local pkg="$1" dest="$2"
   mkdir --parents -- "${dest}"
   local make_install_='true' make_installsim_='false' make_uninstall_='false'
   local make_installcheck_='false' make_uninstallcheck_='false'
   local DESTDIR="${dest}"
   local make_folder_list_for_un_and_install=(usr)
   ( cd -- "${pkg}" && make_helper ) 2>&1
}

## Case 1: an ABSOLUTE (escaping) symlink -> --safe-links drops it -> must die with the
## clear "refusing to install: symlink ... A symlink pointing outside the copied tree" message,
## NOT a raw 'stat' error.
pkg1="${work}/pkg1"
mkdir --parents -- "${pkg1}/usr/bin"
printf 'x\n' > "${pkg1}/usr/bin/realfile"
ln -s /etc/hostname "${pkg1}/usr/bin/escaping"
out1=''
rc1=0
out1="$(run_install "${pkg1}" "${work}/dest1")" || rc1=$?
tests_total=$(( tests_total + 1 ))
if [ "${rc1}" -ne 0 ] && [[ "${out1}" == *'refusing to install: symlink'* ]]; then
   printf '%s\n' "PASS  escaping symlink -> clear die (not a stat crash)"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  escaping symlink: rc=${rc1} out=[${out1}]" >&2
fi

## Case 2: a legitimately DANGLING in-tree relative symlink -> rsync copies it (safe), and the
## install must SKIP it (the destination target is absent) rather than stat-crash.
pkg2="${work}/pkg2"
mkdir --parents -- "${pkg2}/usr/bin"
printf 'x\n' > "${pkg2}/usr/bin/realfile"
ln -s does-not-exist-in-tree "${pkg2}/usr/bin/danglink"
out2=''
rc2=0
out2="$(run_install "${pkg2}" "${work}/dest2")" || rc2=$?
tests_total=$(( tests_total + 1 ))
if [ "${rc2}" -eq 0 ]; then
   printf '%s\n' "PASS  dangling in-tree symlink -> installed + skipped, no crash"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  dangling in-tree symlink: rc=${rc2} out=[${out2}]" >&2
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "install_escaping_symlink_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "install_escaping_symlink_test: ${tests_total} pass, 0 fail, 0 skip"

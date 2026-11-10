#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 'genmkfile install' rsyncs the source tree with '--safe-links', which SILENTLY DROPS a
## symlink pointing outside the copied tree (absolute, or via '..'). The install loop then
## 'stat's every source entry at its destination; for a dropped symlink the destination does
## not exist, so 'stat' aborts under 'set -o errexit' with a cryptic error. make_helper must
## instead emit a NON-FATAL warning (Kicksecure/Whonix package repos carry no raw symlinks,
## and a fatal error could damage the installed system) and SKIP a legitimately dangling
## in-tree symlink rather than stat-crash on it. This drives the REAL make_helper.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Shared genmkfile library discovery + checkout capability gate (sibling suites
## source the same helper, so they cannot drift to different subjects/skips).
_common_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/../dist-ai-tests-common"
[ -r "${_common_dir}/genmkfile-locate.bash" ] || _common_dir="/usr/share/dist-ai-tests-common"
# shellcheck source=../dist-ai-tests-common/genmkfile-locate.bash
source "${_common_dir}/genmkfile-locate.bash"
genmkfile_require_helper
# shellcheck disable=SC2154  ## set by genmkfile_require_helper in the sourced helper
helper_file="${genmkfile_helper_file}"
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

## Source the REAL helper WHOLE (sourced-only lib, was_executed-gated), so make_helper and
## the real path_is_within_any (folder_permission_skip_list check) /
## genmkfile_install_path_excluded (build-residue skip, backed by the
## genmkfile_install_exclude_patterns array) it reaches are defined without running the CLI.
## A single-function sed cut silently drifts the moment the subject gains an intra-file
## dependency -- the extract-a-function anti-pattern dist-ai's CLAUDE.md forbids. The
## reporting/guard stubs below are defined AFTER the source so they override the helper's
## own, leaving the real mode-fix path to run.
# shellcheck disable=SC1090
source "${helper_file}"
if ! declare -F make_helper >/dev/null \
   || ! declare -F path_is_within_any >/dev/null \
   || ! declare -F genmkfile_install_path_excluded >/dev/null; then
   printf '%s\n' 'ERROR: make_helper + path_is_within_any + genmkfile_install_path_excluded not defined after sourcing the helper.' >&2
   exit 1
fi
# shellcheck disable=SC2317
exit_with_error() { printf '%s\n' "DIE: $2" >&2; exit "$1"; }
# shellcheck disable=SC2317
make_require() { :; }
# shellcheck disable=SC2317
make_output_info() { :; }
# shellcheck disable=SC2317
make_output_warn() { printf '%s\n' "WARN: $1" >&2; }
# shellcheck disable=SC2317
in_array() { return 1; }

shopt -s globstar nullglob

tests_total=0
tests_failed=0

## make_helper globs "${PWD}/${source_directory}"/** with globstar.
run_install() {
   local pkg="$1" dest="$2"
   mkdir --parents -- "${dest}"
   # shellcheck disable=SC2034  # make_install_/make_installsim_/make_uninstall_: genmkfile config inputs consumed by make_helper
   local make_install_='true' make_installsim_='false' make_uninstall_='false'
   # shellcheck disable=SC2034  # make_installcheck_/make_uninstallcheck_: genmkfile config inputs consumed by make_helper
   local make_installcheck_='false' make_uninstallcheck_='false'
   # shellcheck disable=SC2034  # DESTDIR: genmkfile config input consumed by make_helper
   local DESTDIR="${dest}"
   # shellcheck disable=SC2034  # make_folder_list_for_un_and_install: genmkfile config input consumed by make_helper
   local make_folder_list_for_un_and_install=(usr)
   ( cd -- "${pkg}" && make_helper ) 2>&1
}

## Case 1: an ABSOLUTE (escaping) symlink -> --safe-links drops it -> make_helper must emit
## the non-fatal "symlink ... was not installed" warning and continue (rc 0), NOT crash on a
## raw 'stat' of the missing destination.
pkg1="${work}/pkg1"
mkdir --parents -- "${pkg1}/usr/bin"
printf '%s\n' "x" > "${pkg1}/usr/bin/realfile"
ln -s /etc/hostname "${pkg1}/usr/bin/escaping"
out1=''
rc1=0
out1="$(run_install "${pkg1}" "${work}/dest1")" || rc1=$?
tests_total=$(( tests_total + 1 ))
if [ "${rc1}" -eq 0 ] \
   && [[ "${out1}" == *'was not installed'* ]] \
   && [ ! -L "${work}/dest1/usr/bin/escaping" ]; then
   printf '%s\n' "PASS  escaping symlink -> non-fatal warn, left uninstalled (no stat crash)"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  escaping symlink: rc=${rc1} out=[${out1}]" >&2
fi

## Case 2: a legitimately DANGLING in-tree relative symlink -> rsync copies it (safe), and the
## install must SKIP it (the destination target is absent) rather than stat-crash.
pkg2="${work}/pkg2"
mkdir --parents -- "${pkg2}/usr/bin"
printf '%s\n' "x" > "${pkg2}/usr/bin/realfile"
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

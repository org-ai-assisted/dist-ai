#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_deb_chl_bumpup (major, version_numbers_by_upstream=true) computes the new Debian
## revision with 'bc'. bc treats a NON-numeric token as an undefined variable equal to 0 and
## exits 0 with no error text, so a non-integer revision -- e.g. a changelog version '1.0-rc1'
## whose revision is 'rc1' -- silently computed new_revision=1 and bumped to '1.0-1', DROPPING
## the qualifier, while the '*error*' guard never fired: a silent, misleading version commit.
## The fix validates the revision is a plain integer before bc and fails loud otherwise.
## This drives the REAL function (sourced; its main is was_executed-guarded) with the external
## commands stubbed, and asserts: a non-integer revision ABORTS with a clear message and never
## reaches debchange; a plain-integer (and an empty) revision still bumps correctly.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck disable=SC2317
error_handler() {
   local exit_code="$?"
   printf '%s\n' "ERROR: exit_code: ${exit_code} | BASH_COMMAND: ${BASH_COMMAND}"
   exit 1
}
trap error_handler ERR

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

## Capability gate: this suite tests the genmkfile CHECKOUT (wired via GENMKFILE_BIN or
## GENMKFILE_SHARE). If nothing was wired and only the installed /usr/share/genmkfile helper
## resolved -- which drifts from the tree under review -- SKIP rather than report a confusing
## FAIL against a possibly-stale subject nobody is changing.
if [ -z "${GENMKFILE_SHARE:-}" ] && [ -z "${GENMKFILE_BIN:-}" ] \
   && [ "${helper_file}" = "/usr/share/genmkfile/make-helper-one.bsh" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi
if ! type -P bc >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: bc is required.' >&2
   exit 1
fi

GENMKFILE_PATH="$(dirname -- "${helper_file}")"
export GENMKFILE_PATH
## style-ok: allow-sc1091-disable -- helper_file is located at runtime, unfollowable
# shellcheck disable=SC1090,SC1091
source "${helper_file}"

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}
trap cleanup_handler EXIT

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }
fail() { tests_failed=$(( tests_failed + 1 )); printf '%s\n' "FAIL  $1" >&2; }

## Drive the REAL make_deb_chl_bumpup with the external commands stubbed. Records the
## '--newversion' argument debchange would receive, and any exit_with_error message, to files
## (the run is a subshell so a stubbed exit_with_error cannot end the test). $1 is the value of
## make_pkg_revision (carries its leading '-', as make_parse_changelog_version produces).
run_bump() {
   local rev="$1"
   true > "${test_root}/newversion"
   true > "${test_root}/die"
   (
      # shellcheck disable=SC2317
      make_require() { :; }
      # shellcheck disable=SC2317
      deb_variables_check() { :; }
      # shellcheck disable=SC2317
      make_output_info() { :; }
      # shellcheck disable=SC2317
      make_log_and_run() {
         if [ "${1:-}" = 'debchange' ] && [ "${2:-}" = '--newversion' ]; then
            printf '%s\n' "${3:-}" >> "${test_root}/newversion"
         fi
      }
      # shellcheck disable=SC2317
      exit_with_error() {
         printf '%s' "${2:-}" > "${test_root}/die"
         exit "${1:-1}"
      }
      make_bump_type='major'
      version_numbers_by_upstream='true'
      make_epoch=''
      make_pkg_version='1.0'
      make_pkg_revision="${rev}"
      make_changelog_version="1.0${rev}"
      DEBEMAIL='test@example.com'
      DEBFULLNAME='Test'
      make_deb_chl_bumpup
   ) >/dev/null 2>&1 || true
}

## 1. A non-integer revision ('-rc1') must ABORT with a clear message and never reach debchange.
run_bump '-rc1'
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
new_ver="$(cat -- "${test_root}/newversion")"
if [ -z "${new_ver}" ] && [[ "${die_msg}" == *'not a plain integer'* ]]; then
   pass "non-integer revision 'rc1' aborts loud, never bumps (msg: no debchange call)"
else
   fail "non-integer revision NOT rejected: die=[${die_msg}] newversion=[${new_ver}]"
fi

## 2. A plain-integer revision ('-1') still bumps correctly ('1.0' + rev 1 -> '1.0-2').
run_bump '-1'
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
new_ver="$(cat -- "${test_root}/newversion")"
if [ -z "${die_msg}" ] && [ "${new_ver}" = '1.0-2' ]; then
   pass "integer revision '1' bumps to '1.0-2' (not aborted, not silently wrong)"
else
   fail "integer revision mis-bumped: die=[${die_msg}] newversion=[${new_ver}] (want 1.0-2)"
fi

## 3. An empty revision (no revision at all) still bumps to '-1', not aborted by the guard.
run_bump ''
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
new_ver="$(cat -- "${test_root}/newversion")"
if [ -z "${die_msg}" ] && [ "${new_ver}" = '1.0-1' ]; then
   pass "empty revision bumps to '1.0-1' (guard does not over-reject)"
else
   fail "empty revision mis-bumped: die=[${die_msg}] newversion=[${new_ver}] (want 1.0-1)"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "chl_bumpup_revision_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "chl_bumpup_revision_test: ${tests_total} pass, 0 fail, 0 skip"

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_uch writes changelog.upstream as a tiny REUSE-headered pointer: two SPDX header
## lines plus the single sentence "See git history for full changelog." -- git history is
## the changelog, so the file must never grow into a per-commit dump. The SPDX email is the
## per-package maintainer address derived from debian/control (kicksecure package ->
## kicksecure.com, whonix package -> whonix.org). Drives the REAL make_uch (sourced; its
## main is was_executed-guarded) in throwaway dirs and asserts: the file carries the SPDX
## header with the correct per-package email, is exactly the one sentence, has zero git-log
## residue (no "commit <sha>" / "Author:" / "Date:" lines), and the CHANGES guard still
## short-circuits without writing the file.

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

## Shared genmkfile library discovery + checkout capability gate (sibling suites
## source the same helper, so they cannot drift to different subjects/skips).
_common_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/../dist-ai-tests-common"
[ -r "${_common_dir}/genmkfile-locate.bash" ] || _common_dir="/usr/share/dist-ai-tests-common"
# shellcheck source=../dist-ai-tests-common/genmkfile-locate.bash
source "${_common_dir}/genmkfile-locate.bash"
genmkfile_require_helper
# shellcheck disable=SC2154  ## set by genmkfile_require_helper in the sourced helper
helper_file="${genmkfile_helper_file}"

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

## Create a throwaway package dir carrying a minimal debian/control whose Source-stanza
## Maintainer holds the given address.
make_pkg_dir() {
   local dir="$1" maint_email="$2"
   mkdir --parents -- "${dir}/debian"
   printf '%s\n' \
      "Source: testpkg" \
      "Maintainer: Patrick Schleizer <${maint_email}>" \
      > "${dir}/debian/control"
}

## Drive the REAL make_uch in a throwaway working directory, with DEBEMAIL unset so the
## email is DERIVED from debian/control (the behaviour under test), not inherited.
run_uch() {
   local dir="$1"
   (
      unset DEBEMAIL DEBFULLNAME
      cd -- "${dir}"
      make_uch
   ) >/dev/null 2>&1
}

## Assert the generated changelog.upstream is EXACTLY the per-package REUSE header plus the
## single pointer sentence. A whole-file compare (not a per-pattern grep) so ANY extra line
## -- indented, comment-prefixed, or a git-log dump -- fails instead of slipping past.
assert_changelog() {
   local label="$1" chl="$2" want_email="$3" expected actual
   tests_total=$(( tests_total + 1 ))
   if [ ! -f "${chl}" ]; then
      fail "${label}: changelog.upstream not created"
      return
   fi
   expected="$(printf '%s\n' \
      "## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${want_email}>" \
      "## SPDX-License-Identifier: AGPL-3.0-or-later" \
      "" \
      "See git history for full changelog.")"
   actual="$(cat -- "${chl}")"
   if [ "${actual}" = "${expected}" ]; then
      pass "${label}: changelog.upstream is exactly the REUSE header <${want_email}> + pointer"
   else
      fail "${label}: changelog.upstream content mismatch"
      printf '%s\n' "--- expected ---" "${expected}" "--- actual ---" >&2
      cat -- "${chl}" >&2
      printf '%s\n' "------------" >&2
   fi
}

## 1. A kicksecure package: the header email is derived as the kicksecure address.
work_ks="${test_root}/pkg_ks"
make_pkg_dir "${work_ks}" "adrelanos@kicksecure.com"
run_uch "${work_ks}"
assert_changelog "kicksecure package" "${work_ks}/changelog.upstream" "adrelanos@kicksecure.com"

## 2. A whonix package: the header email is derived as the whonix address.
work_wh="${test_root}/pkg_wh"
make_pkg_dir "${work_wh}" "adrelanos@whonix.org"
run_uch "${work_wh}"
assert_changelog "whonix package" "${work_wh}/changelog.upstream" "adrelanos@whonix.org"

## 3. The CHANGES guard still short-circuits: no changelog.upstream is written.
work_changes="${test_root}/pkg_changes"
make_pkg_dir "${work_changes}" "adrelanos@kicksecure.com"
printf '%s\n' 'hand-written changes' > "${work_changes}/CHANGES"
run_uch "${work_changes}"
tests_total=$(( tests_total + 1 ))
if [ -f "${work_changes}/changelog.upstream" ]; then
   fail "CHANGES present but changelog.upstream still written (guard broken)"
else
   pass "CHANGES guard short-circuits: changelog.upstream not written"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "uch_changelog_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "uch_changelog_test: ${tests_total} pass, 0 fail, 0 skip"

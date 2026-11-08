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

## Capability gate: test the genmkfile CHECKOUT (wired via GENMKFILE_BIN or GENMKFILE_SHARE).
## If only the installed /usr/share/genmkfile helper resolved -- which drifts from the tree
## under review -- SKIP rather than FAIL against a possibly-stale subject nobody is changing.
if [ -z "${GENMKFILE_SHARE:-}" ] && [ -z "${GENMKFILE_BIN:-}" ] \
   && [ "${helper_file}" = "/usr/share/genmkfile/make-helper-one.bsh" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
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

## Assert the generated changelog.upstream: SPDX header with the expected per-package email,
## the license tag, exactly the one pointer sentence, and zero git-log residue.
assert_changelog() {
   local label="$1" chl="$2" want_email="$3"
   local header_ok='no' license_ok='no' sentence_ok='no' residue='no' sentence_count=0
   tests_total=$(( tests_total + 1 ))
   if [ ! -f "${chl}" ]; then
      fail "${label}: changelog.upstream not created"
      return
   fi
   grep --quiet --fixed-strings -- "## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${want_email}>" "${chl}" && header_ok='yes'
   grep --quiet --fixed-strings -- '## SPDX-License-Identifier: AGPL-3.0-or-later' "${chl}" && license_ok='yes'
   grep --quiet --fixed-strings --line-regexp -- 'See git history for full changelog.' "${chl}" && sentence_ok='yes'
   ## Zero git-log residue: no 'commit <sha>' / 'Author:' / 'Date:' lines.
   if grep --quiet --extended-regexp -- '^(commit [0-9a-f]|Author:|Date:)' "${chl}"; then
      residue='yes'
   fi
   ## Exactly one non-header, non-blank content line: "1 sentence only".
   sentence_count="$(grep --count --extended-regexp -- '^[^#[:space:]]' "${chl}" || true)"
   if [ "${header_ok}" = 'yes' ] && [ "${license_ok}" = 'yes' ] \
      && [ "${sentence_ok}" = 'yes' ] && [ "${residue}" = 'no' ] \
      && [ "${sentence_count}" -eq 1 ]; then
      pass "${label}: SPDX header <${want_email}> + one sentence, no git-log dump"
   else
      fail "${label}: wrong header=${header_ok} license=${license_ok} sentence=${sentence_ok} residue=${residue} content_lines=${sentence_count}"
      printf '%s\n' "--- file ---" >&2
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

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_uch writes changelog.upstream as a tiny REUSE-headered pointer: two SPDX header
## lines plus the single sentence "See git history for full changelog." -- git history is
## the changelog, so the file must never grow into a per-commit dump. Drives the REAL
## make_uch (sourced; its main is was_executed-guarded) in a throwaway dir and asserts: the
## file is created, carries the SPDX header, is exactly the one sentence, has zero git-log
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

## Drive the REAL make_uch in a throwaway working directory.
run_uch() {
   local dir="$1"
   (
      cd -- "${dir}"
      make_uch
   ) >/dev/null 2>&1
}

## 1. A clean dir: the file is created with the SPDX header and the single pointer sentence.
work_one="${test_root}/pkg_one"
mkdir --parents -- "${work_one}"
run_uch "${work_one}"
tests_total=$(( tests_total + 1 ))
chl="${work_one}/changelog.upstream"
if [ ! -f "${chl}" ]; then
   fail "changelog.upstream not created"
else
   header_ok='no'; license_ok='no'; sentence_ok='no'; residue='no'; sentence_count=0
   grep --quiet --fixed-strings -- '## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>' "${chl}" && header_ok='yes'
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
      pass "changelog.upstream: SPDX header + one sentence, no git-log dump"
   else
      fail "changelog.upstream wrong: header=${header_ok} license=${license_ok} sentence=${sentence_ok} residue=${residue} content_lines=${sentence_count}"
      printf '%s\n' "--- file ---" >&2
      cat -- "${chl}" >&2
      printf '%s\n' "------------" >&2
   fi
fi

## 2. The CHANGES guard still short-circuits: no changelog.upstream is written.
work_two="${test_root}/pkg_two"
mkdir --parents -- "${work_two}"
printf '%s\n' 'hand-written changes' > "${work_two}/CHANGES"
run_uch "${work_two}"
tests_total=$(( tests_total + 1 ))
if [ -f "${work_two}/changelog.upstream" ]; then
   fail "CHANGES present but changelog.upstream still written (guard broken)"
else
   pass "CHANGES guard short-circuits: changelog.upstream not written"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "uch_changelog_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "uch_changelog_test: ${tests_total} pass, 0 fail, 0 skip"

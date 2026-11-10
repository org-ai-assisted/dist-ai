#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for test_manpages_regen_before_version_bump_gate.sh's base_indent
## hardening: drive the REAL gate against crafted dm-packaging-helper-script
## fixtures and assert it REFUSES the evasion the looser form passed:
##   - base_indent taken from the gate line let an all-three-in-one-conditional
##     pass (regens nested beside the gate read as 'unconditional'). Deriving the
##     base indent from the first body STATEMENT (skipping blank/comment lines)
##     closes it, and a column-0 comment must not skew it.
## Per-commit pathspec scoping is NOT a gate concern: a text scan of a bash line
## for a real ' -- <pathspec>' reinvents a parser and false-passes on comments /
## -m messages, so the gate drops it; the scoping is covered behaviourally by
## test_pkg_git_manpages_pathspec_abort.sh (drives the real git_commit_pathspecs
## against throwaway repos).
## Fixtures are built with printf (not a heredoc) so the shell-scanning style gate
## does not read the fixture bodies as this test's own code.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
gate="${test_dir}/test_manpages_regen_before_version_bump_gate.sh"
if [ ! -r "${gate}" ]; then
   printf '%s\n' "FATAL: gate under test not found: ${gate}" >&2
   exit 1
fi

workdir="$(mktemp --directory --tmpdir manpages-gate-evasion.XXXXXX)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got ${got}, want ${want})"
      fail=$((fail + 1))
   fi
}

## Run the REAL gate against FIXTURE; emit 'pass' (exit 0) or 'fail' (nonzero).
run_gate() {
   local fixture="$1" rc=0
   DM_PACKAGING_HELPER_SCRIPT="${fixture}" bash -- "${gate}" >/dev/null 2>&1 || rc="$?"
   if [ "${rc}" -eq 0 ]; then
      printf '%s' "pass"
   else
      printf '%s' "fail"
   fi
}

## A well-formed helper: regens called unconditionally at the function base indent
## before the gate, each commit pathspec-scoped on its own line. The gate accepts it.
ok_fixture="${workdir}/helper-ok"
printf '%s\n' \
   '#!/bin/bash' \
   'pkg_git_manpages() {' \
   '   git commit -m "regen man" -- "man" "auto-generated-man-pages"' \
   '}' \
   'pkg_git_debinstfile() {' \
   '   git commit -m "regen install" -- "debian/x.install"' \
   '}' \
   'pkg_need_version_bump_and_pkg_build_and_reprepro_add() {' \
   '   pkg_git_manpages' \
   '   pkg_git_debinstfile' \
   '   pkg_need_version_bump_show' \
   '}' \
   > "${ok_fixture}"
check "well-formed helper is accepted" "$(run_gate "${ok_fixture}")" 'pass'

## Evasion 1: all three nested in one conditional. The gate call is indented
## deeper than the function base, so a base_indent taken from the gate line would
## match the nested regens as 'unconditional'. Deriving base_indent from the first
## body line ('   if ...') makes the deeper regens fail the base-indent match.
nested_fixture="${workdir}/helper-nested"
printf '%s\n' \
   '#!/bin/bash' \
   'pkg_git_manpages() {' \
   '   git commit -m "regen man" -- "man" "auto-generated-man-pages"' \
   '}' \
   'pkg_git_debinstfile() {' \
   '   git commit -m "regen install" -- "debian/x.install"' \
   '}' \
   'pkg_need_version_bump_and_pkg_build_and_reprepro_add() {' \
   '   if true; then' \
   '      pkg_git_manpages' \
   '      pkg_git_debinstfile' \
   '      pkg_need_version_bump_show' \
   '   fi' \
   '}' \
   > "${nested_fixture}"
check "regens nested beside the gate are refused" "$(run_gate "${nested_fixture}")" 'fail'

## Evasion 2: a column-0 comment as the first body line must NOT become the
## measured base indent (the gate still accepts the well-formed regens below it).
comment_fixture="${workdir}/helper-comment-base"
printf '%s\n' \
   '#!/bin/bash' \
   'pkg_git_manpages() {' \
   '   git commit -m "regen man" -- "man" "auto-generated-man-pages"' \
   '}' \
   'pkg_git_debinstfile() {' \
   '   git commit -m "regen install" -- "debian/x.install"' \
   '}' \
   'pkg_need_version_bump_and_pkg_build_and_reprepro_add() {' \
   '# a column-0 comment must not skew the measured base indent' \
   '   pkg_git_manpages' \
   '   pkg_git_debinstfile' \
   '   pkg_need_version_bump_show' \
   '}' \
   > "${comment_fixture}"
check "a column-0 comment does not skew base_indent" "$(run_gate "${comment_fixture}")" 'pass'

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"

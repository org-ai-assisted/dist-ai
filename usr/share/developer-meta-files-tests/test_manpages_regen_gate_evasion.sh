#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for test_manpages_regen_before_version_bump_gate.sh's own hardening:
## drive the REAL gate against crafted dm-packaging-helper-script fixtures and
## assert it now REFUSES two evasions the looser form passed:
##   - base_indent taken from the gate line let an all-three-in-one-conditional
##     pass (regens nested beside the gate read as 'unconditional').
##   - a whole-body ' -- ' glob let a bare 'git commit -m' pass as long as some
##     other line carried ' -- '.
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
      printf 'PASS: %s\n' "${label}"
      pass=$((pass + 1))
   else
      printf 'FAIL: %s (got %s, want %s)\n' "${label}" "${got}" "${want}"
      fail=$((fail + 1))
   fi
}

## Run the REAL gate against FIXTURE; emit 'pass' (exit 0) or 'fail' (nonzero).
run_gate() {
   local fixture="$1" rc=0
   DM_PACKAGING_HELPER_SCRIPT="${fixture}" bash -- "${gate}" >/dev/null 2>&1 || rc="$?"
   if [ "${rc}" -eq 0 ]; then
      printf pass
   else
      printf fail
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

## Evasion 1 (#5): all three nested in one conditional. The gate call is indented
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

## Evasion 2 (#6): pkg_git_manpages commits WITHOUT a pathspec; a later line carries
## ' -- '. The whole-body glob passed on that stray ' -- '; the per-command check
## sees the 'git commit' line has none and refuses.
unscoped_fixture="${workdir}/helper-unscoped"
printf '%s\n' \
   '#!/bin/bash' \
   'pkg_git_manpages() {' \
   '   git commit -m "regen man"' \
   '   printf "%s\n" "done -- really"' \
   '}' \
   'pkg_git_debinstfile() {' \
   '   git commit -m "regen install" -- "debian/x.install"' \
   '}' \
   'pkg_need_version_bump_and_pkg_build_and_reprepro_add() {' \
   '   pkg_git_manpages' \
   '   pkg_git_debinstfile' \
   '   pkg_need_version_bump_show' \
   '}' \
   > "${unscoped_fixture}"
check "a bare commit with a stray later ' -- ' is refused" "$(run_gate "${unscoped_fixture}")" 'fail'

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"

#!/bin/bash

## Copyright (C) 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_strip_build_residue removes python tooling caches from the source tree
## before packaging. It runs inside a build harness, so a bug here does not
## fail loudly -- it ships a package with files missing. The test therefore
## asserts BOTH directions: residue is removed, and everything else survives.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

error_handler() {
   local exit_code="$?"
   printf '%s\n' "ERROR: exit_code: ${exit_code} | BASH_COMMAND: ${BASH_COMMAND}"
   exit 1
}

trap error_handler ERR

## Subject selection mirrors the rest of this suite (first that exists):
##   $GENMKFILE_SHARE -> the derivative-maker submodule checkout -> the installed
##   /usr/share/genmkfile. Checkout BEFORE installed: the installed copy drifts from
##   the tree under review, so preferring it tests code nobody is changing. Absent means SKIP (77), not failure.
locate_helper() {
   local candidate
   for candidate in \
      "${GENMKFILE_SHARE:-}/make-helper-one.bsh" \
      "${HOME}/derivative-maker/packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh" \
      "/usr/share/genmkfile/make-helper-one.bsh"
   do
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
   printf '%s\n' 'SKIP: make-helper-one.bsh not found (set GENMKFILE_SHARE).' >&2
   exit 77
fi

test_root="$(mktemp --directory)"

cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}

trap cleanup_handler EXIT

tests_total=0
tests_failed=0

check_absent() {
   local label="$1" path="$2"
   tests_total=$(( tests_total + 1 ))
   if test -e "${path}" ; then
      printf '%s\n' "FAIL: ${label}: '${path}' still exists"
      tests_failed=$(( tests_failed + 1 ))
   else
      printf '%s\n' "PASS: ${label}"
   fi
}

check_present() {
   local label="$1" path="$2"
   tests_total=$(( tests_total + 1 ))
   if test -e "${path}" ; then
      printf '%s\n' "PASS: ${label}"
   else
      printf '%s\n' "FAIL: ${label}: '${path}' was removed but must survive"
      tests_failed=$(( tests_failed + 1 ))
   fi
}

## Minimal stubs for the harness helpers the function calls, so the real
## function body runs without pulling in the whole build system.
make_require() {
   true
}

make_output_info() {
   printf '%s\n' "info: $*"
}

## Extract only the function under test from the real file, so the test cannot
## silently drift from a reimplementation of it.
sed -n '/^make_strip_build_residue()/,/^}/p' -- "${helper_file}" \
   > "${test_root}/function_under_test.sh"

if ! test -s "${test_root}/function_under_test.sh" ; then
   printf '%s\n' "ERROR: could not extract make_strip_build_residue." >&2
   exit 1
fi

## Generated above by sed, so there is no in-tree path for shellcheck to
## follow; SC1091 rather than a source= directive pointing at a file that does
## not exist until runtime.
# shellcheck disable=SC1091
source "${test_root}/function_under_test.sh"

## Build a source tree carrying residue at several depths, plus files that
## must survive -- including names that merely resemble the residue names.
mkdir --parents -- \
   "${test_root}/tree/usr/lib/python3/dist-packages/pkg/.mypy_cache/3.13" \
   "${test_root}/tree/usr/lib/python3/dist-packages/pkg/__pycache__" \
   "${test_root}/tree/.hypothesis" \
   "${test_root}/tree/usr/lib/python3/dist-packages/pkg/.pytest_cache" \
   "${test_root}/tree/.git/objects" \
   "${test_root}/tree/.git/__pycache__" \
   "${test_root}/tree/usr/share/mypy_cache_docs" \
   "${test_root}/tree/debian"

printf '%s\n' "junk" > "${test_root}/tree/usr/lib/python3/dist-packages/pkg/.mypy_cache/3.13/x.json"
printf '%s\n' "junk" > "${test_root}/tree/usr/lib/python3/dist-packages/pkg/__pycache__/x.pyc"
printf '%s\n' "junk" > "${test_root}/tree/.hypothesis/x.db"
printf '%s\n' "junk" > "${test_root}/tree/usr/lib/python3/dist-packages/pkg/.pytest_cache/x.json"
printf '%s\n' "real" > "${test_root}/tree/usr/lib/python3/dist-packages/pkg/module.py"
printf '%s\n' "real" > "${test_root}/tree/usr/share/mypy_cache_docs/readme.txt"
printf '%s\n' "real" > "${test_root}/tree/.git/objects/deadbeef"
## A residue-NAMED directory inside .git. Without the -prune this is deleted,
## which is what makes the .git assertion below able to fail at all. A plain
## file there proves nothing: find only matches the residue names.
printf '%s\n' "real" > "${test_root}/tree/.git/__pycache__/x.pyc"

cd -- "${test_root}/tree"
make_strip_build_residue

check_absent "nested .mypy_cache removed" \
   "${test_root}/tree/usr/lib/python3/dist-packages/pkg/.mypy_cache"
check_absent "__pycache__ removed" \
   "${test_root}/tree/usr/lib/python3/dist-packages/pkg/__pycache__"
check_absent ".hypothesis removed" \
   "${test_root}/tree/.hypothesis"
check_absent ".pytest_cache removed" \
   "${test_root}/tree/usr/lib/python3/dist-packages/pkg/.pytest_cache"

## The other direction, which is what makes a deletion bug visible.
check_present "real source file survives" \
   "${test_root}/tree/usr/lib/python3/dist-packages/pkg/module.py"
check_present "similarly-named directory survives" \
   "${test_root}/tree/usr/share/mypy_cache_docs/readme.txt"
check_present ".git contents survive" \
   "${test_root}/tree/.git/objects/deadbeef"
check_present ".git is pruned, even for a residue-named directory" \
   "${test_root}/tree/.git/__pycache__/x.pyc"

## The guard: a tree with no debian/ is not a package source root, and this
## function deletes recursively, so it must strip nothing there.
mkdir --parents -- "${test_root}/not_a_package/__pycache__"
printf '%s\n' "junk" > "${test_root}/not_a_package/__pycache__/x.pyc"
cd -- "${test_root}/not_a_package"
make_strip_build_residue
check_present "no debian/ - residue left untouched" \
   "${test_root}/not_a_package/__pycache__/x.pyc"

printf '%s\n' "---"
printf '%s\n' "${tests_total} run, $(( tests_total - tests_failed )) pass, ${tests_failed} fail, 0 skip"

if [ "${tests_failed}" != "0" ]; then
   exit 1
fi

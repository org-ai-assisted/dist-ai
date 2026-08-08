#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_parse_changelog_version splits a Debian changelog version into epoch,
## upstream version and revision. Every derived artifact name is built from those
## three ('.dsc', '.orig.tar.xz', '.debian.tar.xz', '.changes', each '.deb'), so a
## mis-split does not fail loudly -- it ships a package under a wrong name.
##
## The case that matters: Debian permits hyphens in the UPSTREAM version, and the
## revision is the part after the LAST hyphen. Taking the revision from the FIRST
## hyphen while the version strips at the last one makes the two halves disagree,
## and concatenating them back duplicates the middle segment.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## Reached only via the ERR trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
error_handler() {
   local exit_code="$?"
   printf '%s\n' "ERROR: exit_code: ${exit_code} | BASH_COMMAND: ${BASH_COMMAND}"
   exit 1
}

trap error_handler ERR

## Subject selection mirrors the rest of this suite (first that exists):
##   $GENMKFILE_SHARE -> the derivative-maker submodule checkout -> the installed
##   /usr/share/genmkfile. Checkout BEFORE installed: the installed copy drifts from
##   the tree under review, so preferring it tests code nobody is changing. Absent means SKIP (77), not failure: the
##   suite must not report a red when the component simply is not present.
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

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}

trap cleanup_handler EXIT

tests_total=0
tests_failed=0

## Extract the function under test rather than sourcing the whole library, matching
## test_strip_build_residue.sh.
sed -n '/^make_parse_changelog_version()/,/^}/p' -- "${helper_file}" \
   > "${test_root}/function_under_test.sh"

if ! test -s "${test_root}/function_under_test.sh" ; then
   printf '%s\n' "ERROR: could not extract make_parse_changelog_version." >&2
   exit 1
fi

## The extracted file is generated at runtime, so there is no path for a source=
## directive to point at.
# shellcheck disable=SC1091
source "${test_root}/function_under_test.sh"

check_parse() {
   local changelog_version="$1" want_epoch="$2" want_version="$3" want_revision="$4"

   make_epoch=""
   make_pkg_version=""
   make_pkg_revision=""
   make_parse_changelog_version "${changelog_version}"

   tests_total=$(( tests_total + 1 ))
   if [ "${make_epoch}" = "${want_epoch}" ] \
      && [ "${make_pkg_version}" = "${want_version}" ] \
      && [ "${make_pkg_revision}" = "${want_revision}" ]; then
      printf '%s\n' "PASS  ${changelog_version} -> epoch='${make_epoch}' version='${make_pkg_version}' revision='${make_pkg_revision}'"
   else
      tests_failed=$(( tests_failed + 1 ))
      printf '%s\n' "FAIL  ${changelog_version}" >&2
      printf '%s\n' "        want epoch='${want_epoch}' version='${want_version}' revision='${want_revision}'" >&2
      printf '%s\n' "        got  epoch='${make_epoch}' version='${make_pkg_version}' revision='${make_pkg_revision}'" >&2
   fi
}

## Round-trip: the concatenation callers actually build must reproduce the input.
check_roundtrip() {
   local changelog_version="$1" rebuilt

   make_epoch=""
   make_pkg_version=""
   make_pkg_revision=""
   make_parse_changelog_version "${changelog_version}"

   rebuilt="${make_pkg_version}${make_pkg_revision}"
   if [ -n "${make_epoch}" ]; then
      rebuilt="${make_epoch}:${rebuilt}"
   fi

   tests_total=$(( tests_total + 1 ))
   if [ "${rebuilt}" = "${changelog_version}" ]; then
      printf '%s\n' "PASS  round-trip ${changelog_version}"
   else
      tests_failed=$(( tests_failed + 1 ))
      printf '%s\n' "FAIL  round-trip ${changelog_version} -> ${rebuilt}" >&2
   fi
}

## The ordinary shapes named in make_get_variables' own comment.
check_parse '0.1-1'          ''  '0.1'        '-1'
check_parse '3:0.1-1'        '3' '0.1'        '-1'
check_parse '1:20240810'     '1' '20240810'   ''
check_parse '20240810'       ''  '20240810'   ''

## THE REGRESSION: a hyphen inside the upstream version. Splitting the revision on
## the first hyphen yields version '1.0-beta' with revision '-beta-1', so the
## rebuilt name becomes '1.0-beta-beta-1'.
check_parse '1.0-beta-1'     ''  '1.0-beta'   '-1'
check_parse '2:1.0-rc-3'     '2' '1.0-rc'     '-3'

## Round-trip every shape: this is what artifact names are built from.
for version in '0.1-1' '3:0.1-1' '1:20240810' '20240810' '1.0-beta-1' '2:1.0-rc-3'; do
   check_roundtrip "${version}"
done

printf '%s\n' "" "${tests_total} test(s), ${tests_failed} failed"
if [ "${tests_failed}" -ne 0 ]; then
   exit 1
fi
exit 0

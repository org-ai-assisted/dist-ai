#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_debinstfile_create maps a source file named '<path>#<pkgname>' to
## debian/<pkgname>.install. It derived <pkgname> from the FIRST '#' in the WHOLE find path,
## so a PARENT directory named e.g. 'x#..' injected '../' into the path it then safe-rm's and
## writes -- an arbitrary-file delete/write OUTSIDE genmkfile_temp_dir, as root under a build.
## The fix takes the package name from the BASENAME's last '#' and validates it. This drives
## the REAL function against a hostile source tree and asserts nothing escaped the temp dir.

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

## Capability gate: this suite tests the genmkfile CHECKOUT (wired via GENMKFILE_BIN or
## GENMKFILE_SHARE). If nothing was wired and only the installed /usr/share/genmkfile helper
## resolved -- which drifts from the tree under review -- SKIP rather than report a confusing
## FAIL against a possibly-stale subject nobody is changing.
if [ -z "${GENMKFILE_SHARE:-}" ] && [ -z "${GENMKFILE_BIN:-}" ] \
   && [ "${helper_file}" = "/usr/share/genmkfile/make-helper-one.bsh" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi
if ! type -P sponge >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: sponge (moreutils) is required.' >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() {
   safe-rm -r -f -- "${work}"
}
trap cleanup EXIT

## Extract the real function; stub only the reporting/guard helpers it calls.
{
   printf '%s\n' 'exit_with_error() { printf "DIE: %s\n" "$2" >&2; exit "$1"; }'
   printf '%s\n' 'make_require() { :; }'
   printf '%s\n' 'make_output_info() { :; }'
   sed -n '/^make_debinstfile_create()/,/^}/p' -- "${helper_file}"
} > "${work}/fn.sh"
if ! grep --quiet '^make_debinstfile_create()' "${work}/fn.sh"; then
   printf '%s\n' 'ERROR: could not extract make_debinstfile_create.' >&2
   exit 1
fi
# shellcheck disable=SC1091
source "${work}/fn.sh"

## Hostile source tree: a PARENT directory carrying '#..' and a file whose basename has '#'.
pkg_root="${work}/pkgroot"
mkdir --parents -- "${pkg_root}/x#.."
printf 'payload\n' > "${pkg_root}/x#../pwned#realpkg"
mkdir --parents -- "${pkg_root}/debian"

genmkfile_temp_dir="${work}/scratch"
mkdir --parents -- "${genmkfile_temp_dir}"
make_folder_list_for_un_and_install=(x#..)

tests_total=0
tests_failed=0

## The path an unfixed name-derivation escapes to: genmkfile_temp_dir/../pwned#realpkg.install.
escaped="$(dirname -- "${genmkfile_temp_dir}")/pwned#realpkg.install"

status=0
( cd -- "${pkg_root}" && make_debinstfile_create ) >/dev/null 2>&1 || status=$?

tests_total=$(( tests_total + 1 ))
if [ ! -e "${escaped}" ]; then
   printf '%s\n' "PASS  hostile '#..' parent did NOT escape genmkfile_temp_dir (no ${escaped})"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  arbitrary write escaped to ${escaped}" >&2
fi

## The hostile FILE ('x#../pwned#realpkg') is legitimately handled as package 'realpkg' and
## copied to the package's OWN debian/ -- a contained sink. A TRUE escape is a .install written
## anywhere else (above the temp dir, or outside pkg_root). Allow only the two legit roots.
tests_total=$(( tests_total + 1 ))
outside='false'
while IFS= read -r -d '' f; do
   if [[ "${f}" != "${genmkfile_temp_dir}/"* && "${f}" != "${pkg_root}/debian/"* ]]; then
      outside='true'
   fi
done < <(find "${work}" -name '*.install' -print0)
if [ "${outside}" = 'false' ]; then
   printf '%s\n' "PASS  every generated .install stayed inside genmkfile_temp_dir"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  a generated .install landed outside genmkfile_temp_dir" >&2
fi

## A dot-prefixed package name ('foo#.evil' -> '.evil') must be REJECTED: '.evil.install' would
## be silently dropped by the later non-dotglob '*.install' expansion.
dot_root="${work}/dotroot"
mkdir --parents -- "${dot_root}/sub" "${dot_root}/debian"
printf 'x\n' > "${dot_root}/sub/foo#.evil"
dot_out=''
dot_rc=0
dot_out="$( ( cd -- "${dot_root}" && make_debinstfile_create ) 2>&1 )" || dot_rc=$?
tests_total=$(( tests_total + 1 ))
if [ "${dot_rc}" -ne 0 ] && [[ "${dot_out}" == *'invalid package name'* ]]; then
   printf '%s\n' "PASS  dot-prefixed package name rejected"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  dot-prefixed package name not rejected: rc=${dot_rc} out=[${dot_out}]" >&2
fi

## An invalid package name must be FATAL, not a silent skip. With 'find | while' the die
## ran in a pipe SUBSHELL, so the function kept going and copied whatever it already had --
## a bad entry silently dropped files while the build reported success. Fixture: a VALID
## file that sorts BEFORE an invalid one ('#.evil'); the whole run must abort (rc != 0) and
## the valid file's package must NOT be copied to debian/ (it aborts at the invalid entry).
fatal_root="${work}/fatalroot"
mkdir --parents -- "${fatal_root}/usr/bin" "${fatal_root}/debian"
printf 'x\n' > "${fatal_root}/usr/bin/good#pkg-ok"
printf 'x\n' > "${fatal_root}/usr/bin/zzz#.evil"
genmkfile_temp_dir="${work}/fatalscratch"
mkdir --parents -- "${genmkfile_temp_dir}"
fatal_rc=0
( cd -- "${fatal_root}" && make_debinstfile_create ) >/dev/null 2>&1 || fatal_rc=$?
tests_total=$(( tests_total + 1 ))
if [ "${fatal_rc}" -ne 0 ] && [ ! -e "${fatal_root}/debian/pkg-ok.install" ]; then
   printf '%s\n' "PASS  an invalid package name aborts the whole run (no silent partial packaging)"
else
   tests_failed=$(( tests_failed + 1 ))
   ok_exists='no'
   [ -e "${fatal_root}/debian/pkg-ok.install" ] && ok_exists='yes'
   printf '%s\n' "FAIL  invalid pkg name not fatal: rc=${fatal_rc} pkg-ok.install=${ok_exists}" >&2
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "debinstfile_hash_containment_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "debinstfile_hash_containment_test: ${tests_total} pass, 0 fail, 0 skip"

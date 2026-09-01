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

## Every .install the function wrote stays inside the temp dir.
tests_total=$(( tests_total + 1 ))
outside='false'
while IFS= read -r -d '' f; do
   if [[ "${f}" != "${genmkfile_temp_dir}/"* ]]; then
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

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "debinstfile_hash_containment_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "debinstfile_hash_containment_test: ${tests_total} pass, 0 fail, 0 skip"

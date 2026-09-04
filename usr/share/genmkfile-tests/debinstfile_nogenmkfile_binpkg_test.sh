#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_debinstfile_create honours a 'nogenmkfile' opt-out marker so a maintainer can
## hand-maintain an install file. The single-source-package guard checks only
## debian/<source-pkg>.install. The MULTI-package generation loop, however, cp-overwrites
## every debian/<binary-pkg>.install whose content differs, with no per-target opt-out --
## so 'nogenmkfile' + hand-written content in a BINARY-package install file was silently
## clobbered (data loss). The fix checks the marker on each per-target install file inside
## the overwrite loop, matching the marker as a whole line ('nogenmkfile' or '## nogenmkfile')
## rather than an anywhere-substring. This drives the REAL function and asserts:
##   1. a bare-marked debian/<binpkg>.install is left untouched (FAILS on the pre-fix code);
##   2. an UNmarked binary-package install file is still (re)generated (guard not over-broad);
##   3. a PATH merely containing 'nogenmkfile' does not falsely freeze its file;
##   4. a '#'-prefixed mapping containing 'nogenmkfile' is not mistaken for a comment marker;
##   5. the comment marker form '## nogenmkfile' is honoured too.

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

## Extract the real functions; stub only the reporting/guard helpers they call.
{
   printf '%s\n' 'exit_with_error() { printf "DIE: %s\n" "$2" >&2; exit "$1"; }'
   printf '%s\n' 'make_require() { :; }'
   printf '%s\n' 'make_output_info() { :; }'
   sed -n '/^make_debinstfile_has_nogenmkfile_marker()/,/^}/p' -- "${helper_file}"
   sed -n '/^make_debinstfile_create()/,/^}/p' -- "${helper_file}"
} > "${work}/fn.sh"
if ! grep --quiet '^make_debinstfile_create()' "${work}/fn.sh" \
   || ! grep --quiet '^make_debinstfile_has_nogenmkfile_marker()' "${work}/fn.sh"; then
   printf '%s\n' 'ERROR: could not extract make_debinstfile_create + marker helper.' >&2
   exit 1
fi
# shellcheck disable=SC1091
source "${work}/fn.sh"

tests_total=0
tests_failed=0

## Source tree with binary packages via the '#<pkgname>' convention:
##  - 'optout':    its debian/optout.install is hand-maintained and carries the bare marker.
##  - 'regen':     its debian/regen.install has NO marker and stale content.
##  - 'pathfp':    debian/pathfp.install has NO marker but stale content whose text merely
##                 contains the substring 'nogenmkfile' inside a PATH -- an anywhere-substring
##                 grep would wrongly freeze it (the false-positive the reviewers flagged).
##  - 'commentfp': debian/commentfp.install has NO marker but a stale line that STARTS with
##                 '#' and contains 'nogenmkfile' (as a '#'-prefixed generated mapping would)
##                 -- treating it as a comment marker would wrongly freeze it; a 'SOURCE =>
##                 DEST' mapping is never the opt-out.
##  - 'optoutc':   its debian/optoutc.install opts out with the COMMENT form '## nogenmkfile'
##                 (the other honoured marker form) and MUST be preserved.
pkg_root="${work}/pkgroot"
mkdir --parents -- "${pkg_root}/usr/bin" "${pkg_root}/debian"
printf 'toolA\n' > "${pkg_root}/usr/bin/tool-a#optout"
printf 'toolB\n' > "${pkg_root}/usr/bin/tool-b#regen"
printf 'toolC\n' > "${pkg_root}/usr/bin/nogenmkfile#pathfp"
printf 'toolD\n' > "${pkg_root}/usr/bin/tool-d#commentfp"
printf 'toolE\n' > "${pkg_root}/usr/bin/tool-e#optoutc"

## The maintainer's hand-written content that MUST survive (bare marker form).
maintainer_content='nogenmkfile
usr/bin/tool-a => /usr/bin/hand-maintained-destination'
printf '%s\n' "${maintainer_content}" > "${pkg_root}/debian/optout.install"

## Hand-written content opting out via the COMMENT marker form; MUST also survive.
maintainer_content_comment='## nogenmkfile
usr/bin/tool-e => /usr/bin/hand-maintained-comment-destination'
printf '%s\n' "${maintainer_content_comment}" > "${pkg_root}/debian/optoutc.install"

## An unmarked, stale binary-package install file that SHOULD be overwritten.
printf '%s\n' 'stale content with no marker' > "${pkg_root}/debian/regen.install"

## Stale content containing 'nogenmkfile' only inside a PATH (no marker line).
## A substring match would treat this as an opt-out and freeze it; the marker match must not.
printf '%s\n' 'usr/bin/nogenmkfile => /usr/bin/stale-destination' > "${pkg_root}/debian/pathfp.install"

## Stale line that STARTS with '#' and contains 'nogenmkfile' -- exactly what a '#'-prefixed
## source path yields as a generated mapping. A comment-line match would freeze it; must not.
printf '%s\n' '#nogenmkfile#commentfp => /usr/bin/stale-destination' > "${pkg_root}/debian/commentfp.install"

genmkfile_temp_dir="${work}/scratch"
mkdir --parents -- "${genmkfile_temp_dir}"
make_folder_list_for_un_and_install=(usr)

status=0
( cd -- "${pkg_root}" && make_debinstfile_create ) >/dev/null 2>&1 || status=$?

tests_total=$(( tests_total + 1 ))
if [ "${status}" -eq 0 ]; then
   printf '%s\n' "PASS  make_debinstfile_create returned 0"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  make_debinstfile_create exited ${status}" >&2
fi

## 1. The marked binary-package install file is preserved byte-for-byte.
tests_total=$(( tests_total + 1 ))
actual_optout="$(cat -- "${pkg_root}/debian/optout.install")"
if [ "${actual_optout}" = "${maintainer_content}" ]; then
   printf '%s\n' "PASS  marked debian/optout.install left untouched (opt-out honoured)"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  marked debian/optout.install was OVERWRITTEN (data loss):" >&2
   printf '%s\n' "----- actual -----" >&2
   printf '%s\n' "${actual_optout}" >&2
   printf '%s\n' "------------------" >&2
fi

## 2. The unmarked binary-package install file is still regenerated (fix is not over-broad).
tests_total=$(( tests_total + 1 ))
if grep --quiet -- '=> /usr/bin/tool-b' "${pkg_root}/debian/regen.install" \
   && ! grep --quiet -- 'stale content with no marker' "${pkg_root}/debian/regen.install"; then
   printf '%s\n' "PASS  unmarked debian/regen.install was regenerated"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  unmarked debian/regen.install not regenerated:" >&2
   cat -- "${pkg_root}/debian/regen.install" >&2 || true
fi

## 3. A path merely containing 'nogenmkfile' must NOT be mistaken for the opt-out marker:
## pathfp.install is regenerated (dh-exec header present), not frozen by a substring match.
tests_total=$(( tests_total + 1 ))
if grep --quiet -- 'dh-exec' "${pkg_root}/debian/pathfp.install" \
   && ! grep --quiet -- 'stale-destination' "${pkg_root}/debian/pathfp.install"; then
   printf '%s\n' "PASS  'nogenmkfile' in a path did NOT falsely trigger the opt-out"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  a path containing 'nogenmkfile' froze debian/pathfp.install (substring false-positive):" >&2
   cat -- "${pkg_root}/debian/pathfp.install" >&2 || true
fi

## 4. A '#'-prefixed line containing 'nogenmkfile' (a '#'-prefixed generated mapping) must NOT
## be mistaken for a comment marker: commentfp.install is regenerated, not frozen.
tests_total=$(( tests_total + 1 ))
if grep --quiet -- 'dh-exec' "${pkg_root}/debian/commentfp.install" \
   && ! grep --quiet -- 'stale-destination' "${pkg_root}/debian/commentfp.install"; then
   printf '%s\n' "PASS  a '#'-prefixed 'nogenmkfile' line did NOT falsely trigger the opt-out"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  a '#'-prefixed 'nogenmkfile' line froze debian/commentfp.install (comment-branch false-positive):" >&2
   cat -- "${pkg_root}/debian/commentfp.install" >&2 || true
fi

## 5. The comment marker form ('## nogenmkfile') is also honoured: optoutc.install preserved.
tests_total=$(( tests_total + 1 ))
actual_optoutc="$(cat -- "${pkg_root}/debian/optoutc.install")"
if [ "${actual_optoutc}" = "${maintainer_content_comment}" ]; then
   printf '%s\n' "PASS  comment marker '## nogenmkfile' honoured (optoutc left untouched)"
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  comment marker '## nogenmkfile' not honoured; optoutc.install OVERWRITTEN:" >&2
   printf '%s\n' "${actual_optoutc}" >&2
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "debinstfile_nogenmkfile_binpkg_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "debinstfile_nogenmkfile_binpkg_test: ${tests_total} pass, 0 fail, 0 skip"

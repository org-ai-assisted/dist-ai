#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 'genmkfile dist' builds the upstream .orig tarball from the working tree, excluding the
## packaging dir './debian' (lintian no-debian-changes). Two coupled bugs:
##   - the exclusion used a bare './debian*' glob, which ALSO swallowed sibling top-level names
##     that merely START with 'debian' (a file 'debianrc', a dir 'debian-notes/') -- silently
##     dropping legitimate upstream files from the release tarball;
##   - the empty-directory guard did NOT share that exclusion, so an empty dir UNDER debian/
##     (never tarred anyway) aborted the build with "Empty directory found!".
## This pins both: an empty dir under debian/ does not abort, and 'debian'-prefixed SIBLINGS
## land in the tarball while the real debian/ dir does not.
##
## Hermetic: DISTDIR is the temp workdir; no root, nothing outside the workdir touched.
##
## Exit: 0 pass | 1 fail | 77 skip when genmkfile is not present.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

locate_genmkfile() {
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      printf '%s\n' "${GENMKFILE_BIN}"
      return 0
   fi
   local checkout
   checkout="${HOME}/derivative-maker/packages/kicksecure/genmkfile/usr/bin/genmkfile"
   if [ -x "${checkout}" ]; then
      printf '%s\n' "${checkout}"
      return 0
   fi
   if [ -x /usr/bin/genmkfile ]; then
      printf '%s\n' /usr/bin/genmkfile
      return 0
   fi
   return 1
}

if ! genmkfile_bin="$(locate_genmkfile)"; then
   printf '%s\n' 'FATAL: genmkfile not found (set GENMKFILE_BIN).' >&2
   exit 1
fi

if [ -z "${GENMKFILE_BIN:-}" ] && [ "${genmkfile_bin}" = "/usr/bin/genmkfile" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-dist-sibling.XXXXXX")"
checks=0
failures=0

# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}
trap cleanup_handler EXIT

pass() {
   checks=$(( checks + 1 ))
   printf '%s\n' "PASS  $1"
}
fail() {
   checks=$(( checks + 1 ))
   failures=$(( failures + 1 ))
   printf '%s\n' "FAIL  $1" >&2
}

pkg_dir="${work_dir}/gmf-dist-pkg"
mkdir --parents -- \
   "${pkg_dir}/debian/emptyplaceholder" \
   "${pkg_dir}/usr/bin" \
   "${pkg_dir}/debian-notes"

cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: gmf-dist-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-dist-pkg
Architecture: all
Description: throwaway fixture for the dist debian-sibling test
 Not a real package.
CONTROL

cat > "${pkg_dir}/debian/changelog" <<'CHANGELOG'
gmf-dist-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG

## A real upstream file.
printf '%s\n' 'tool' > "${pkg_dir}/usr/bin/tool"
## A top-level FILE whose name starts with 'debian' but is NOT the packaging dir.
printf '%s\n' 'rc' > "${pkg_dir}/debianrc"
## A top-level DIR whose name starts with 'debian' but is NOT the packaging dir.
printf '%s\n' 'note' > "${pkg_dir}/debian-notes/note.txt"
## 'debian/emptyplaceholder' is an EMPTY dir UNDER the packaging dir (created above) -- it is
## never tarred, so it must NOT trip the empty-directory guard.

## Run 'genmkfile dist' in the package root; the .orig tarball lands in DISTDIR (default '..').
rc=0
(
   cd -- "${pkg_dir}" \
   && "${genmkfile_bin}" dist
) > "${work_dir}/dist.log" 2>&1 || rc=$?

if [ "${rc}" -eq 0 ]; then
   pass 'dist exited 0 (empty dir under debian/ did not trip the guard)'
else
   fail "dist aborted (rc=${rc}): $(tail -6 -- "${work_dir}/dist.log")"
fi

## Find the produced tarball (DISTDIR defaults to the package parent = work_dir).
tarball="$(find "${work_dir}" -maxdepth 1 -name '*.orig.tar.*' -print -quit 2>/dev/null || true)"
if [ -z "${tarball}" ]; then
   fail 'no upstream .orig tarball produced -- remaining checks are vacuous'
   printf '%s\n' "" "${checks} check(s), ${failures} failure(s)"
   exit 1
fi
printf '%s\n' "INFO: tarball: ${tarball}"
members="$(tar --list --file "${tarball}" 2>/dev/null || true)"

in_tar() { grep --quiet --fixed-strings -- "$1" <<< "${members}"; }

## #3: 'debian'-prefixed SIBLINGS must be in the tarball (the old './debian*' glob dropped them).
if in_tar 'debianrc'; then
   pass "sibling file 'debianrc' is in the tarball"
else
   fail "sibling file 'debianrc' was dropped from the tarball (over-broad debian* exclusion)"
fi
if in_tar 'debian-notes/note.txt'; then
   pass "sibling dir 'debian-notes/' is in the tarball"
else
   fail "sibling dir 'debian-notes/' was dropped from the tarball (over-broad debian* exclusion)"
fi

## The real packaging dir 'debian/' must NOT be in the upstream tarball (lintian no-debian-changes).
if in_tar 'debian/control'; then
   fail "the packaging dir debian/ leaked into the upstream tarball"
else
   pass 'the packaging dir debian/ is excluded from the tarball'
fi

## CANARY: a real upstream file really made it in, so the checks above are not vacuous.
if in_tar 'usr/bin/tool'; then
   pass 'canary: a real upstream file is in the tarball'
else
   fail 'canary: real upstream file missing -- the tarball checks are vacuous'
fi

printf '%s\n' "" "${checks} check(s), ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: dist keeps debian-prefixed siblings and tolerates empty dirs under debian/'
exit 0

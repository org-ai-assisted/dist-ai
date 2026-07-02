#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for genmkfile's install-time handling of symlinks that
## 'rsync --safe-links' drops.
##
## 'genmkfile install' rsync's each source top-level directory into DESTDIR
## with '--safe-links', which SKIPS symlinks pointing outside the copied tree
## (absolute, or via '..'). The per-file loop in make_helper then 'stat's each
## destination to fix its mode. A dropped symlink has no destination, so an
## unguarded 'stat' aborted the whole install with a cryptic 'cannot statx'
## under 'set -o errexit'. genmkfile now instead:
##   - truly-absent destination (safe-links dropped a symlink) -> 'die' with a
##     clear, actionable message (fail loud; the symlink was not installed);
##   - destination that IS a (dangling) in-tree symlink rsync copied -> skip it
##     (chmod is meaningless), install continues;
##   - a normal file / directory -> install and fix mode.
##
## This test drives the real genmkfile against throwaway source trees and
## asserts all three behaviors. No root, no network.
##
## Subject selection (first that exists):
##   $GENMKFILE_BIN  ->  /usr/bin/genmkfile  ->  the derivative-maker
##   submodule checkout under ~/derivative-maker.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

locate_genmkfile() {
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      printf '%s\n' "${GENMKFILE_BIN}"
      return 0
   fi
   ## Fixed-location path test (genmkfile installs to /usr/bin/genmkfile
   ## across the ecosystem) rather than a PATH lookup.
   if [ -x /usr/bin/genmkfile ]; then
      printf '%s\n' /usr/bin/genmkfile
      return 0
   fi
   local checkout
   checkout="${HOME}/derivative-maker/packages/kicksecure/genmkfile/usr/bin/genmkfile"
   if [ -x "${checkout}" ]; then
      printf '%s\n' "${checkout}"
      return 0
   fi
   return 1
}

## 'genmkfile install' shells out to rsync; without it the suite cannot
## exercise the code path, so SKIP rather than fail.
if ! command -v rsync >/dev/null 2>&1; then
   printf '%s\n' "SKIP: rsync not available" >&2
   exit 77
fi

genmkfile_bin="$(locate_genmkfile)" || {
   printf '%s\n' "SKIP: no genmkfile found (set GENMKFILE_BIN, install genmkfile, or check out derivative-maker)" >&2
   exit 77
}
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

cleanup_workdir() {
   ## SC2317: reached via the EXIT trap below, not a straight-line call.
   # shellcheck disable=SC2317
   safe-rm --recursive --force -- "${workdir}"
}

workdir="$(mktemp --directory)"
trap cleanup_workdir EXIT

make_fixture() {
   ## Minimal but real source package: a parseable changelog and a control
   ## file with a binary stanza, plus a 'usr/bin/' with one normal file that
   ## every scenario expects to be installed.
   local dir="$1"
   mkdir --parents -- "${dir}/debian" "${dir}/usr/bin"
   cat > "${dir}/debian/control" <<'CONTROL'
Source: gmf-test-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-test-pkg
Architecture: all
Depends: ${misc:Depends}
Description: throwaway fixture for genmkfile install safe-links test
 Not a real package.
CONTROL
   cat > "${dir}/debian/changelog" <<'CHANGELOG'
gmf-test-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG
   printf '%s\n' "normal file content" > "${dir}/usr/bin/normalfile"
}

## Run 'genmkfile install' for a prepared package tree, capturing exit code
## into $rc and combined output into $out.
out=""
rc=0
do_install() {
   local pkg_dir="$1" dest_dir="$2"
   rc=0
   out="$(
      cd "${pkg_dir}"
      DESTDIR="${dest_dir}" "${genmkfile_bin}" install 2>&1
   )" || rc=$?
}

failures=0
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1"; failures=$(( failures + 1 )); }

## ---- Scenario 1: a normal file installs cleanly. ----
printf '\n===== scenario: normal file =====\n'
s1_pkg="${workdir}/normal/pkg"
s1_dest="${workdir}/normal/dest"
mkdir --parents -- "${s1_dest}"
make_fixture "${s1_pkg}"
do_install "${s1_pkg}" "${s1_dest}"
if [ "${rc}" -eq 0 ] && [ -f "${s1_dest}/usr/bin/normalfile" ]; then
   pass "normal file installed (exit 0)"
else
   fail "normal file: exit ${rc}, normalfile present=$( [ -f "${s1_dest}/usr/bin/normalfile" ] && echo yes || echo no )"
   printf '%s\n' "${out}" | tail -10
fi

## ---- Scenario 2: an absolute (escaping) symlink -> fail loud. ----
## 'rsync --safe-links' drops it, so it has no destination; genmkfile must
## 'die' with a clear message rather than aborting cryptically or silently
## skipping a symlink that was not installed.
printf '\n===== scenario: absolute (escaping) symlink =====\n'
s2_pkg="${workdir}/escaping/pkg"
s2_dest="${workdir}/escaping/dest"
mkdir --parents -- "${s2_dest}"
make_fixture "${s2_pkg}"
ln --symbolic -- /etc/hostname "${s2_pkg}/usr/bin/abslink"
do_install "${s2_pkg}" "${s2_dest}"
if [ "${rc}" -ne 0 ] && printf '%s\n' "${out}" | grep --quiet -- 'safe-links'; then
   pass "escaping symlink aborts install with a safe-links message (exit ${rc})"
else
   fail "escaping symlink: expected non-zero exit + 'safe-links' message, got exit ${rc}"
   printf '%s\n' "${out}" | tail -10
fi
## It must NOT abort with the bare, cryptic 'stat' error (the pre-fix symptom).
if printf '%s\n' "${out}" | grep --quiet -- 'cannot statx'; then
   fail "escaping symlink: aborted with the cryptic 'cannot statx' (pre-fix behavior)"
fi

## ---- Scenario 3: a dangling in-tree symlink -> tolerated. ----
## A relative symlink whose target is inside the tree but missing is copied by
## rsync (it is "safe"); it lands in DESTDIR as a dangling symlink. genmkfile
## must skip it (chmod is meaningless) and still install the rest.
printf '\n===== scenario: dangling in-tree symlink =====\n'
s3_pkg="${workdir}/dangling/pkg"
s3_dest="${workdir}/dangling/dest"
mkdir --parents -- "${s3_dest}"
make_fixture "${s3_pkg}"
ln --symbolic -- ./does-not-exist "${s3_pkg}/usr/bin/danglink"
do_install "${s3_pkg}" "${s3_dest}"
if [ "${rc}" -eq 0 ] \
   && [ -f "${s3_dest}/usr/bin/normalfile" ] \
   && [ -L "${s3_dest}/usr/bin/danglink" ]; then
   pass "dangling in-tree symlink tolerated; normal file still installed (exit 0)"
else
   fail "dangling symlink: exit ${rc}, normalfile=$( [ -f "${s3_dest}/usr/bin/normalfile" ] && echo yes || echo no ), danglink=$( [ -L "${s3_dest}/usr/bin/danglink" ] && echo yes || echo no )"
   printf '%s\n' "${out}" | tail -10
fi

printf '\n===== summary =====\n'
if [ "${failures}" -eq 0 ]; then
   printf 'OK: all genmkfile install safe-links checks passed\n'
   exit 0
fi
printf 'FAILED: %s genmkfile install safe-links check(s) failed\n' "${failures}"
exit 1

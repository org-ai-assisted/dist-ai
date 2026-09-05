#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 'genmkfile uninstall' must remove everything it installed, and 'uninstallcheck' must
## refuse to call the result clean while anything is left.
##
## THE FAILURE THIS GUARDS is double-silent. A dangling symlink -- one whose target is
## not installed, or is removed first -- is invisible to 'test -f', because that
## predicate follows the link. So uninstall skipped it AND uninstallcheck then exited 0
## reporting a clean uninstall, with the file still on disk. Neither step said anything.
##
## The predicate has to be file-or-symlink, not "anything that exists": '-e' is also
## true for a DIRECTORY, and the uninstall loop hands each hit to safe-rm, which fails
## with "Is a directory". Both halves are asserted here, because fixing the first by
## breaking the second is the obvious wrong turn.
##
## Hermetic: DESTDIR is a temp directory. No root, no network.
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

## Subject selection mirrors the rest of this suite: checkout BEFORE the installed
## copy, since the installed engine drifts from the tree under review.
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

## Capability gate: this suite tests the genmkfile CHECKOUT (wired via GENMKFILE_BIN). If
## nothing was wired and only the installed /usr/bin/genmkfile resolved -- which drifts from the
## tree under review -- SKIP rather than report a confusing FAIL against a possibly-stale
## subject nobody is changing.
if [ -z "${GENMKFILE_BIN:-}" ] && [ "${genmkfile_bin}" = "/usr/bin/genmkfile" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-uninstall.XXXXXX")"
checks=0
failures=0

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
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

pkg_dir="${work_dir}/pkg"
dest_dir="${work_dir}/dest"
mkdir --parents -- "${pkg_dir}/debian" "${pkg_dir}/usr/share/gmf-uninst" "${dest_dir}"

cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: gmf-uninst
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-uninst
Architecture: all
Description: throwaway fixture for the uninstall completeness test
 Not a real package.
CONTROL

cat > "${pkg_dir}/debian/changelog" <<'CHANGELOG'
gmf-uninst (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG

printf '%s\n' 'data' > "${pkg_dir}/usr/share/gmf-uninst/real-file"
## A relative in-tree symlink whose target does not exist: rsync --safe-links keeps it
## (it does not escape the tree), so it IS installed, and it is exactly what 'test -f'
## cannot see.
ln -s ./missing-target -- "${pkg_dir}/usr/share/gmf-uninst/dangling-symlink"

run_target() {
   local target="$1" rc=0
   ( cd -- "${pkg_dir}" && DESTDIR="${dest_dir}" "${genmkfile_bin}" "${target}" ) \
      > "${work_dir}/${target}.log" 2>&1 || rc=$?
   return "${rc}"
}

## --- install ----------------------------------------------------------------
if run_target install; then
   pass 'install exited 0'
else
   fail "install failed: $(tail -3 -- "${work_dir}/install.log")"
fi

if [ -L "${dest_dir}/usr/share/gmf-uninst/dangling-symlink" ]; then
   pass 'the dangling symlink really was installed (the case under test exists)'
else
   fail 'the dangling symlink was not installed -- the rest of this test is vacuous'
fi

## --- uninstall --------------------------------------------------------------
## The directory arm matters as much as the symlink one: a predicate of "anything that
## exists" makes uninstall hand a directory to safe-rm and abort.
if run_target uninstall; then
   pass 'uninstall exited 0 (it did not trip over a directory)'
else
   fail "uninstall failed: $(grep -m1 -- 'Is a directory\|rm:' "${work_dir}/uninstall.log" || tail -3 -- "${work_dir}/uninstall.log")"
fi

if [ -e "${dest_dir}/usr/share/gmf-uninst/real-file" ]; then
   fail 'uninstall left the regular file behind'
else
   pass 'the regular file is gone'
fi

if [ -L "${dest_dir}/usr/share/gmf-uninst/dangling-symlink" ]; then
   fail 'uninstall left the dangling symlink behind'
else
   pass 'the dangling symlink is gone'
fi

## Nothing installed may remain, by any name.
leftovers="$(find "${dest_dir}" -mindepth 1 \( -type f -o -type l \) 2>/dev/null | head -5)"
if [ -z "${leftovers}" ]; then
   pass 'no installed file or symlink remains under DESTDIR'
else
   fail "leftovers under DESTDIR: ${leftovers}"
fi

## --- uninstallcheck ---------------------------------------------------------
if run_target uninstallcheck; then
   pass 'uninstallcheck reports clean once everything really is gone'
else
   fail 'uninstallcheck reports still-installed on a genuinely clean tree'
fi

## --- the false green, directly ----------------------------------------------
## Re-plant ONLY the dangling symlink and assert uninstallcheck refuses to call it
## clean. This is the assertion that fails on the old predicate.
mkdir --parents -- "${dest_dir}/usr/share/gmf-uninst"
ln -s ./missing-target -- "${dest_dir}/usr/share/gmf-uninst/dangling-symlink"
if run_target uninstallcheck; then
   fail 'uninstallcheck reported CLEAN with a dangling symlink still installed'
else
   pass 'uninstallcheck refuses to call a leftover dangling symlink clean'
fi

printf '%s\n' "" "${checks} check(s), ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: uninstall removes what it installed, and uninstallcheck tells the truth'
exit 0

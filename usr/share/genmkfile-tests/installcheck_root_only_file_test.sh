#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for genmkfile's make_installcheck over root-owned config.
##
## THE BUG: installcheck diffs each packaged file against its installed copy.
## A root-owned installed config file (e.g. /etc/sudoers.d/*, mode 0440) is
## unreadable to a non-root installcheck, so a bare 'diff' failed
##   diff: /etc/sudoers.d/tpo-downloader: Permission denied
## and then MISREPORTED the (unchanged) file as "changed in /etc". genmkfile now
## reads an unreadable installed file via sudo for the diff, and if even sudo
## cannot read it, prints an honest "not readable ... re-run as root" notice and
## skips -- never a false "changed", never a raw "Permission denied".
##
## Drives the REAL genmkfile against a throwaway package tree: installs an
## /etc file, makes the installed copy unreadable to the current user, and runs
## 'genmkfile installcheck'. The bug is non-root-specific (root bypasses file
## permissions), so this exercises the fix only when run as a normal user.
##
## No network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

locate_genmkfile() {
   local candidate from_bin=''
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      printf '%s\n' "${GENMKFILE_BIN}"
      return 0
   fi
   for candidate in \
      "${HOME}/derivative-maker/packages/kicksecure/genmkfile/usr/bin/genmkfile" \
      "/usr/bin/genmkfile"; do
      if [ -x "${candidate}" ]; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

genmkfile_bin="$(locate_genmkfile)" || {
   printf '%s\n' "FATAL: no genmkfile found (set GENMKFILE_BIN, install genmkfile, or check out derivative-maker)" >&2
   exit 1
}

## Test the CHECKOUT, not a possibly-stale installed copy nobody is changing.
if [ -z "${GENMKFILE_BIN:-}" ] && [ "${genmkfile_bin}" = "/usr/bin/genmkfile" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi

## The bug only manifests as a non-root user; root reads every file regardless
## of mode, so an unreadable installed file cannot be reproduced here as root.
if [ "${EUID}" -eq 0 ]; then
   printf '%s\n' "SKIP: running as root; root bypasses file permissions, so the unreadable-config path cannot be exercised." >&2
   exit 77  ## style-ok: allow-skip: bug is non-root-specific; root cannot reproduce an unreadable file
fi

printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

workdir="$(mktemp --directory)"
cleanup_workdir() {
   # shellcheck disable=SC2317
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup_workdir EXIT

pkg_dir="${workdir}/pkg"
dest_dir="${workdir}/dest"
mkdir --parents -- "${dest_dir}"
mkdir --parents -- "${pkg_dir}/debian" "${pkg_dir}/usr/bin" "${pkg_dir}/etc/sudoers.d"
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: gmf-test-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-test-pkg
Architecture: all
Depends: ${misc:Depends}
Description: throwaway fixture for genmkfile installcheck root-only-file test
 Not a real package.
CONTROL
cat > "${pkg_dir}/debian/changelog" <<'CHANGELOG'
gmf-test-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG
printf '%s\n' "normal file content" > "${pkg_dir}/usr/bin/normalfile"
printf '%s\n' "## root-only config fixture" > "${pkg_dir}/etc/sudoers.d/gmf-test"

## Install into DESTDIR, then make the installed /etc file unreadable to us --
## the shape of a real 0440 root:root sudoers drop-in seen by a non-root check.
( cd "${pkg_dir}" && DESTDIR="${dest_dir}" "${genmkfile_bin}" install >/dev/null 2>&1 )
installed_etc_file="${dest_dir}/etc/sudoers.d/gmf-test"
if [ ! -f "${installed_etc_file}" ]; then
   printf '%s\n' "FATAL: fixture install did not place '${installed_etc_file}'." >&2
   exit 1
fi
chmod 000 -- "${installed_etc_file}"
if [ -r "${installed_etc_file}" ]; then
   printf '%s\n' "SKIP: '${installed_etc_file}' still readable after chmod 000 (unusual filesystem); cannot exercise the unreadable path." >&2
   chmod 644 -- "${installed_etc_file}"
   exit 77  ## style-ok: allow-skip: environment cannot make a file unreadable to its owner
fi

icrc=0
icout="$( cd "${pkg_dir}" && DESTDIR="${dest_dir}" "${genmkfile_bin}" installcheck 2>&1 )" || icrc=$?
chmod 644 -- "${installed_etc_file}"

test_failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## The installed content is identical to the packaged file, so with the fix
## installcheck either reads it via sudo (clean diff) or, if sudo cannot, emits
## the honest not-readable notice. Neither a raw "Permission denied" nor a false
## "changed in /etc" may appear -- both are the pre-fix symptom.
case "${icout}" in
   *"Permission denied"*)
      fail "installcheck leaked a raw 'Permission denied' on the root-only file"
      ;;
   *)
      pass "installcheck did not fail with 'Permission denied' on the unreadable file"
      ;;
esac

case "${icout}" in
   *"gmf-test"*"changed in /etc"*|*"changed in /etc"*"gmf-test"*)
      fail "installcheck misreported the unchanged root-only file as 'changed in /etc'"
      ;;
   *)
      pass "installcheck did not misreport the unchanged root-only file as changed"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s). installcheck output:" >&2
   printf '%s\n' "${icout}" >&2
   exit 1
fi
printf '%s\n' "OK: installcheck handles an unreadable root-only /etc file without a false change."

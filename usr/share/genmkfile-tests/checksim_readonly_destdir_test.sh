#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the read-only / dry-run genmkfile targets -- installcheck, uninstallcheck,
## installsim, uninstallsim -- must NOT require a WRITABLE DESTDIR. None of them writes to
## DESTDIR (a stat, an rsync --dry-run, or a "would do" print), so the make_helper
## writability precondition must gate ONLY the modes that actually write (install, uninstall).
##
## Pre-fix the gate exempted installcheck ALONE (`if [ "${make_installcheck_}" != "true" ]`),
## so 'genmkfile uninstallcheck' / installsim / uninstallsim aborted with
##   DESTDIR '<dir>' is not writeable!
## against a non-writable DESTDIR -- e.g. unprivileged against the default DESTDIR=/.
##
## Hermetic: DESTDIR is a mode-0555 (non-writable) temp dir owned by the test user; no root,
## nothing outside the workdir touched. Exit: 0 pass | 1 fail | 77 skip (no genmkfile checkout).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

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

genmkfile_bin="$(locate_genmkfile)" || {
   printf '%s\n' 'FATAL: genmkfile not found (set GENMKFILE_BIN).' >&2
   exit 1
}
if [ -z "${GENMKFILE_BIN:-}" ] && [ "${genmkfile_bin}" = "/usr/bin/genmkfile" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

## A non-writable DESTDIR must not be created as root (root ignores the write bit, so the
## test would be vacuous). Refuse to run privileged.
if [ "$(id -u)" -eq 0 ]; then
   printf '%s\n' "SKIP: running as root -- a mode-0555 dir is still writable to root, so this test cannot exercise the gate." >&2
   exit 77  ## style-ok: allow-skip: root defeats the non-writable-DESTDIR premise
fi

work_dir="$(mktemp --directory)"
cleanup() {
   # shellcheck disable=SC2317
   chmod 0755 -- "${work_dir}/ro-dest" 2>/dev/null || true
   # shellcheck disable=SC2317
   safe-rm --recursive --force -- "${work_dir}" 2>/dev/null || true
}
trap cleanup EXIT

pkg_dir="${work_dir}/pkg"
mkdir --parents -- "${pkg_dir}/debian" "${pkg_dir}/usr/bin"
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: gmf-ro-dest-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-ro-dest-pkg
Architecture: all
Description: throwaway fixture for the read-only-DESTDIR check/sim regression test
 Not a real package.
CONTROL
cat > "${pkg_dir}/debian/changelog" <<'CHANGELOG'
gmf-ro-dest-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG
printf '%s\n' '#!/bin/bash' 'true' > "${pkg_dir}/usr/bin/realtool"
chmod 0755 -- "${pkg_dir}/usr/bin/realtool"

## A DESTDIR the test user cannot write (mode 0555): exists + readable, but 'test -w' is false.
ro_dest="${work_dir}/ro-dest"
mkdir --parents -- "${ro_dest}"
chmod 0555 -- "${ro_dest}"
if test -w "${ro_dest}"; then
   printf '%s\n' "SKIP: '${ro_dest}' is unexpectedly writable (unusual fs/ACLs); cannot exercise the gate." >&2
   exit 77  ## style-ok: allow-skip: premise (a non-writable dir) not achievable here
fi

failures=0
run_ro() {  ## $1 = read-only/dry-run target
   local target="$1" out rc=0
   out="$(cd -- "${pkg_dir}" && env CI= DESTDIR="${ro_dest}" "${genmkfile_bin}" "${target}" 2>&1)" || rc=$?
   if grep --quiet 'is not writeable' <<< "${out}"; then
      printf '%s\n' "FAIL: ${target} aborted on a non-writable DESTDIR (regression): must not require write for a read-only/dry-run mode"
      failures=$(( failures + 1 ))
   elif [ "${rc}" -ne 0 ]; then
      printf '%s\n' "FAIL: ${target} exited ${rc} on a read-only DESTDIR (not the writability abort):"
      printf '%s\n' "${out}" | tail -8
      failures=$(( failures + 1 ))
   else
      printf '%s\n' "PASS: ${target} runs against a non-writable DESTDIR (no write required)"
   fi
}

run_ro installcheck
run_ro uninstallcheck
run_ro installsim
run_ro uninstallsim

## CANARY: prove the premise held -- a WRITE mode (install) against the SAME non-writable
## DESTDIR still DOES abort with the writability error. If this did not fail, 'test -w' was
## not actually false and every pass above is vacuous.
write_out="$(cd -- "${pkg_dir}" && env CI= DESTDIR="${ro_dest}" "${genmkfile_bin}" install 2>&1)" || true
if grep --quiet 'is not writeable' <<< "${write_out}"; then
   printf '%s\n' "PASS: canary: 'install' (a write mode) still aborts on the non-writable DESTDIR"
else
   printf '%s\n' "FAIL: canary: 'install' did NOT hit the writability gate -- the DESTDIR was writable, checks above are vacuous"
   failures=$(( failures + 1 ))
fi

printf '%s\n' '' "${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: read-only/dry-run modes do not require a writable DESTDIR; write modes still do'
exit 0

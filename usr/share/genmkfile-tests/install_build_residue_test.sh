#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 'genmkfile install' rsync-excludes build residue (__pycache__, *.pyc, *.pyo,
## .mypy_cache, .pytest_cache, .hypothesis) so it never lands in the target. But the
## per-entry install loop walks the WHOLE source tree ('/**'), so it still VISITS those
## excluded entries. rsync never created their DESTDIR path, so the mode-fix
## 'stat -c %a -- <dest>' hits a missing file and, under 'set -o errexit', aborts the
## whole install -- exactly on the tree the excludes exist for (one that accumulated a
## bytecode/tooling cache). This pins that the loop SKIPS the same set it excludes.
##
## Regression: on the pre-fix engine 'genmkfile install' exits non-zero here (the
## 'install exited 0' assertion fails); with the shared exclude list + loop skip it
## installs the real files and drops the residue.
##
## Hermetic: DESTDIR is a temp directory, so no root and nothing outside the workdir is
## touched.
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

## Subject selection mirrors the rest of this suite: checkout BEFORE the installed copy,
## since the installed engine drifts from the tree under review.
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
## nothing was wired and only the installed /usr/bin/genmkfile resolved -- which drifts from
## the tree under review -- SKIP rather than report a confusing FAIL against a possibly-stale
## subject nobody is changing.
if [ -z "${GENMKFILE_BIN:-}" ] && [ "${genmkfile_bin}" = "/usr/bin/genmkfile" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-install-residue.XXXXXX")"
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
mkdir --parents -- \
   "${pkg_dir}/debian" \
   "${pkg_dir}/usr/bin" \
   "${pkg_dir}/usr/share/gmf-residue-pkg" \
   "${pkg_dir}/usr/lib/python3/dist-packages/gmf-residue-pkg/__pycache__" \
   "${pkg_dir}/usr/share/gmf-residue-pkg/.hypothesis/examples" \
   "${pkg_dir}/usr/lib/gmf-residue-pkg/.mypy_cache" \
   "${pkg_dir}/usr/share/gmf-residue-pkg/.pytest_cache"

cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: gmf-residue-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-residue-pkg
Architecture: all
Description: throwaway fixture for the install build-residue test
 Not a real package.
CONTROL

cat > "${pkg_dir}/debian/changelog" <<'CHANGELOG'
gmf-residue-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG

## Real installable files.
printf '%s\n' '#!/bin/bash' 'true' > "${pkg_dir}/usr/bin/realtool"
chmod 0755 -- "${pkg_dir}/usr/bin/realtool"
printf '%s\n' 'data' > "${pkg_dir}/usr/share/gmf-residue-pkg/data-file"
chmod 0644 -- "${pkg_dir}/usr/share/gmf-residue-pkg/data-file"

## Build residue -- the exact set the rsync excludes name. Every one is under a shipped
## directory, so the whole-tree install loop visits it.
printf '%s' 'bytecode' > "${pkg_dir}/usr/lib/python3/dist-packages/gmf-residue-pkg/__pycache__/mod.cpython-311.pyc"
printf '%s' 'loose-bytecode' > "${pkg_dir}/usr/bin/loose.pyc"
printf '%s' 'opt-bytecode' > "${pkg_dir}/usr/bin/loose.pyo"
printf '%s' 'example' > "${pkg_dir}/usr/share/gmf-residue-pkg/.hypothesis/examples/abc123"
printf '%s' 'cache' > "${pkg_dir}/usr/lib/gmf-residue-pkg/.mypy_cache/entry"
printf '%s' 'cache' > "${pkg_dir}/usr/share/gmf-residue-pkg/.pytest_cache/entry"

dest_dir="${work_dir}/dest"
mkdir --parents -- "${dest_dir}"

## CI=true is AMBIENT in a GitHub Actions runner; clear it so the force-exec heuristic
## does not perturb this test (it is orthogonal to residue handling).
rc=0
(
   cd -- "${pkg_dir}" \
   && env CI= DESTDIR="${dest_dir}" "${genmkfile_bin}" install
) > "${work_dir}/install.log" 2>&1 || rc=$?

if [ "${rc}" -eq 0 ]; then
   pass 'install exited 0 on a tree carrying build residue'
else
   fail "install aborted (rc=${rc}) on a tree with build residue: $(tail -5 -- "${work_dir}/install.log")"
fi

## The real files must be installed.
present() {
   local desc="$1" path="$2"
   if [ -e "${path}" ]; then
      pass "${desc}"
   else
      fail "${desc}: missing '${path}'"
   fi
}

## Residue must NOT be installed (rsync excluded it; the loop must not resurrect it).
absent() {
   local desc="$1" path="$2"
   if [ ! -e "${path}" ]; then
      pass "${desc}"
   else
      fail "${desc}: '${path}' was installed but should have been excluded"
   fi
}

present 'a real executable is installed'      "${dest_dir}/usr/bin/realtool"
present 'a real data file is installed'        "${dest_dir}/usr/share/gmf-residue-pkg/data-file"

absent  '__pycache__ bytecode is not installed' "${dest_dir}/usr/lib/python3/dist-packages/gmf-residue-pkg/__pycache__/mod.cpython-311.pyc"
absent  'the __pycache__ directory is not installed' "${dest_dir}/usr/lib/python3/dist-packages/gmf-residue-pkg/__pycache__"
absent  'a loose .pyc is not installed'        "${dest_dir}/usr/bin/loose.pyc"
absent  'a loose .pyo is not installed'        "${dest_dir}/usr/bin/loose.pyo"
absent  '.hypothesis is not installed'         "${dest_dir}/usr/share/gmf-residue-pkg/.hypothesis"
absent  '.mypy_cache is not installed'         "${dest_dir}/usr/lib/gmf-residue-pkg/.mypy_cache"
absent  '.pytest_cache is not installed'       "${dest_dir}/usr/share/gmf-residue-pkg/.pytest_cache"

## CANARY: if install had silently copied nothing, every 'absent' check passes vacuously.
## Assert a real file really landed so the pass set is not empty.
if [ -f "${dest_dir}/usr/bin/realtool" ]; then
   pass 'canary: install really populated DESTDIR'
else
   fail 'canary: DESTDIR empty -- the residue-absence checks are vacuous'
fi

printf '%s\n' "" "${checks} check(s), ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: build residue is excluded and never aborts the install'
exit 0

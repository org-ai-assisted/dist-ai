#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the genmkfile target-dispatch optimization.
##
## genmkfile's main dispatch splits build-machine setup into a cheap
## "dependencies only" path (make_get_dependencies) and the full
## "version info" path (make_get_variables). Only deb-build-dep /
## deb-run-dep / deb-all-dep may take the cheap path. Targets that touch
## any variable set by make_get_variables -- the upstream/debian tarball
## paths, the .dsc / .changes file names, make_package_list -- MUST take
## the full path.
##
## Two commits once mis-classified three such targets into the cheap
## group:
##   deb-cleanup                      -> make_undist et al. need
##                                       make_upstream_tarball_relative_path
##   reprepro-remove / reprepro-add   -> make_reprepro_shared needs
##                                       make_main_changes_file and
##                                       make_package_list
## The symptom was an immediate abort, e.g.:
##   make_upstream_tarball_relative_path: unbound variable
##
## This test runs each of the three targets against a throwaway minimal
## Debian source package and asserts that genmkfile routes them through
## make_get_variables and never trips an "unbound variable" error. No
## root, no network, no real reprepro (a stub wrapper stands in).
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

make_fixture() {
   ## Minimal but real source package: a parseable changelog (so
   ## dpkg-parsechangelog yields a version) and a control file with a
   ## binary stanza (so make_get_variables can build make_package_list).
   local dir="$1"
   mkdir --parents -- "${dir}/debian"
   cat > "${dir}/debian/control" <<'CONTROL'
Source: gmf-test-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-test-pkg
Architecture: all
Depends: ${misc:Depends}
Description: throwaway fixture for genmkfile dispatch regression test
 Not a real package.
CONTROL
   cat > "${dir}/debian/changelog" <<'CHANGELOG'
gmf-test-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG
}

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

pkg_dir="${workdir}/pkg"
dist_dir="${workdir}/dist"
mkdir --parents -- "${dist_dir}"
make_fixture "${pkg_dir}"

## Stub reprepro wrapper so reprepro-{remove,add} reach completion
## without a real apt repository. It must accept any arguments and
## succeed; the test does not care what reprepro would do, only that
## genmkfile set up its variables first.
reprepro_stub="${workdir}/dm-reprepro-wrapper-stub"
cat > "${reprepro_stub}" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x -- "${reprepro_stub}"

## reprepro-add reads (and test -f's) the .changes file whose name
## make_get_variables computes: <source>_<version><revision>_<arch>.changes
## with arch = dpkg --print-architecture. run_target creates it per-run.
arch="$(dpkg --print-architecture)"

failures=0
run_target() {
   local target="$1" require_zero="$2" out rc=0
   printf '\n===== target: %s =====\n' "${target}"
   ## reprepro-add test -f's the .changes file make_get_variables names.
   ## Recreate it here, not once at setup: deb-cleanup (run earlier)
   ## sweeps *.changes out of DISTDIR, so a setup-time fixture would be
   ## gone by the time this target runs.
   if [ "${target}" = "reprepro-add" ]; then
      : > "${dist_dir}/gmf-test-pkg_1.0-1_${arch}.changes"
   fi
   ## make_*_tolower=false: genmkfile otherwise lowercases the WHOLE
   ## tarball path (DISTDIR included), then realpath's it for existence.
   ## A mktemp DISTDIR contains uppercase, so the lowercased parent would
   ## not exist and realpath would fail -- an artifact of the temp path,
   ## unrelated to the dispatch routing under test. Real build DISTDIRs
   ## are lowercase, so this never bites in practice.
   out="$(
      cd "${pkg_dir}"
      DISTDIR="${dist_dir}" \
      make_reprepro_wrapper="${reprepro_stub}" \
      make_debdist_tolower=false \
      make_upstream_tarball_relative_path_tolower=false \
         "${genmkfile_bin}" "${target}" 2>&1
   )" || rc=$?

   if printf '%s\n' "${out}" | grep --quiet 'unbound variable'; then
      printf 'FAIL: %s tripped an "unbound variable" error (regression):\n' "${target}"
      printf '%s\n' "${out}" | grep 'unbound variable'
      failures=$(( failures + 1 ))
   fi

   if printf '%s\n' "${out}" | grep --quiet 'make_function_run: make_get_variables'; then
      printf 'PASS: %s routed through make_get_variables\n' "${target}"
   else
      printf 'FAIL: %s did NOT run make_get_variables (cheap-path mis-classification)\n' "${target}"
      failures=$(( failures + 1 ))
   fi

   if [ "${require_zero}" = "true" ] && [ "${rc}" -ne 0 ]; then
      printf 'FAIL: %s exited %s (expected 0):\n' "${target}" "${rc}"
      printf '%s\n' "${out}" | tail -20
      failures=$(( failures + 1 ))
   fi
}

## deb-cleanup is fully self-contained -> demand a clean exit.
## reprepro-{remove,add} run against the stub -> demand a clean exit too.
run_target deb-cleanup      true
run_target reprepro-remove  true
run_target reprepro-add     true

printf '\n===== summary =====\n'
if [ "${failures}" -eq 0 ]; then
   printf 'OK: all genmkfile dispatch regression checks passed\n'
   exit 0
fi
printf 'FAILED: %s genmkfile dispatch regression check(s) failed\n' "${failures}"
exit 1

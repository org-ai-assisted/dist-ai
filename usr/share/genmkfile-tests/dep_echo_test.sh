#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the genmkfile deb-{build,run,all}-dep-echo targets.
##
## These echo the dependency package names (what the matching deb-*-dep target would
## install) to STDOUT, one per line, WITHOUT installing -- so a caller can capture them
## into a variable (e.g. to batch-install several packages' deps in one apt-get).
##
## The load-bearing property: STDOUT must be a CLEAN machine-readable list. genmkfile's own
## diagnostics ("INFO: command:", "INFO: make_function_run:") normally go to stdout; for the
## echo targets they are routed to STDERR (via make_quiet_stdout) so a capture is not
## polluted. This test asserts:
##   1. deb-all-dep-echo stdout carries the deps + NO "INFO:" line (clean);
##   2. its INFO diagnostics DO appear on stderr (routed, not lost);
##   3. deb-build-dep-echo echoes build deps but NOT the runtime-only dep;
##   4. deb-run-dep-echo echoes the runtime dep but NOT the build-only dep;
##   5. CANARY: a NON-echo target still emits INFO on STDOUT -- so the make_output_info
##      stderr-routing did not change behaviour for every other target.
##
## No root, no network, no install (echo only). Subject: the genmkfile CHECKOUT.

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

make_fixture() {
   ## Distinguishable build-only and runtime-only deps so the -echo variants can be told
   ## apart. Fake names are fine: -echo never installs, it only parses + prints.
   local dir="$1"
   mkdir --parents -- "${dir}/debian"
   cat > "${dir}/debian/control" <<'CONTROL'
Source: gmf-echo-test-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13), fixture-build-only-dep

Package: gmf-echo-test-pkg
Architecture: all
Depends: fixture-run-only-dep, ${misc:Depends}
Description: throwaway fixture for the genmkfile dep-echo regression test
 Not a real package.
CONTROL
   cat > "${dir}/debian/changelog" <<'CHANGELOG'
gmf-echo-test-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG
}

genmkfile_bin="$(locate_genmkfile)" || {
   printf '%s\n' "FATAL: no genmkfile found (set GENMKFILE_BIN, install genmkfile, or check out derivative-maker)" >&2
   exit 1
}
if [ -z "${GENMKFILE_BIN:-}" ] && [ "${genmkfile_bin}" = "/usr/bin/genmkfile" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

workdir="$(mktemp --directory)"
cleanup_workdir() {
   # shellcheck disable=SC2317
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup_workdir EXIT

pkg_dir="${workdir}/pkg"
make_fixture "${pkg_dir}"
## make_get_distdir runs for every target and aborts if DISTDIR does not exist, so create
## the dist dir the run_echo helper points DISTDIR at (deb-*-dep-echo itself writes nothing
## there; in real use DISTDIR defaults to the package's parent, which exists).
mkdir --parents -- "${workdir}/dist"

failures=0
fail() { printf '%s\n' "FAIL: $1"; failures=$(( failures + 1 )); }
pass() { printf '%s\n' "PASS: $1"; }

## Run a target with stdout and stderr captured SEPARATELY (the whole point is that the
## payload lands on stdout and the diagnostics on stderr).
run_echo() {  ## $1=target ; sets echo_out (stdout) + echo_err (stderr)
   local target="$1"
   echo_out="$(cd "${pkg_dir}" && DISTDIR="${workdir}/dist" make_use_cowbuilder=false "${genmkfile_bin}" "${target}" 2>"${workdir}/err")"
   echo_err="$(cat "${workdir}/err")"
}

## --- deb-all-dep-echo: clean stdout + stderr-routed diagnostics ---
run_echo deb-all-dep-echo
if grep --quiet 'INFO:' <<< "${echo_out}"; then
   fail "deb-all-dep-echo leaked an INFO line onto stdout (stdout must be clean):"
   grep 'INFO:' <<< "${echo_out}" | head -3
else
   pass "deb-all-dep-echo stdout carries no INFO line (clean for capture)"
fi
if grep --quiet 'INFO:' <<< "${echo_err}"; then
   pass "deb-all-dep-echo routed its INFO diagnostics to stderr"
else
   fail "deb-all-dep-echo emitted no INFO on stderr (diagnostics lost, not routed)"
fi
for dep in build-essential dctrl-tools debhelper-compat fixture-build-only-dep fixture-run-only-dep; do
   if grep --quiet --line-regexp --fixed-strings "${dep}" <<< "${echo_out}"; then
      pass "deb-all-dep-echo lists ${dep}"
   else
      fail "deb-all-dep-echo is missing ${dep}"
   fi
done

## --- deb-build-dep-echo: build deps, NOT the runtime-only dep ---
run_echo deb-build-dep-echo
if grep --quiet --line-regexp --fixed-strings 'fixture-build-only-dep' <<< "${echo_out}"; then
   pass "deb-build-dep-echo lists the build-only dep"
else
   fail "deb-build-dep-echo is missing the build-only dep"
fi
if grep --quiet --line-regexp --fixed-strings 'fixture-run-only-dep' <<< "${echo_out}"; then
   fail "deb-build-dep-echo wrongly lists the runtime-only dep"
else
   pass "deb-build-dep-echo excludes the runtime-only dep"
fi

## --- deb-run-dep-echo: runtime dep, NOT the build-only dep ---
run_echo deb-run-dep-echo
if grep --quiet --line-regexp --fixed-strings 'fixture-run-only-dep' <<< "${echo_out}"; then
   pass "deb-run-dep-echo lists the runtime-only dep"
else
   fail "deb-run-dep-echo is missing the runtime-only dep"
fi
if grep --quiet --line-regexp --fixed-strings 'fixture-build-only-dep' <<< "${echo_out}"; then
   fail "deb-run-dep-echo wrongly lists the build-only dep"
else
   pass "deb-run-dep-echo excludes the build-only dep"
fi

## --- CANARY: a NON-echo target still emits INFO on STDOUT ---
## Guards the make_output_info change: the stderr routing must be scoped to the -echo
## targets, not applied to every genmkfile invocation. 'help' emits "INFO: command: help"
## and has no side effects.
canary_out="$(cd "${pkg_dir}" && "${genmkfile_bin}" help 2>/dev/null)"
if grep --quiet 'INFO:' <<< "${canary_out}"; then
   pass "a non-echo target (help) still emits INFO on stdout (routing is echo-scoped)"
else
   fail "non-echo target lost its stdout INFO -- make_output_info routing is too broad"
fi

printf '%s\n' '' '===== summary ====='
if [ "${failures}" -eq 0 ]; then
   printf '%s\n' 'OK: all genmkfile dep-echo regression checks passed'
   exit 0
fi
printf '%s\n' "FAILED: ${failures} genmkfile dep-echo regression check(s) failed"
exit 1

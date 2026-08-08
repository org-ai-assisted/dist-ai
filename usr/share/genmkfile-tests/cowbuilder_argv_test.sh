#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The cowbuilder command line decides WHICH Debian suite, WHICH archive and WHICH
## chroot a package is built in. Every one of those is a precedence chain, and getting
## one wrong is silent: the .deb is produced, the exit code is 0, and only the contents
## are wrong.
##
## What is pinned:
##   --distribution   dist_build_apt_stable_release  ->  make_cowbuilder_distribution
##                    ->  lsb_release. Inverting this builds a package for one suite
##                    inside a chroot of another.
##   --mirror         dist_build_apt_sources_mirror  ->  APPROX_PROXY_ENABLE (the
##                    derivative-maker apt-cacher)  ->  deb.debian.org. A wrong branch
##                    silently builds against the wrong archive, or against a cache
##                    proxy that is not running.
##   --basepath vs --buildplace   'base.cow_<arch>' and 'cow.cow_<arch>' differ by one
##                    character. Swapping them corrupts the shared read-only base
##                    instead of the throwaway snapshot, and nothing in the output says
##                    so.
##   make_cow_suffix  the parallel-build isolation knob. If it stops being appended,
##                    two concurrent deb-pkg runs quietly share one writable cow and
##                    corrupt each other.
##
## Hermetic: 'sudo' and 'cowbuilder' are stubbed on PATH and record their argv. The
## real genmkfile runs against a throwaway minimal source package. No root, no chroot,
## no network -- only the command line is under test, which is where these bugs live.
##
## Exit: 0 pass | 1 fail | 77 skip when genmkfile is not present.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

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
   printf '%s\n' 'SKIP: genmkfile not found (set GENMKFILE_BIN).' >&2
   exit 77
fi
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-cowbuilder-argv.XXXXXX")"
failures=0
checks=0

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_handler EXIT

stub_dir="${work_dir}/bin"
pkg_dir="${work_dir}/pkg"
dist_dir="${work_dir}/dist"
mkdir --parents -- "${stub_dir}" "${pkg_dir}/debian" "${dist_dir}"

## sudo stub: drop 'sudo' and run the rest, so the recorded argv is cowbuilder's own.
cat > "${stub_dir}/sudo" <<'STUB'
#!/bin/bash
## Run the child and forward its status; a replaced process leaves no frame.
"$@"
exit "$?"
STUB

## cowbuilder stub: record argv, one field per line, and succeed.
cat > "${stub_dir}/cowbuilder" <<'STUB'
#!/bin/bash
set -o nounset
for arg in "$@"; do
   printf '%s\n' "${arg}" >> "${GENMKFILE_ARGV_LOG}"
done
exit 0
STUB

## lsb_release stub: a distinctive codename, so the fallback branch is identifiable.
cat > "${stub_dir}/lsb_release" <<'STUB'
#!/bin/bash
printf '%s\n' 'stub-codename'
STUB

chmod 0755 -- "${stub_dir}/sudo" "${stub_dir}/cowbuilder" "${stub_dir}/lsb_release"

cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: gmf-argv-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-argv-pkg
Architecture: all
Depends: ${misc:Depends}
Description: throwaway fixture for the cowbuilder argv test
 Not a real package.
CONTROL

cat > "${pkg_dir}/debian/changelog" <<'CHANGELOG'
gmf-argv-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG

cat > "${pkg_dir}/debian/rules" <<'RULES'
#!/usr/bin/make -f
%:
	dh $@
RULES
chmod 0755 -- "${pkg_dir}/debian/rules"

## deb-pkg-build refuses to start without the tarballs and .dsc, and verifies the
## expected .deb afterwards. Seed all of them: the build itself is stubbed out, and
## what is under test is the argv, not the artifacts.
seed_artifacts() {
   printf '%s\n' 'fixture' > "${dist_dir}/gmf-argv-pkg_1.0.orig.tar.xz"
   printf '%s\n' 'fixture' > "${dist_dir}/gmf-argv-pkg_1.0-1.debian.tar.xz"
   printf '%s\n' 'fixture' > "${dist_dir}/gmf-argv-pkg_1.0-1.dsc"
   printf '%s\n' 'fixture' > "${dist_dir}/gmf-argv-pkg_1.0-1_all.deb"
}

## Run deb-pkg-build with the given environment and leave the recorded argv in
## ${argv_log}. Returns genmkfile's exit status.
run_build() {
   argv_log="${work_dir}/argv.log"
   safe-rm --force -- "${argv_log}"
   printf '%s' '' > "${argv_log}"
   seed_artifacts
   local rc=0
   (
      cd -- "${pkg_dir}" \
      && PATH="${stub_dir}:${PATH}" \
         GENMKFILE_ARGV_LOG="${argv_log}" \
         make_use_cowbuilder=true \
         make_use_lintian=false \
         make_cowbuilder_dist_folder="${dist_dir}" \
         cowbuilder_cache_dir="${work_dir}/cache" \
         env "$@" "${genmkfile_bin}" deb-pkg-build
   ) > "${work_dir}/build.log" 2>&1 || rc=$?
   return "${rc}"
}

## Value of a recorded option, e.g. arg_value --distribution.
arg_value() {
   local want="$1" prev='' line
   while IFS= read -r line; do
      if [ "${prev}" = "${want}" ]; then
         printf '%s\n' "${line}"
         return 0
      fi
      prev="${line}"
   done < "${argv_log}"
   return 1
}

check() {
   local desc="$1" want="$2" got="$3"
   checks=$(( checks + 1 ))
   if [ "${want}" = "${got}" ]; then
      printf '%s\n' "PASS  ${desc}: ${got}"
   else
      failures=$(( failures + 1 ))
      printf '%s\n' "FAIL  ${desc}: want '${want}', got '${got}'" >&2
   fi
}

## --- distribution precedence ------------------------------------------------
run_build dist_build_apt_stable_release=from-dm || true
check 'distribution: dist_build_apt_stable_release wins' 'from-dm' "$(arg_value --distribution || printf '<none>')"

run_build dist_build_apt_stable_release=from-dm make_cowbuilder_distribution=explicit || true
check 'distribution: an explicit setting is not overridden' 'explicit' "$(arg_value --distribution || printf '<none>')"

run_build || true
check 'distribution: falls back to lsb_release' 'stub-codename' "$(arg_value --distribution || printf '<none>')"

## --- mirror precedence ------------------------------------------------------
run_build dist_build_apt_sources_mirror=http://dm.example.com/debian || true
check 'mirror: dist_build_apt_sources_mirror wins' 'http://dm.example.com/debian' "$(arg_value --mirror || printf '<none>')"

run_build APPROX_PROXY_ENABLE=yes || true
check 'mirror: the approx cacher is used when enabled' 'http://127.0.0.1:9977/debian' "$(arg_value --mirror || printf '<none>')"

run_build || true
check 'mirror: falls back to deb.debian.org' 'https://deb.debian.org/debian' "$(arg_value --mirror || printf '<none>')"

## The dm mirror must beat the proxy: with both set, a build that silently went to the
## cacher would be building against a different archive than dm asked for.
run_build dist_build_apt_sources_mirror=http://dm.example.com/debian APPROX_PROXY_ENABLE=yes || true
check 'mirror: dm setting beats the approx cacher' 'http://dm.example.com/debian' "$(arg_value --mirror || printf '<none>')"

## --- basepath vs buildplace -------------------------------------------------
## One character apart. A swap corrupts the shared read-only base instead of the
## throwaway snapshot, and nothing in the output would say so.
run_build || true
check 'basepath is the shared read-only base' "${work_dir}/cache/base.cow_$(dpkg --print-architecture)" \
   "$(arg_value --basepath || printf '<none>')"
check 'buildplace is the throwaway snapshot' "${work_dir}/cache/cow.cow_$(dpkg --print-architecture)" \
   "$(arg_value --buildplace || printf '<none>')"

## --- parallel-build isolation ------------------------------------------------
run_build make_cow_suffix=.7 || true
check 'make_cow_suffix isolates the writable cow' "${work_dir}/cache/cow.cow_$(dpkg --print-architecture).7" \
   "$(arg_value --buildplace || printf '<none>')"
check 'and never the shared base' "${work_dir}/cache/base.cow_$(dpkg --print-architecture)" \
   "$(arg_value --basepath || printf '<none>')"

## --- CANARY -----------------------------------------------------------------
## Every assertion above reads ${argv_log}. If the stub were never reached the log
## would be empty and arg_value would return '<none>' for everything -- which must not
## be mistaken for a pass.
checks=$(( checks + 1 ))
if [ -s "${argv_log}" ] && grep --quiet -- '--buildresult' "${argv_log}"; then
   printf '%s\n' 'PASS  canary: the cowbuilder stub really was invoked'
else
   failures=$(( failures + 1 ))
   printf '%s\n' 'FAIL  canary: no cowbuilder argv recorded -- every check above is vacuous' >&2
fi

printf '%s\n' "" "${checks} check(s), ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: cowbuilder argv precedence holds'
exit 0

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Multi-architecture binary builds hinge on one flag, all_package_debs_are_arch_all,
## and one skip decision in make_deb_pkg_build_shared. Both were silently wrong:
##
##   - The flag is 'true' only when EVERY binary a package emits is
##     'Architecture: all'. The secondary-architecture skip must fire exactly in
##     that case (the arch-all .debs were already produced while targeting the
##     first architecture). It instead fired when the flag was 'false', i.e. when
##     the package DID emit an architecture-dependent binary -- so the arch64/arm64
##     .deb was never built for any non-first architecture, while pure arch-all
##     packages were needlessly rebuilt under emulation.
##
##   - A stanza whose 'Architecture:' restriction excludes the target produces no
##     artifact, yet it cleared the flag too, forcing a pointless secondary build.
##
##   - The secondary-build cleanup 'safe-rm -- .../*_all.deb' runs with nullglob
##     unset. A pure 'Architecture: any' package produces no '*_all.deb', so the
##     unmatched glob passed the literal pattern to safe-rm, which aborts the build
##     under errexit. This only becomes reachable once the skip is fixed.
##
## All three are invisible from a single-architecture build (the default), so this
## suite drives the per-architecture loop with make_cross_build_platform_list.
##
## Hermetic: 'sudo' and 'cowbuilder' are stubbed on PATH. The cowbuilder stub
## records every invocation and materialises the .debs the fixture would produce, so
## the real per-architecture loop, artifact verification and cleanup all run without
## root, chroot, network or an actual build. What is under test is which
## architectures get built and whether the cleanup survives a missing arch-all .deb.
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
   printf '%s\n' 'SKIP: genmkfile not found (set GENMKFILE_BIN).' >&2
   exit 77
fi
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-secondary-arch.XXXXXX")"
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
build_log="${work_dir}/build.log"
invocation_log="${work_dir}/cowbuilder-invocations.log"
mkdir --parents -- "${stub_dir}" "${pkg_dir}/debian" "${dist_dir}"

## sudo stub: drop 'sudo' and run the rest, so the child cowbuilder is reached.
cat > "${stub_dir}/sudo" <<'STUB'
#!/bin/bash
## 'env ...' follows 'sudo' in the real argv; run the remainder verbatim.
"$@"
exit "$?"
STUB

## cowbuilder stub: record one line per invocation, and materialise the .debs the
## fixture emits so the loop's verification and cleanup run against real files.
##   GENMKFILE_STUB_EMIT_ARCH_DEB=true  -> create <base>_<arch>.deb
##   GENMKFILE_STUB_EMIT_ALL_DEB=true   -> create <base>_all.deb
## <arch> is read from '--architecture' (the target architecture when a package is
## not trivially cross-buildable, which the fixtures are not); <base> is the .dsc
## name passed via '--build', minus its '.dsc' suffix.
cat > "${stub_dir}/cowbuilder" <<'STUB'
#!/bin/bash
set -o nounset
arch=''
dsc=''
buildresult=''
prev=''
for arg in "$@"; do
   case "${prev}" in
      --architecture)
         arch="${arg}"
         ;;
      --build)
         dsc="${arg}"
         ;;
      --buildresult)
         buildresult="${arg}"
         ;;
   esac
   prev="${arg}"
done
printf '%s\n' "arch=${arch}" >> "${GENMKFILE_INVOCATION_LOG}"
base="$(basename -- "${dsc}")"
base="${base%.dsc}"
if [ "${GENMKFILE_STUB_EMIT_ARCH_DEB:-false}" = "true" ]; then
   printf '%s\n' 'fixture' > "${buildresult}/${base}_${arch}.deb"
fi
if [ "${GENMKFILE_STUB_EMIT_ALL_DEB:-false}" = "true" ]; then
   printf '%s\n' 'fixture' > "${buildresult}/${base}_all.deb"
fi
exit 0
STUB

## lsb_release stub: keeps the distribution lookup off the real system.
cat > "${stub_dir}/lsb_release" <<'STUB'
#!/bin/bash
printf '%s\n' 'stub-codename'
STUB

chmod 0755 -- "${stub_dir}/sudo" "${stub_dir}/cowbuilder" "${stub_dir}/lsb_release"

cat > "${pkg_dir}/debian/rules" <<'RULES'
#!/usr/bin/make -f
%:
	dh $@
RULES
chmod 0755 -- "${pkg_dir}/debian/rules"

cat > "${pkg_dir}/debian/changelog" <<'CHANGELOG'
gmf-sec-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG

## Write debian/control with the given binary stanza block appended.
write_control() {
   local stanzas="$1"
   cat > "${pkg_dir}/debian/control" <<CONTROL
Source: gmf-sec-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

${stanzas}
CONTROL
}

## Source artifacts are architecture-independent and produced once; seed them so
## deb-pkg-build does not refuse to start. The .debs are produced by the stub, NOT
## seeded here -- seeding them would mask a stub that never ran.
seed_source_artifacts() {
   printf '%s\n' 'fixture' > "${dist_dir}/gmf-sec-pkg_1.0.orig.tar.xz"
   printf '%s\n' 'fixture' > "${dist_dir}/gmf-sec-pkg_1.0-1.debian.tar.xz"
   printf '%s\n' 'fixture' > "${dist_dir}/gmf-sec-pkg_1.0-1.dsc"
}

## style-ok: allow-lintian-disable
## R-213 waiver: this unit test drives genmkfile against a STUBBED cowbuilder to
## verify the per-architecture skip decision and invocation log, not to produce a
## real deliverable. lintian and debsign are turned off so the unit exercises the
## build-dispatch logic without invoking the real packaging tools.

## Run 'genmkfile deb-pkg-build' across ${arch_list} and return its exit status.
## The recorded cowbuilder invocations are left in ${invocation_log}.
run_build() {
   local arch_list="$1" emit_arch="$2" emit_all="$3"
   printf '%s' '' > "${invocation_log}"
   ## Drop any .debs a previous case left in dist so each run starts clean.
   safe-rm --force -- "${dist_dir}"/*.deb 2>/dev/null || true
   seed_source_artifacts
   local rc=0
   (
      cd -- "${pkg_dir}" \
      && PATH="${stub_dir}:${PATH}" \
         GENMKFILE_INVOCATION_LOG="${invocation_log}" \
         GENMKFILE_STUB_EMIT_ARCH_DEB="${emit_arch}" \
         GENMKFILE_STUB_EMIT_ALL_DEB="${emit_all}" \
         make_use_cowbuilder=true \
         make_use_lintian=false \
         make_use_debsign=false \
         make_cowbuilder_dist_folder="${dist_dir}" \
         cowbuilder_cache_dir="${work_dir}/cache" \
         make_cross_build_platform_list="${arch_list}" \
         "${genmkfile_bin}" deb-pkg-build
   ) > "${build_log}" 2>&1 || rc=$?
   return "${rc}"
}

invocation_count() {
   local count=0 line
   while IFS= read -r line; do
      case "${line}" in
         arch=*)
            count=$(( count + 1 ))
            ;;
      esac
   done < "${invocation_log}"
   printf '%s' "${count}"
}

check() {
   local desc="$1" want="$2" got="$3"
   checks=$(( checks + 1 ))
   if [ "${want}" = "${got}" ]; then
      printf '%s\n' "PASS  ${desc}: ${got}"
   else
      failures=$(( failures + 1 ))
      printf '%s\n' "FAIL  ${desc}: want '${want}', got '${got}'" >&2
      printf '%s\n' "----- build.log -----" >&2
      cat -- "${build_log}" >&2 || true
      printf '%s\n' "---------------------" >&2
   fi
}

## --- Case A: pure 'Architecture: any' ---------------------------------------
## Must build on BOTH architectures (the arm64 .deb has to exist). The stub emits
## only the arch-dependent .deb, never an arch-all one, so the secondary cleanup
## meets a glob that matches nothing -- which must not abort the build.
write_control 'Package: gmf-sec-pkg
Architecture: any
Depends: ${misc:Depends}
Description: arch-dependent fixture
 Not a real package.'
a_rc=0
run_build 'amd64 arm64' true false || a_rc=$?
check 'any: architecture-dependent secondary build is not skipped' '2' "$(invocation_count)"
check 'any: build survives a secondary cleanup with no arch-all .deb' '0' "${a_rc}"

## --- Case B: pure 'Architecture: all' ---------------------------------------
## The arch-all .deb is built once, while targeting the first architecture; the
## secondary architecture must be skipped.
write_control 'Package: gmf-sec-pkg
Architecture: all
Depends: ${misc:Depends}
Description: arch-independent fixture
 Not a real package.'
run_build 'amd64 arm64' false true || true
check 'all: arch-all-only package skips the secondary architecture' '1' "$(invocation_count)"

## --- Case C: 'Architecture: all' plus an excluded arch-specific stanza -------
## The 'amd64' stanza produces nothing while targeting s390x, so it must not force
## a secondary build: the package still emits only an arch-all binary there.
write_control 'Package: gmf-sec-pkg
Architecture: all
Depends: ${misc:Depends}
Description: arch-independent fixture
 Not a real package.

Package: gmf-sec-pkg-amd64
Architecture: amd64
Depends: ${misc:Depends}
Description: amd64-only fixture
 Not a real package.'
run_build 'amd64 s390x' true true || true
check 'excluded stanza: arch-all package still skips the secondary architecture' '1' "$(invocation_count)"

## --- CANARY -----------------------------------------------------------------
## Every count above reads ${invocation_log}. If the cowbuilder stub were never
## reached (wrong PATH, an early die) the log would be empty and every count would
## be '0' -- which must not read as a pass. The first architecture always builds,
## so at least one invocation must have been recorded by the last run.
checks=$(( checks + 1 ))
if [ -s "${invocation_log}" ]; then
   printf '%s\n' 'PASS  canary: the cowbuilder stub really was invoked'
else
   failures=$(( failures + 1 ))
   printf '%s\n' 'FAIL  canary: no cowbuilder invocation recorded -- every check above is vacuous' >&2
fi

printf '%s\n' "" "${checks} check(s), ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: secondary-architecture build selection holds'
exit 0

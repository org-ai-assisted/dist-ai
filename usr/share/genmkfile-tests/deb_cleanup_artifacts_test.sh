#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 'genmkfile deb-cleanup' must clear THIS package's artifacts out of DISTDIR, all of
## them, and nothing belonging to another package.
##
## DISTDIR is the .deb cache that deb-pkg and reprepro read from, so both directions
## are silent when wrong: leftovers mean a later build can publish or install a stale
## binary, and over-deletion silently destroys another package's cached artifacts.
##
## Two shapes the glob table missed, both verified against real filenames:
##
##   orig tarball        pkg_1.0.orig.tar.xz     named from make_pkg_version WITHOUT
##                                               the revision, so it carries no hyphen
##   revision-less .deb  pkg_2.0_all.deb         a version with no Debian revision
##
## A pattern requiring a literal '-' matches neither. The current version's orig
## tarball was removed anyway by the exact-path fallback at the end of make_deb_cleanup,
## which is what hid the first case: every PREVIOUS version's tarball accumulated.
##
## Hermetic: seeds a DISTDIR with labelled artifacts and runs the real genmkfile against
## a throwaway minimal source package. No root, no network, no chroot.
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

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-cleanup-artifacts.XXXXXX")"
failures=0

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_handler EXIT

pkg_dir="${work_dir}/pkg"
dist_dir="${work_dir}/dist"
mkdir --parents -- "${pkg_dir}/debian" "${dist_dir}"

cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: gmf-clean-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-clean-pkg
Architecture: all
Depends: ${misc:Depends}
Description: throwaway fixture for the deb-cleanup artifact sweep test
 Not a real package.
CONTROL

cat > "${pkg_dir}/debian/changelog" <<'CHANGELOG'
gmf-clean-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG

## Artifacts that MUST be swept: this package, any version, with or without a revision.
must_go=(
   'gmf-clean-pkg_1.0-1_all.deb'
   'gmf-clean-pkg_0.9-1_all.deb'
   'gmf-clean-pkg_2.0_all.deb'
   'gmf-clean-pkg-dbgsym_1.0-1_amd64.deb'
   'gmf-clean-pkg_1.0-1_amd64.buildinfo'
   'gmf-clean-pkg_1.0-1.debian.tar.xz'
   'gmf-clean-pkg_1.0-1.dsc'
   'gmf-clean-pkg_1.0-1_amd64.changes'
   'gmf-clean-pkg_1.0-1_source.changes'
   'gmf-clean-pkg_1.0.orig.tar.xz'
   'gmf-clean-pkg_0.9.orig.tar.xz'
)

## Artifacts that MUST survive: a different package, including one whose name merely
## starts with the same text. Over-deletion here silently destroys another package's
## cached build.
must_stay=(
   'otherpkg_1.0-1_all.deb'
   'otherpkg_1.0.orig.tar.xz'
   'gmf-clean-pkg-extra_1.0-1_all.deb'
   'gmf-clean-pkg-extra_1.0.orig.tar.xz'
)

for artifact in "${must_go[@]}" "${must_stay[@]}"; do
   printf '%s\n' 'fixture artifact' > "${dist_dir}/${artifact}"
done

## deb-cleanup runs 'debian/rules clean', which needs a rules file.
cat > "${pkg_dir}/debian/rules" <<'RULES'
#!/usr/bin/make -f
%:
	dh $@
RULES
chmod 0755 -- "${pkg_dir}/debian/rules"

cleanup_rc=0
(
   cd -- "${pkg_dir}" \
   && make_cowbuilder_dist_folder="${dist_dir}" \
      make_use_cowbuilder=true \
      "${genmkfile_bin}" deb-cleanup
) > "${work_dir}/cleanup.log" 2>&1 || cleanup_rc=$?

if [ "${cleanup_rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: deb-cleanup exited ${cleanup_rc}" >&2
   tail -20 -- "${work_dir}/cleanup.log" >&2
   failures=$(( failures + 1 ))
else
   printf '%s\n' 'PASS: deb-cleanup exited 0'
fi

for artifact in "${must_go[@]}"; do
   if [ -e "${dist_dir}/${artifact}" ]; then
      printf '%s\n' "FAIL: left behind: ${artifact}" >&2
      failures=$(( failures + 1 ))
   else
      printf '%s\n' "PASS: swept: ${artifact}"
   fi
done

for artifact in "${must_stay[@]}"; do
   if [ -e "${dist_dir}/${artifact}" ]; then
      printf '%s\n' "PASS: survived (belongs to another package): ${artifact}"
   else
      printf '%s\n' "FAIL: DELETED another package's artifact: ${artifact}" >&2
      failures=$(( failures + 1 ))
   fi
done

printf '%s\n' "" "${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: deb-cleanup swept this package and spared the others'
exit 0

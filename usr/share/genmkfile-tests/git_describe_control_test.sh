#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for genmkfile's make_use_git_describe_for_version path
## when the repo ALSO ships debian/control (e.g. live-build).
##
## The flag tells genmkfile to take the version of the git tag from
## `git describe` instead of debian/changelog, for special repos that have
## no debian/control (Whonix-Installer, qubes-template-*, ...). Those repos
## have no deb to build, so make_get_variables short-circuits before it
## sets the tarball / .dsc path variables.
##
## live-build, however, sets the same flag but DOES ship debian/control and
## is built as a .deb via `genmkfile deb-icup`. The unconditional
## short-circuit left make_upstream_tarball_relative_path (and the debian
## tarball / .dsc paths) unset, so deb-cleanup -> make_undist aborted with:
##   make-helper-one.bsh: line ...: make_upstream_tarball_relative_path: unbound variable
##
## The fix gates the short-circuit on the ACTUAL absence of debian/control:
## a flagged repo that has debian/control falls through to the normal path
## and gets the deb variables, WHILE still taking its git tag version from
## `git describe` (so `genmkfile git-verify` keeps comparing against the
## repo's commit_<sha> tag, not the changelog version).
##
## This test asserts both halves on a throwaway flag+control fixture:
##   1. deb-cleanup is routed through make_get_variables, never trips an
##      "unbound variable" error, and exits 0 (deb variables are set).
##   2. git-tag-show still reports the git-describe tag version
##      (commit_<sha>), NOT the changelog version (the git tag scheme is
##      preserved).
##
## No root, no network. Subject selection (first that exists):
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
   ## A repo that mirrors live-build: debian/control (so it can build a
   ## .deb), a parseable changelog with an epoch (like live-build's
   ## 1:20250505), the make_use_git_describe_for_version override, and a
   ## single annotated git tag named commit_<sha> -- the scheme
   ## make_git_tag_sign creates and `git describe --abbrev=0` resolves
   ## (lightweight tags are invisible to plain `git describe`).
   local dir="$1"
   mkdir --parents -- "${dir}/debian/source"
   cat > "${dir}/debian/control" <<'CONTROL'
Source: gmf-gitdescribe-pkg
Section: misc
Priority: optional
Maintainer: test <test@example.com>
Build-Depends: debhelper-compat (= 13)

Package: gmf-gitdescribe-pkg
Architecture: all
Depends: ${misc:Depends}
Description: throwaway fixture: git-describe flag WITH debian/control
 Not a real package.
CONTROL
   cat > "${dir}/debian/changelog" <<'CHANGELOG'
gmf-gitdescribe-pkg (1:20250505) unstable; urgency=medium

  * Fixture with an epoch version, like live-build.

 -- test <test@example.com>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG
   printf '3.0 (native)\n' > "${dir}/debian/source/format"
   printf '#!/usr/bin/make -f\n%%:\n\tdh $@\n' > "${dir}/debian/rules"
   chmod +x -- "${dir}/debian/rules"
   printf '#!/bin/bash\nmake_use_git_describe_for_version=true\n' \
      > "${dir}/make-helper-overrides.bsh"
   chmod +x -- "${dir}/make-helper-overrides.bsh"

   git -C "${dir}" init --quiet
   git -C "${dir}" config user.email test@example.com
   git -C "${dir}" config user.name test
   git -C "${dir}" add --all
   git -C "${dir}" commit --quiet --message init
   fixture_tag="commit_$(git -C "${dir}" rev-parse HEAD)"
   ## Annotated tag (not lightweight): plain `git describe` only sees these.
   git -C "${dir}" tag --annotate --message . -- "${fixture_tag}"
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

fixture_tag=""
pkg_dir="${workdir}/pkg"
dist_dir="${workdir}/dist"
mkdir --parents -- "${dist_dir}"
make_fixture "${pkg_dir}"

failures=0

## 1) deb-cleanup must be routed through make_get_variables, set the deb
##    path variables (no "unbound variable"), and exit cleanly.
printf '\n===== deb-cleanup (flag + debian/control) =====\n'
cleanup_out=""
cleanup_rc=0
cleanup_out="$(
   cd "${pkg_dir}"
   DISTDIR="${dist_dir}" "${genmkfile_bin}" deb-cleanup 2>&1
)" || cleanup_rc=$?

if printf '%s\n' "${cleanup_out}" | grep --quiet 'unbound variable'; then
   printf 'FAIL: deb-cleanup tripped an "unbound variable" error (regression):\n'
   printf '%s\n' "${cleanup_out}" | grep 'unbound variable'
   failures=$(( failures + 1 ))
else
   printf 'PASS: deb-cleanup did not trip an "unbound variable" error\n'
fi

if printf '%s\n' "${cleanup_out}" | grep --quiet 'make_function_run: make_get_variables'; then
   printf 'PASS: deb-cleanup routed through make_get_variables\n'
else
   printf 'FAIL: deb-cleanup did NOT run make_get_variables\n'
   failures=$(( failures + 1 ))
fi

if [ "${cleanup_rc}" -eq 0 ]; then
   printf 'PASS: deb-cleanup exited 0\n'
else
   printf 'FAIL: deb-cleanup exited %s (expected 0):\n' "${cleanup_rc}"
   printf '%s\n' "${cleanup_out}" | tail -20
   failures=$(( failures + 1 ))
fi

## 2) The git tag version must still come from `git describe` (the
##    commit_<sha> tag), NOT from the changelog version. Otherwise
##    git-verify would compare the changelog version against the repo's
##    commit_<sha> tag and fail.
printf '\n===== git-tag-show (version source preserved) =====\n'
tag_show_out="$(
   cd "${pkg_dir}"
   DISTDIR="${dist_dir}" "${genmkfile_bin}" git-tag-show 2>/dev/null
)"
## The printf'd version is the only bare commit_<40hex> / 20250505 line.
tag_version="$(printf '%s\n' "${tag_show_out}" \
   | grep --extended-regexp '^(commit_[0-9a-f]{40}|1?:?20250505)$' | head -1 || true)"

if [ "${tag_version}" = "${fixture_tag}" ]; then
   printf 'PASS: git-tag-show reported the git-describe tag (%s)\n' "${tag_version}"
else
   printf 'FAIL: git-tag-show reported "%s", expected the git tag "%s"\n' \
      "${tag_version}" "${fixture_tag}"
   failures=$(( failures + 1 ))
fi

printf '\n===== summary =====\n'
if [ "${failures}" -eq 0 ]; then
   printf 'OK: all genmkfile git-describe+control regression checks passed\n'
   exit 0
fi
printf 'FAILED: %s genmkfile git-describe+control regression check(s) failed\n' "${failures}"
exit 1

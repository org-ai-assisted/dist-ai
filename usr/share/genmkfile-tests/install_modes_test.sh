#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 'genmkfile install' fixes the mode of every file it installs. The outcome is a
## permission bit, which is the definition of silently wrong: the package builds, the
## file is present, and only the mode is off -- an executable that lands 0644 fails at
## runtime with EACCES, far from the build that caused it.
##
## Pinned here:
##   - an executable source installs 0755, a non-executable one 0644
##   - the CI force-exec workaround: under CI=true an executable location (/usr/bin,
##     /usr/sbin, /usr/libexec/<source-pkg>/) is forced +x, because some upstream push
##     paths land every tree entry at 100644 and the bit is lost before genmkfile ever
##     sees it
##   - GENMKFILE_CI_FORCE_EXEC=0 turns that off
##   - the forcing is location-scoped: a data file elsewhere is NOT made executable
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

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-install-modes.XXXXXX")"
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
   "${pkg_dir}/usr/share/gmf-mode-pkg"

cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: gmf-mode-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-mode-pkg
Architecture: all
Description: throwaway fixture for the install-mode test
 Not a real package.
CONTROL

cat > "${pkg_dir}/debian/changelog" <<'CHANGELOG'
gmf-mode-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG

printf '%s\n' '#!/bin/bash' 'true' > "${pkg_dir}/usr/bin/exec-file"
chmod 0755 -- "${pkg_dir}/usr/bin/exec-file"
## An executable location, but the exec bit lost in transit -- the case CI force-exec
## exists for.
printf '%s\n' '#!/bin/bash' 'true' > "${pkg_dir}/usr/bin/lost-exec-bit"
chmod 0644 -- "${pkg_dir}/usr/bin/lost-exec-bit"
## A data file OUTSIDE an executable location: must never be forced executable.
printf '%s\n' 'data' > "${pkg_dir}/usr/share/gmf-mode-pkg/data-file"
chmod 0644 -- "${pkg_dir}/usr/share/gmf-mode-pkg/data-file"

## folder_permission_skip_list holds '/usr/src'. A file genuinely under it keeps the
## mode it arrived with; a file merely CONTAINING that text in its path must not.
mkdir --parents -- "${pkg_dir}/usr/src" "${pkg_dir}/usr/share/doc/gmf-mode-pkg/usr"
printf '%s\n' 'kept' > "${pkg_dir}/usr/src/keep-my-mode"
chmod 0600 -- "${pkg_dir}/usr/src/keep-my-mode"
## An in-tree symlink alias OUTSIDE the skip-list, pointing at the 0600 skip-list file. The
## mode-fix must SKIP a symlink: 'stat %a' on a symlink is always 0777 and 'chmod' FOLLOWS it,
## so processing this alias would chmod the 0600 target to 0644 -- loosening a protected file.
ln -s ../src/keep-my-mode "${pkg_dir}/usr/bin/keep-alias"
printf '%s\n' 'notes' > "${pkg_dir}/usr/share/doc/gmf-mode-pkg/usr/src-notes"
chmod 0600 -- "${pkg_dir}/usr/share/doc/gmf-mode-pkg/usr/src-notes"

## Run 'genmkfile install' into a fresh DESTDIR and leave it in ${dest_dir}.
run_install() {
   local tag="$1"
   shift
   dest_dir="${work_dir}/dest-${tag}"
   mkdir --parents -- "${dest_dir}"
   local rc=0
   (
      cd -- "${pkg_dir}" \
      && env DESTDIR="${dest_dir}" "$@" "${genmkfile_bin}" install
   ) > "${work_dir}/install-${tag}.log" 2>&1 || rc=$?
   return "${rc}"
}

mode_of() {
   stat -c %a -- "$1" 2>/dev/null || printf '%s' '<absent>'
}

check_mode() {
   local desc="$1" want="$2" path="$3" got
   got="$(mode_of "${path}")"
   if [ "${got}" = "${want}" ]; then
      pass "${desc}: ${got}"
   else
      fail "${desc}: want ${want}, got ${got} (${path})"
   fi
}

## --- ordinary install (no CI) ------------------------------------------------
## CI=true is AMBIENT in a GitHub Actions runner, so this case must clear it explicitly.
## Assuming it unset passed locally and failed in CI, where the force-exec heuristic
## fired and the "non-executable installs 0644" assertion saw 0755.
if run_install plain CI=; then
   pass 'install exited 0'
else
   fail "install failed: $(tail -3 -- "${work_dir}/install-plain.log")"
fi
check_mode 'an executable source installs 0755' '755' "${dest_dir}/usr/bin/exec-file"
check_mode 'a non-executable source installs 0644' '644' "${dest_dir}/usr/bin/lost-exec-bit"
check_mode 'a data file installs 0644' '644' "${dest_dir}/usr/share/gmf-mode-pkg/data-file"

## --- CI force-exec -----------------------------------------------------------
## Some upstream push paths land every tree entry at 100644, so the exec bit is gone
## before genmkfile sees it and the installed script fails with EACCES in CI.
run_install ci CI=true || true
check_mode 'CI forces +x in an executable location' '755' "${dest_dir}/usr/bin/lost-exec-bit"
check_mode 'CI leaves an already-executable file alone' '755' "${dest_dir}/usr/bin/exec-file"

## Scope matters: forcing +x everywhere would silently make data files executable.
check_mode 'CI does NOT force +x outside an executable location' '644' \
   "${dest_dir}/usr/share/gmf-mode-pkg/data-file"

## --- the opt-out -------------------------------------------------------------
run_install ci-off CI=true GENMKFILE_CI_FORCE_EXEC=0 || true
check_mode 'GENMKFILE_CI_FORCE_EXEC=0 disables the forcing' '644' \
   "${dest_dir}/usr/bin/lost-exec-bit"
check_mode 'and an already-executable file is unaffected by the opt-out' '755' \
   "${dest_dir}/usr/bin/exec-file"

## --- the skip-list is a PATH question, not a substring one -------------------
## A skip-list entry of '/usr/src' also matched '/usr/share/doc/x/usr/src-notes' under a
## substring test, so that file silently kept whatever mode it arrived with -- the same
## quiet wrong-permission outcome the checks above exist for.
run_install skiplist CI= || true
check_mode 'a file genuinely under a skipped folder keeps its mode' '600' \
   "${dest_dir}/usr/src/keep-my-mode"
check_mode 'a path merely CONTAINING the skip-list text is still mode-fixed' '644' \
   "${dest_dir}/usr/share/doc/gmf-mode-pkg/usr/src-notes"

## --- a stale destination special bit is NORMALISED to the source mode ---------
## git cannot store setuid/setgid/sticky, so the source never declares them: genmkfile installs
## to the SOURCE-declared mode (0755), and a stale destination setuid (e.g. left by a prior
## postinst, or on a re-install) is cleared -- keeping it would leave an updated 0755 binary
## silently setuid-root. Special bits are re-applied by maintainer scripts, not genmkfile.
run_install setuid CI= || true
chmod u+s -- "${dest_dir}/usr/bin/exec-file"
run_install setuid CI= || true
check_mode 'a stale setuid is normalised to the source mode on re-install' '755' \
   "${dest_dir}/usr/bin/exec-file"

## --- CANARY ------------------------------------------------------------------
## Every check above reads a path under DESTDIR. If install had silently copied
## nothing, mode_of would return '<absent>' everywhere -- which must not be mistaken
## for a pass, and is caught by asserting a file really landed.
if [ -f "${dest_dir}/usr/bin/exec-file" ]; then
   pass 'canary: install really populated DESTDIR'
else
   fail 'canary: DESTDIR is empty -- every mode check above is vacuous'
fi

printf '%s\n' "" "${checks} check(s), ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: install-time mode fixing holds'
exit 0

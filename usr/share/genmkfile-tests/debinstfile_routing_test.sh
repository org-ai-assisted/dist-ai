#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 'genmkfile debinstfile' decides which binary .deb each '#'-suffixed file lands in.
##
## There are ~150 such files in the derivative-maker tree, most of them in
## security-misc, split across several binary packages. This function is the only thing
## routing them. A bug in the three string operations that split the name produces a
## syntactically valid .install that puts files in the WRONG package, or drops them --
## the build succeeds, the .deb is produced, and nobody notices until a runtime file is
## missing on a user's system.
##
## Pinned here:
##   - '<path>#<pkg>' routes to debian/<pkg>.install as '<path>#<pkg> => /<path>'
##   - one .install per binary package, and a file with no '#' routes nowhere
##   - the dh-exec shebang and the executable bit, without which the '=>' renaming
##     silently stops working
##   - no debian/<source>.install is invented
##   - re-running changes nothing (the cmp -s skip must not corrupt a good file)
##
## Hermetic: a throwaway minimal source package, no root, no network, no chroot.
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
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-debinstfile.XXXXXX")"
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

make_fixture() {
   local dir="$1"
   mkdir --parents -- "${dir}/debian" "${dir}/usr/bin" "${dir}/usr/share/foo" "${dir}/etc"
   cat > "${dir}/debian/control" <<'CONTROL'
Source: gmf-inst-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: pkg-one
Architecture: all
Description: first binary package
 Not a real package.

Package: pkg-two
Architecture: all
Description: second binary package
 Not a real package.
CONTROL
   cat > "${dir}/debian/changelog" <<'CHANGELOG'
gmf-inst-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG
   printf '%s\n' 'x' > "${dir}/usr/bin/a#pkg-one"
   printf '%s\n' 'x' > "${dir}/usr/share/foo/b#pkg-two"
   ## No '#': must not be routed anywhere.
   printf '%s\n' 'x' > "${dir}/etc/plain"
   ## A file under a '#'-named PARENT directory: the '#<pkg>' delimiter must be stripped
   ## from the BASENAME only, so the parent's '#' survives in the destination. Old code
   ## truncated the dest at the FIRST '#' of the whole path ('/usr/li' not '/usr/li#b/tool').
   mkdir --parents -- "${dir}/usr/li#b"
   printf '%s\n' 'x' > "${dir}/usr/li#b/tool#pkg-one"
   ## A '#'-named DIRECTORY is not a file to install; it must never become an install entry.
   mkdir --parents -- "${dir}/usr/emptydir#pkg-two"
}

run_debinstfile() {
   local dir="$1" rc=0
   ( cd -- "${dir}" && "${genmkfile_bin}" debinstfile ) > "${dir}/debinstfile.log" 2>&1 || rc=$?
   return "${rc}"
}

## --- routing ----------------------------------------------------------------
pkg_dir="${work_dir}/pkg"
make_fixture "${pkg_dir}"

if run_debinstfile "${pkg_dir}"; then
   pass 'debinstfile exited 0'
else
   ## The engine prints a long "report this bug" banner, so a plain tail shows only
   ## the frame. Surface the line that names the cause -- typically a missing tool.
   fail "debinstfile failed: $(grep -m1 -iE 'not found|No such file|ERROR:' -- "${pkg_dir}/debinstfile.log" || tail -3 -- "${pkg_dir}/debinstfile.log")"
fi

if [ -f "${pkg_dir}/debian/pkg-one.install" ] && [ -f "${pkg_dir}/debian/pkg-two.install" ]; then
   pass 'one .install per binary package'
else
   fail "expected debian/pkg-one.install and debian/pkg-two.install, got: $(ls -- "${pkg_dir}/debian")"
fi

## The mapping is what actually routes the file. Getting the source or the destination
## wrong is exactly the silent mis-packaging this test exists for.
if grep --quiet --line-regexp --fixed-strings -- 'usr/bin/a#pkg-one => /usr/bin/a' \
   "${pkg_dir}/debian/pkg-one.install"; then
   pass 'the file is routed to its package with the hash stripped from the destination'
else
   fail "wrong mapping: $(grep -- '=>' "${pkg_dir}/debian/pkg-one.install" || true)"
fi
if grep --quiet --line-regexp --fixed-strings -- 'usr/share/foo/b#pkg-two => /usr/share/foo/b' \
   "${pkg_dir}/debian/pkg-two.install"; then
   pass 'a nested path routes to the second package'
else
   fail "wrong mapping: $(grep -- '=>' "${pkg_dir}/debian/pkg-two.install" || true)"
fi

## A '#' in a PARENT directory must not truncate the destination: only the basename's
## '#<pkg>' is stripped. Old code ('${file_name%%#*}') produced '=> /usr/li'.
if grep --quiet --line-regexp --fixed-strings -- 'usr/li#b/tool#pkg-one => /usr/li#b/tool' \
   "${pkg_dir}/debian/pkg-one.install"; then
   pass 'a hash in a parent directory does not truncate the destination'
else
   fail "parent-hash dest wrong: $(grep -- 'tool' "${pkg_dir}/debian/pkg-one.install" || true)"
fi

## A '#'-named DIRECTORY is not a file to install; it must not be routed into any package.
if grep --quiet -- 'emptydir' "${pkg_dir}/debian/pkg-one.install" "${pkg_dir}/debian/pkg-two.install"; then
   fail 'a hash-named directory was emitted as an install entry'
else
   pass 'a hash-named directory is not routed (files/symlinks only)'
fi

## Cross-contamination: each package's file must carry ONLY its own entries.
if grep --quiet -- 'pkg-two' "${pkg_dir}/debian/pkg-one.install"; then
   fail "pkg-one.install contains a pkg-two entry"
else
   pass 'no cross-contamination between packages'
fi

## A file with no '#' belongs to no binary package and must not be routed.
if grep --quiet -- 'etc/plain' "${pkg_dir}/debian/pkg-one.install" "${pkg_dir}/debian/pkg-two.install"; then
   fail 'a file with no hash suffix was routed into a package'
else
   pass 'a file with no hash suffix is not routed'
fi

## dh-exec does the '=>' renaming, and only if the file says so AND is executable.
if grep --quiet --fixed-strings -- '#!/usr/bin/dh-exec' <<< "$(head -1 -- "${pkg_dir}/debian/pkg-one.install")"; then
   pass 'the generated file carries the dh-exec shebang'
else
   fail "missing dh-exec shebang: $(head -1 -- "${pkg_dir}/debian/pkg-one.install")"
fi
if [ -x "${pkg_dir}/debian/pkg-one.install" ]; then
   pass 'the generated file is executable (dh-exec is not run otherwise)'
else
   fail "not executable: mode $(stat -c %a -- "${pkg_dir}/debian/pkg-one.install")"
fi

## The SOURCE package name is not a binary package here; inventing a .install for it
## would hand dh a file with no matching package.
if [ -e "${pkg_dir}/debian/gmf-inst-pkg.install" ]; then
   fail 'invented a .install for the source package name'
else
   pass 'no .install invented for the source package name'
fi

## --- idempotence ------------------------------------------------------------
## The cmp -s skip means a second run should change nothing. If it rewrites or
## truncates a good file, packaging silently changes on an unrelated re-run.
before_one="$(cat -- "${pkg_dir}/debian/pkg-one.install")"
before_two="$(cat -- "${pkg_dir}/debian/pkg-two.install")"
run_debinstfile "${pkg_dir}" || true
if [ "${before_one}" = "$(cat -- "${pkg_dir}/debian/pkg-one.install")" ] \
   && [ "${before_two}" = "$(cat -- "${pkg_dir}/debian/pkg-two.install")" ]; then
   pass 'a second run changes nothing'
else
   fail 'a second run rewrote the generated files'
fi

## --- the two opt-outs -------------------------------------------------------
## Both key on the SOURCE package, not on a per-binary-package file, and both skip the
## whole generation. Overwriting a maintainer's deliberate packaging would silently
## change what ships.

## 1. 'nogenmkfile' in debian/<source>.install.
optout_dir="${work_dir}/optout-marker"
make_fixture "${optout_dir}"
printf '%s\n' '## nogenmkfile' 'usr/bin/handwritten' \
   > "${optout_dir}/debian/gmf-inst-pkg.install"
run_debinstfile "${optout_dir}" || true
if [ -e "${optout_dir}/debian/pkg-one.install" ] || [ -e "${optout_dir}/debian/pkg-two.install" ]; then
   fail 'the nogenmkfile marker did not stop generation'
else
   pass 'a nogenmkfile marker in debian/<source>.install stops generation entirely'
fi
if grep --quiet --fixed-strings -- 'usr/bin/handwritten' "${optout_dir}/debian/gmf-inst-pkg.install"; then
   pass 'and the hand-written file is untouched'
else
   fail 'the hand-written opt-out file was rewritten'
fi

## 2. An upstream-provided debian/install. Generating per-package files alongside it
##    makes dh ignore it, which ships an empty package -- the case the short-circuit
##    exists for.
plain_dir="${work_dir}/optout-debian-install"
make_fixture "${plain_dir}"
printf '%s\n' 'usr/bin/upstream-provided' > "${plain_dir}/debian/install"
run_debinstfile "${plain_dir}" || true
if [ -e "${plain_dir}/debian/pkg-one.install" ] || [ -e "${plain_dir}/debian/pkg-two.install" ]; then
   fail 'generated per-package .install files alongside an existing debian/install'
else
   pass 'an existing debian/install suppresses generation (dh would ignore it otherwise)'
fi

## --- direct 'debinstfile-create' must ALSO honor the nogenmkfile opt-out --------------------
## The overwrite guard lives in make_debinstfile_create, not only in the make_debinstfile wrapper,
## so calling the internal target directly ('genmkfile debinstfile-create') cannot clobber a
## hand-maintained debian/<source>.install carrying the marker.
create_optout="${work_dir}/create-optout"
make_fixture "${create_optout}"
printf '%s\n' '## nogenmkfile' 'usr/bin/handwritten' > "${create_optout}/debian/gmf-inst-pkg.install"
optout_before="$(cat -- "${create_optout}/debian/gmf-inst-pkg.install")"
( cd -- "${create_optout}" && "${genmkfile_bin}" debinstfile-create ) >/dev/null 2>&1 || true
if [ "${optout_before}" = "$(cat -- "${create_optout}/debian/gmf-inst-pkg.install")" ] \
   && [ ! -e "${create_optout}/debian/pkg-one.install" ]; then
   pass 'direct debinstfile-create honors the nogenmkfile opt-out (guard not bypassable)'
else
   fail 'direct debinstfile-create bypassed the nogenmkfile guard and regenerated'
fi

## --- producer failure must ABORT, not accept a partial list -----------------
## The file list is built by 'find | sort -z'. If sort (or find) fails AFTER emitting partial
## output, the run must fail loud, not generate a truncated .install. A process substitution
## '< <(find | sort)' hid the producer's exit status; the fix captures it with an explicit rc
## check. Inject a 'sort -z' that emits ONE record then exits 1 (delegating any non '-z' sort to
## the real one, so only the NUL-delimited producer is sabotaged).
fake_bin="${work_dir}/fakebin"
mkdir --parents -- "${fake_bin}"
cat > "${fake_bin}/sort" <<'FAKESORT'
#!/bin/bash
for a in "$@"; do
   case "${a}" in
      -z | --zero-terminated)
         IFS= read -r -d '' rec || true
         printf '%s\0' "${rec}"
         exit 1
         ;;
   esac
done
exec /usr/bin/sort "$@"
FAKESORT
chmod +x -- "${fake_bin}/sort"

prod_dir="${work_dir}/producer-fail"
make_fixture "${prod_dir}"
prod_rc=0
( cd -- "${prod_dir}" && PATH="${fake_bin}:${PATH}" "${genmkfile_bin}" debinstfile ) >/dev/null 2>&1 || prod_rc=$?
if [ "${prod_rc}" -ne 0 ]; then
   pass 'a failing find|sort producer aborts debinstfile (no partial .install accepted)'
else
   fail "debinstfile exited 0 despite sort failing: $(ls -- "${prod_dir}/debian" 2>/dev/null || true)"
fi

printf '%s\n' "" "${checks} check(s), ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: debinstfile routing holds'
exit 0

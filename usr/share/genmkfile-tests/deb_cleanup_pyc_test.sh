#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 'genmkfile deb-cleanup' (via make_strip_build_residue) must remove Python bytecode from the
## source tree. A stale '.pyc' left behind is imported in place of edited '.py' source on the
## next run, so an edit silently has no effect.
##
## The sweep must take whole '__pycache__' directories AND stray '.pyc'/'.pyo' outside one,
## must NOT touch the '.py' sources or unrelated files, and must NOT delete the package root
## even when it is itself named '__pycache__' (a recursive sweep with no depth floor would).
##
## Hermetic: a throwaway minimal source package with a seeded bytecode tree, run through the
## REAL genmkfile. No root, no network, no chroot.
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
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-clean-pyc.XXXXXX")"
passes=0
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
Source: gmf-pyc-pkg
Section: misc
Priority: optional
Maintainer: test <test@localhost>
Build-Depends: debhelper-compat (= 13)

Package: gmf-pyc-pkg
Architecture: all
Depends: ${misc:Depends}
Description: throwaway fixture for the make_clean bytecode sweep test
 Not a real package.
CONTROL

cat > "${pkg_dir}/debian/changelog" <<'CHANGELOG'
gmf-pyc-pkg (1.0-1) unstable; urgency=medium

  * Fixture.

 -- test <test@localhost>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG

## deb-cleanup runs 'debian/rules clean', which needs a rules file.
cat > "${pkg_dir}/debian/rules" <<'RULES'
#!/usr/bin/make -f
%:
	dh $@
RULES
chmod 0755 -- "${pkg_dir}/debian/rules"

## Bytecode that MUST be swept: a nested __pycache__, a top-level __pycache__, and a stray
## '.pyc'/'.pyo' living outside any __pycache__.
mkdir --parents -- "${pkg_dir}/sub/__pycache__" "${pkg_dir}/__pycache__"
must_go=(
   'sub/__pycache__/mod.cpython-311.pyc'
   'sub/__pycache__/mod.cpython-312.opt-1.pyc'
   '__pycache__/top.cpython-311.pyc'
   'stray.pyc'
   'sub/orphan.pyo'
)
for f in "${must_go[@]}"; do
   printf '%s\n' 'stale bytecode' > "${pkg_dir}/${f}"
done

## Sources + unrelated files that MUST survive: over-deletion here would destroy the very
## thing the bytecode was masking.
must_stay=(
   'mod.py'
   'sub/mod.py'
   'debian/control'
   'keep.txt'
)
printf '%s\n' 'VALUE = "new"' > "${pkg_dir}/mod.py"
printf '%s\n' 'VALUE = "new"' > "${pkg_dir}/sub/mod.py"
printf '%s\n' 'unrelated' > "${pkg_dir}/keep.txt"

## Canary: every seed must exist on disk BEFORE the sweep, or the "swept" checks below pass
## vacuously (a fixture that never wrote the bytecode). Assert here, while it is still there.
for f in "${must_go[@]}"; do
   if [ ! -e "${pkg_dir}/${f}" ]; then
      printf '%s\n' "FAIL: canary -- seed not created: ${f}; sweep checks would be vacuous" >&2
      failures=$(( failures + 1 ))
   fi
done
if [ "${failures}" -eq 0 ]; then
   printf '%s\n' 'PASS: canary -- all bytecode seeds present before the sweep'
   passes=$(( passes + 1 ))
fi

clean_rc=0
(
   cd -- "${pkg_dir}" \
   && make_cowbuilder_dist_folder="${dist_dir}" \
      make_use_cowbuilder=true \
      "${genmkfile_bin}" deb-cleanup
) > "${work_dir}/clean.log" 2>&1 || clean_rc=$?

if [ "${clean_rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: deb-cleanup exited ${clean_rc}" >&2
   tail -20 -- "${work_dir}/clean.log" >&2
   failures=$(( failures + 1 ))
else
   printf '%s\n' 'PASS: deb-cleanup exited 0'
   passes=$(( passes + 1 ))
fi

for f in "${must_go[@]}"; do
   if [ -e "${pkg_dir}/${f}" ]; then
      printf '%s\n' "FAIL: bytecode left behind: ${f}" >&2
      failures=$(( failures + 1 ))
   else
      printf '%s\n' "PASS: swept: ${f}"
      passes=$(( passes + 1 ))
   fi
done

## Both __pycache__ directories must be gone, not merely emptied.
for d in 'sub/__pycache__' '__pycache__'; do
   if [ -e "${pkg_dir}/${d}" ]; then
      printf '%s\n' "FAIL: __pycache__ directory left behind: ${d}" >&2
      failures=$(( failures + 1 ))
   else
      printf '%s\n' "PASS: removed directory: ${d}"
      passes=$(( passes + 1 ))
   fi
done

for f in "${must_stay[@]}"; do
   if [ -e "${pkg_dir}/${f}" ]; then
      printf '%s\n' "PASS: survived: ${f}"
      passes=$(( passes + 1 ))
   else
      printf '%s\n' "FAIL: deleted a non-bytecode file: ${f}" >&2
      failures=$(( failures + 1 ))
   fi
done

## Second scenario: the sweep must NOT delete the project ROOT even when the root directory
## itself is named '__pycache__'. Without a depth floor, 'find "${PWD}" -name __pycache__'
## matches the root and 'safe-rm --recursive' wipes the whole checkout. Nested bytecode inside
## it must still be swept.
root_pkg="${work_dir}/__pycache__"
mkdir --parents -- "${root_pkg}/debian" "${root_pkg}/sub/__pycache__"
cp -- "${pkg_dir}/debian/changelog" "${root_pkg}/debian/changelog"
cp -- "${pkg_dir}/debian/rules" "${root_pkg}/debian/rules"
sed 's/gmf-pyc-pkg/gmf-root-pkg/g' "${pkg_dir}/debian/control" > "${root_pkg}/debian/control"
printf '%s\n' 'keep me' > "${root_pkg}/keep.txt"
printf '%s\n' 'stale' > "${root_pkg}/sub/__pycache__/nested.cpython-311.pyc"

root_rc=0
(
   cd -- "${root_pkg}" \
   && make_cowbuilder_dist_folder="${dist_dir}" \
      make_use_cowbuilder=true \
      "${genmkfile_bin}" deb-cleanup
) > "${work_dir}/root.log" 2>&1 || root_rc=$?

## A non-zero exit here would otherwise be swallowed: the survival checks below hold
## even when the sweep aborted early, so assert the exit code explicitly.
if [ "${root_rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: deb-cleanup (root named __pycache__) exited ${root_rc}" >&2
   tail -20 -- "${work_dir}/root.log" >&2
   failures=$(( failures + 1 ))
else
   printf '%s\n' 'PASS: deb-cleanup (root named __pycache__) exited 0'
   passes=$(( passes + 1 ))
fi

if [ -d "${root_pkg}" ] && [ -e "${root_pkg}/keep.txt" ]; then
   printf '%s\n' 'PASS: a project root named __pycache__ is NOT deleted (root and its files survive)'
   passes=$(( passes + 1 ))
else
   printf '%s\n' 'FAIL: the sweep deleted a project root named __pycache__ -- data loss' >&2
   failures=$(( failures + 1 ))
fi
if [ -e "${root_pkg}/sub/__pycache__/nested.cpython-311.pyc" ]; then
   printf '%s\n' 'FAIL: nested bytecode under a __pycache__-named root was not swept' >&2
   failures=$(( failures + 1 ))
else
   printf '%s\n' 'PASS: nested bytecode under a __pycache__-named root is still swept'
   passes=$(( passes + 1 ))
fi

printf '%s\n' "" "${passes} pass, ${failures} fail, 0 skip"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: deb-cleanup swept the bytecode and spared the sources'
exit 0

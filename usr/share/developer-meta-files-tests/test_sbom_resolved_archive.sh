#!/bin/bash

## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@kicksecure.com>
## SPDX-License-Identifier: AGPL-3.0-or-later

## AI-Assisted

## Behavioural test for developer-meta-files' dm-sbom-archive (the resolved per-.deb
## CycloneDX SBOM archive, tier B of the two-tier SBOM). Sources the real library and
## drives the real functions against a HERMETIC fixture reprepro index -- a hand-written
## dists/<cn>/<comp>/binary-<arch>/Packages with one package stanza (name, version, arch,
## content hashes, Filename, Size) plus a minimal Release. No build, no real repo, no net.
##
## Each assertion guards a contract of sbom_archive_one / sbom_archive_commit:
##   - RESOLVED: the binary component carries the index's content hashes (the whole point;
##     an unresolved, hash-less SBOM must FAIL loud, not archive silently).
##   - REPRODUCIBLE: two runs are byte-identical (deterministic serial + timestamp).
##   - serial = UUID5 of the package identity (not debsbom's random default).
##   - timestamp = the SOURCE_DATE_EPOCH passed in (not wall-clock).
##   - the binary->source edge is present (source component emitted, no closure expansion).
##   - the resolution GUARD rejects a name/version mismatch (returns non-zero).
##   - sbom_archive_commit makes a local commit and is a no-op on an unchanged archive.
##
## debsbom + jq + uuidgen + git are REAL requirements; a missing one is an ENVIRONMENT bug
## (FATAL exit 1), never a skip. Exit: 0 pass | 1 fail.
## style-ok: no-has

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## GIT_DIR and friends override 'git -C'; a caller with them set (a hook, submodule
## foreach) would make the library's git ops touch the CALLER's repo. Scrub them.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

## Isolate git config so the fixture commit cannot pick up the operator's global
## core.hooksPath (the style gate) -- the test exercises the library, not the host hooks.
## /dev/null, not a mktemp file: nothing writes the global config here (sbom_archive_commit
## sets identity with 'git -c user.name/email'), so there is no temp file to leak if the
## script exits before the cleanup trap is armed.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

test_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"

rel='usr/bin/dm-sbom-archive'
candidates=()
[ -z "${SBOM_ARCHIVE_BSH:-}" ] || candidates+=( "${SBOM_ARCHIVE_BSH}" )
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || candidates+=( "${DEVELOPER_META_FILES_DIR}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/${rel}" )
candidates+=( "/${rel}" )
subject=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-sbom-archive not found (set SBOM_ARCHIVE_BSH)." >&2
   exit 1
fi
## Absolute path: the standalone-exec assertions invoke it from inside a cd'd subshell, where
## a relative SBOM_ARCHIVE_BSH would resolve against the wrong directory.
subject="$(readlink --canonicalize -- "${subject}")"
for tool in debsbom jq uuidgen git safe-rm dpkg; do
   if ! command -v "${tool}" >/dev/null; then
      printf '%s\n' "FATAL: '${tool}' missing; a hard requirement of the test." >&2
      exit 1
   fi
done

# shellcheck disable=SC1090 # path resolved at runtime
source "${subject}"

workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## --- hermetic fixture reprepro index -----------------------------------------------
codename='local'
component='main'
arch='amd64'
pkg='sbomfixture'
version='2.0-1'
## A fixed PAST epoch: a wall-clock timestamp would miss it by years.
source_date_epoch='1700000000'

repo="${workdir}/repo"
binary_dir="${repo}/dists/${codename}/${component}/binary-${arch}"
mkdir --parents -- "${binary_dir}"

## Two stanzas: an arch-specific package and an 'Architecture: all' package WITH an epoch
## (the common shape for our packages), so the test also covers the all-arch resolution
## path and the epoch-stripped-filename convention.
allpkg='sbomfixture-all'
allversion='3:1.5-2'
allsha256='4444444444444444444444444444444444444444444444444444444444444444'
cat > "${binary_dir}/Packages" <<EOF
Package: ${pkg}
Version: ${version}
Architecture: ${arch}
Maintainer: Test <test@example.com>
Installed-Size: 10
Filename: pool/${component}/s/${pkg}/${pkg}_${version}_${arch}.deb
Size: 1234
SHA256: 1111111111111111111111111111111111111111111111111111111111111111
SHA1: 2222222222222222222222222222222222222222
MD5sum: 33333333333333333333333333333333
Description: hermetic SBOM fixture
 One package stanza for the resolved-SBOM test.

Package: ${allpkg}
Version: ${allversion}
Architecture: all
Maintainer: Test <test@example.com>
Installed-Size: 10
Filename: pool/${component}/s/${allpkg}/${allpkg}_1.5-2_all.deb
Size: 4321
SHA256: ${allsha256}
SHA1: 5555555555555555555555555555555555555555
MD5sum: 66666666666666666666666666666666
Description: hermetic SBOM fixture (arch all, epoch)
 Arch-all package with an epoch, for the all-arch + epoch-filename path.
EOF

## A third source 'runpkg' producing TWO binaries at ONE shared version (runbin amd64 +
## rundata all), each carrying a Source: field (name != source) -- the shape sbom_archive_run
## iterates from a single debian/control + changelog. Exercises the multi-binary orchestration
## and the explicit-Source edge (the stanzas above omit Source, so source == name there).
cat >> "${binary_dir}/Packages" <<EOF

Package: runbin
Source: runpkg
Version: 1.0-1
Architecture: ${arch}
Maintainer: Test <test@example.com>
Installed-Size: 10
Filename: pool/${component}/r/runpkg/runbin_1.0-1_${arch}.deb
Size: 2000
SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA1: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
MD5sum: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Description: run-test arch-dependent binary
 Body.

Package: rundata
Source: runpkg
Version: 1.0-1
Architecture: all
Maintainer: Test <test@example.com>
Installed-Size: 10
Filename: pool/${component}/r/runpkg/rundata_1.0-1_all.deb
Size: 2001
SHA256: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
SHA1: dddddddddddddddddddddddddddddddddddddddd
MD5sum: dddddddddddddddddddddddddddddddd
Description: run-test arch-all binary
 Body.
EOF

cat > "${repo}/dists/${codename}/Release" <<EOF
Origin: test
Label: test
Codename: ${codename}
Components: ${component}
Architectures: ${arch}
Description: hermetic fixture repository
EOF

## Source package tree sbom_archive_run reads: control (two binaries) + a changelog whose
## date is exactly source_date_epoch (1700000000 = Tue, 14 Nov 2023 22:13:20 +0000).
pkgdir="${workdir}/runpkg"
mkdir --parents -- "${pkgdir}/debian"
cat > "${pkgdir}/debian/control" <<EOF
Source: runpkg
Section: misc
Priority: optional
Maintainer: Test <test@example.com>
Standards-Version: 4.7.2

Package: runbin
Architecture: any
Description: run-test arch-dependent binary
 Body.

Package: rundata
Architecture: all
Description: run-test arch-all binary
 Body.
EOF
cat > "${pkgdir}/debian/changelog" <<EOF
runpkg (1.0-1) unstable; urgency=medium

  * Test.

 -- Test <test@example.com>  Tue, 14 Nov 2023 22:13:20 +0000
EOF

## --- drive the real library --------------------------------------------------------
archive_dir="${workdir}/archive"

out="$(sbom_archive_one \
   "${repo}" "${codename}" "${pkg}" "${version}" "${arch}" "${arch}" \
   "${source_date_epoch}" "${archive_dir}")"

cp -- "${out}" "${workdir}/run1.json"

## Second run must be byte-identical.
sbom_archive_one \
   "${repo}" "${codename}" "${pkg}" "${version}" "${arch}" "${arch}" \
   "${source_date_epoch}" "${archive_dir}" >/dev/null
cp -- "${out}" "${workdir}/run2.json"

## Expected serial is a LITERAL (UUID5 of 'deb/sbomfixture/2.0-1/amd64'), computed
## independently of the function under test so the identity check is not circular; the
## function itself is checked against the same literal below. expected_sha256 is the
## fixture stanza's SHA256, so the resolution check proves the RIGHT hash was read.
expected_serial='dd221d17-777f-573c-8d0a-ec5533a18f48'
expected_sha256='1111111111111111111111111111111111111111111111111111111111111111'

## All JSON-semantic assertions live in the standalone helper (no inline 'python3 -c'),
## run directly via its shebang. Not exec'd: the EXIT trap must still fire.
"${test_dir}/sbom_resolved_archive_assert.py" \
   "${workdir}/run1.json" "${workdir}/run2.json" \
   "${expected_serial}" "${source_date_epoch}" "${pkg}" "${version}" "${arch}" \
   "${expected_sha256}"

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

## sbom_archive_serial is tested against the SAME literal expected_serial the assertions
## above used, so neither side depends on the other (no circularity).
if [ "$(sbom_archive_serial "${pkg}" "${version}" "${arch}")" = "${expected_serial}" ]; then
   pass "sbom_archive_serial produces the expected deterministic UUID5"
else
   fail "sbom_archive_serial did not produce the expected UUID5 ${expected_serial}"
fi

## Resolution GUARD: a version that is not in the index must FAIL loud (non-zero) AND must
## leave NO file behind (else a later 'git add --all' would commit it). A SEPARATE empty
## archive dir, so 'nothing was created' is checked as an EMPTY dir -- not just the absence
## of one known filename, which would miss any stray file under a different name.
guard_dir="${workdir}/guard"
if sbom_archive_one \
      "${repo}" "${codename}" "${pkg}" "9.9-9" "${arch}" "${arch}" \
      "${source_date_epoch}" "${guard_dir}" >/dev/null 2>&1; then
   fail "guard: an unresolved package (wrong version) was archived instead of failing"
else
   pass "guard rejects an unresolved package (no hashes -> non-zero)"
fi
if [ -n "$(ls -A -- "${guard_dir}" 2>/dev/null)" ]; then
   fail "guard left a file behind (would be committed later)"
else
   pass "guard discarded the unresolved SBOM (archive dir empty)"
fi

## Commit: a local commit is made and the SBOM is in the HEAD tree (committed, not merely
## staged -- 'cat-file -e HEAD:<path>' reads the commit, whereas 'ls-files' reads the index).
DEBFULLNAME='Test' DEBEMAIL='test@example.com' \
   sbom_archive_commit "${archive_dir}" "sbom: fixture ${version}"
if git -C "${archive_dir}" cat-file -e "HEAD:$(basename -- "${out}")" 2>/dev/null; then
   pass "sbom_archive_commit created a local commit tracking the SBOM"
else
   fail "sbom_archive_commit did not commit the SBOM"
fi

## No-op on an unchanged archive (idempotent).
commit_before="$(git -C "${archive_dir}" rev-parse HEAD)"
DEBFULLNAME='Test' DEBEMAIL='test@example.com' \
   sbom_archive_commit "${archive_dir}" "sbom: fixture ${version} again"
commit_after="$(git -C "${archive_dir}" rev-parse HEAD)"
if [ "${commit_before}" = "${commit_after}" ]; then
   pass "sbom_archive_commit is a no-op when nothing changed"
else
   fail "sbom_archive_commit made an empty commit"
fi

## Arch-all + epoch: resolves (hashes), and the filename strips the epoch (.deb convention)
## while the component keeps the full epoched version.
all_out="$(sbom_archive_one \
   "${repo}" "${codename}" "${allpkg}" "${allversion}" all "${arch}" \
   "${source_date_epoch}" "${archive_dir}")"
if [ "$(basename -- "${all_out}")" = "${allpkg}_1.5-2_all.cdx.json" ]; then
   pass "arch-all SBOM filename strips the epoch (.deb convention)"
else
   fail "arch-all filename not epoch-stripped: $(basename -- "${all_out}")"
fi
if jq --exit-status \
      --arg n "${allpkg}" --arg v "${allversion}" --arg h "${allsha256}" \
      '[.components[]?
        | select(.name == $n and .version == $v
                 and ((.purl // "") | test("[?&]arch=all(&|$)"))
                 and ((.hashes // []) | any(.alg == "SHA-256" and .content == $h)))] | length > 0' \
      "${all_out}" >/dev/null; then
   pass "arch-all package resolved with the index SHA-256 (name, arch=all, epoched version)"
else
   fail "arch-all package did not resolve with the fixture SHA-256"
fi

## Codename detection: the single codename under dists/ (no literal '*' glob leak).
if [ "$(sbom_archive_codename "${repo}")" = "${codename}" ]; then
   pass "sbom_archive_codename returns the single repo codename"
else
   fail "sbom_archive_codename did not return '${codename}'"
fi

## Presence check (arch-aware): a built package is present for its own arch; an unbuilt one
## (wrong version, OR right name/version but an arch not built) is absent, so the wrapper can
## skip it instead of failing the whole packaging batch.
if sbom_archive_present "${repo}" "${codename}" "${pkg}" "${version}" "${arch}"; then
   pass "sbom_archive_present finds a package that is in the index"
else
   fail "sbom_archive_present missed a package that is in the index"
fi
if sbom_archive_present "${repo}" "${codename}" "${pkg}" "9.9-9" "${arch}"; then
   fail "sbom_archive_present reported an absent version as present"
else
   pass "sbom_archive_present reports an absent version as absent"
fi
if sbom_archive_present "${repo}" "${codename}" "${pkg}" "${version}" arm64; then
   fail "sbom_archive_present matched an arch the package was not built for"
else
   pass "sbom_archive_present rejects a wrong arch (same name+version)"
fi

## if_present: archive when the arch is in the index, INFO-skip (no file, rc 0) when not.
present_dir="${workdir}/ifpresent"
sbom_archive_if_present \
   "${repo}" "${codename}" "${pkg}" "${version}" "${arch}" "${arch}" \
   "${source_date_epoch}" "${present_dir}"
if [ -f "${present_dir}/${pkg}_${version}_${arch}.cdx.json" ]; then
   pass "sbom_archive_if_present archives a package present for its arch"
else
   fail "sbom_archive_if_present did not archive a present package"
fi
## Absent-arch negative case in a SEPARATE empty dir, so 'no SBOM created' is an empty dir,
## not just the absence of one known filename.
absent_dir="${workdir}/ifpresent-absent"
if sbom_archive_if_present \
      "${repo}" "${codename}" "${pkg}" "${version}" arm64 arm64 \
      "${source_date_epoch}" "${absent_dir}" \
      && [ -z "$(ls -A -- "${absent_dir}" 2>/dev/null)" ]; then
   pass "sbom_archive_if_present skips (rc 0, no file) an arch not in the index"
else
   fail "sbom_archive_if_present did not cleanly skip an absent arch"
fi

## sbom_archive_run: the whole orchestration from a source tree. Two binaries at one version
## -- runbin (any -> built arch) + rundata (all) -- both archived and committed in one pass.
run_archive_dir="${workdir}/run-archive"
(
   cd -- "${pkgdir}"
   make_cross_build_platform_list="${arch}" DEBFULLNAME='Test' DEBEMAIL='test@example.com' \
      sbom_archive_run "${repo}" "${run_archive_dir}" runpkg
)
if [ -f "${run_archive_dir}/runbin_1.0-1_${arch}.cdx.json" ] \
      && [ -f "${run_archive_dir}/rundata_1.0-1_all.cdx.json" ]; then
   pass "sbom_archive_run archives every declared binary (arch-dep + all)"
else
   fail "sbom_archive_run did not archive both binaries"
fi
## Explicit-Source edge: the binary's source component is 'runpkg' (Source: field, not its
## own name) AND a dependency edge runs from the binary's bom-ref to the source's bom-ref.
if jq --exit-status '
      (first(.components[] | select(.name == "runbin") | .["bom-ref"])) as $bin
      | (first(.components[] | select((.purl // "") | test("[?&]arch=source(&|$)")))) as $src
      | ($src.name == "runpkg")
        and ([.dependencies[]?
              | select(.ref == $bin and ((.dependsOn // []) | index($src["bom-ref"])))]
             | length == 1)
   ' "${run_archive_dir}/runbin_1.0-1_${arch}.cdx.json" >/dev/null; then
   pass "sbom_archive_run links the binary to its 'runpkg' source (edge present)"
else
   fail "sbom_archive_run did not emit the binary->runpkg source edge"
fi
## Committed (HEAD tree), not merely staged: cat-file -e reads the commit.
if git -C "${run_archive_dir}" cat-file -e "HEAD:runbin_1.0-1_${arch}.cdx.json" 2>/dev/null \
      && git -C "${run_archive_dir}" cat-file -e "HEAD:rundata_1.0-1_all.cdx.json" 2>/dev/null; then
   pass "sbom_archive_run commits every binary's SBOM"
else
   fail "sbom_archive_run did not commit both SBOMs"
fi
## Honors make_cross_build_platform_list: a list of ONLY an unbuilt arch archives no
## arch-dependent binary -- it must NOT fall back to the native arch, which IS in the index.
## The 'all' package still archives (arch-independent), proving the run itself ran.
run_skip_dir="${workdir}/run-skip"
(
   cd -- "${pkgdir}"
   make_cross_build_platform_list='ppc64el' DEBFULLNAME='Test' DEBEMAIL='test@example.com' \
      sbom_archive_run "${repo}" "${run_skip_dir}" runpkg
)
if [ ! -e "${run_skip_dir}/runbin_1.0-1_ppc64el.cdx.json" ] \
      && [ ! -e "${run_skip_dir}/runbin_1.0-1_${arch}.cdx.json" ] \
      && [ -f "${run_skip_dir}/rundata_1.0-1_all.cdx.json" ]; then
   pass "sbom_archive_run honors the build list (unbuilt arch -> no native fallback)"
else
   fail "sbom_archive_run did not honor the build list"
fi

## Standalone EXECUTABLE: run the script itself (main + was_executed), not sourced; both
## binaries must end up committed in the HEAD tree.
exec_archive_dir="${workdir}/exec-archive"
(
   cd -- "${pkgdir}"
   make_cross_build_platform_list="${arch}" DEBFULLNAME='Test' DEBEMAIL='test@example.com' \
      "${subject}" "${repo}" "${exec_archive_dir}" runpkg
)
if git -C "${exec_archive_dir}" cat-file -e "HEAD:runbin_1.0-1_${arch}.cdx.json" 2>/dev/null \
      && git -C "${exec_archive_dir}" cat-file -e "HEAD:rundata_1.0-1_all.cdx.json" 2>/dev/null; then
   pass "executed as a script (main/was_executed) commits every binary"
else
   fail "standalone execution did not commit both SBOMs"
fi
## Wrong argument count fails loud via the main() usage guard -- assert the Usage: message,
## not merely a nonzero exit (nounset on a missing arg, or a non-exec file, also exits nonzero).
usage_rc=0
usage_err="$("${subject}" "${repo}" "${exec_archive_dir}" 2>&1 1>/dev/null)" || usage_rc=$?
if [ "${usage_rc}" -ne 0 ] && grep --quiet 'Usage:' <<< "${usage_err}"; then
   pass "main rejects a wrong argument count with a usage message"
else
   fail "main did not emit the usage guard on a wrong argument count"
fi

## No debian/control -> clean no-op (rc 0), BEFORE any repo check: a non-package dir has
## nothing to archive, so a bad/unset repo path is irrelevant and must not abort. (The hook's
## pkg_sbom_archive guards control likewise, so an unset derivative_repository_name under
## nounset cannot abort the packaging shell.)
nocontrol_dir="${workdir}/nocontrol"
mkdir --parents -- "${nocontrol_dir}"
nocontrol_rc=0
(
   cd -- "${nocontrol_dir}"
   sbom_archive_run '/no/such/repo' "${workdir}/nocontrol-archive" runpkg
) || nocontrol_rc=$?
if [ "${nocontrol_rc}" -eq 0 ] && [ ! -e "${workdir}/nocontrol-archive" ]; then
   pass "sbom_archive_run is a clean no-op when debian/control is absent"
else
   fail "sbom_archive_run did not no-op on a missing debian/control (rc ${nocontrol_rc})"
fi

printf '%s\n' "RESULT: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]

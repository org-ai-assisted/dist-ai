#!/bin/bash

## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@kicksecure.com>
## SPDX-License-Identifier: AGPL-3.0-or-later

## AI-Assisted

## Behavioural test for developer-meta-files' sbom-archive.bsh (the resolved per-.deb
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
isolated_gitconfig="$(mktemp)"
export GIT_CONFIG_GLOBAL="${isolated_gitconfig}"
export GIT_CONFIG_SYSTEM=/dev/null

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

test_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"

rel='usr/libexec/developer-meta-files/sbom-archive.bsh'
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
   printf '%s\n' "FATAL: sbom-archive.bsh not found (set SBOM_ARCHIVE_BSH)." >&2
   exit 1
fi
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
   safe-rm --recursive --force -- "${workdir}" "${isolated_gitconfig}"
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
SHA256: 4444444444444444444444444444444444444444444444444444444444444444
SHA1: 5555555555555555555555555555555555555555
MD5sum: 66666666666666666666666666666666
Description: hermetic SBOM fixture (arch all, epoch)
 Arch-all package with an epoch, for the all-arch + epoch-filename path.
EOF

cat > "${repo}/dists/${codename}/Release" <<EOF
Origin: test
Label: test
Codename: ${codename}
Components: ${component}
Architectures: ${arch}
Description: hermetic fixture repository
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

expected_serial="$(sbom_archive_serial "${pkg}" "${version}" "${arch}")"

## All JSON-semantic assertions live in the standalone helper (no inline 'python3 -c'),
## run directly via its shebang. Not exec'd: the EXIT trap must still fire.
"${test_dir}/sbom_resolved_archive_assert.py" \
   "${workdir}/run1.json" "${workdir}/run2.json" \
   "${expected_serial}" "${source_date_epoch}" "${pkg}" "${version}" "${arch}"

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

## Resolution GUARD: a version that is not in the index must FAIL loud (non-zero).
if sbom_archive_one \
      "${repo}" "${codename}" "${pkg}" "9.9-9" "${arch}" "${arch}" \
      "${source_date_epoch}" "${archive_dir}" >/dev/null 2>&1; then
   fail "guard: an unresolved package (wrong version) was archived instead of failing"
else
   pass "guard rejects an unresolved package (no hashes -> non-zero)"
fi

## Commit: a local commit is made and the SBOM is tracked.
DEBFULLNAME='Test' DEBEMAIL='test@example.com' \
   sbom_archive_commit "${archive_dir}" "sbom: fixture ${version}"
if git -C "${archive_dir}" rev-parse --verify --quiet HEAD >/dev/null \
      && git -C "${archive_dir}" ls-files --error-unmatch \
            "$(basename -- "${out}")" >/dev/null 2>&1; then
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
      --arg v "${allversion}" \
      '[.components[]? | select(.version == $v and ((.hashes // []) | length > 0))] | length > 0' \
      "${all_out}" >/dev/null; then
   pass "arch-all package resolved with its full epoched version"
else
   fail "arch-all package did not resolve with hashes at version ${allversion}"
fi

## Presence check: a built package is present; an unbuilt one (or wrong version) is absent,
## so the wrapper can skip it instead of failing the whole packaging batch.
if sbom_archive_present "${repo}" "${codename}" "${pkg}" "${version}"; then
   pass "sbom_archive_present finds a package that is in the index"
else
   fail "sbom_archive_present missed a package that is in the index"
fi
if sbom_archive_present "${repo}" "${codename}" "${pkg}" "9.9-9"; then
   fail "sbom_archive_present reported an absent version as present"
else
   pass "sbom_archive_present reports an absent version as absent"
fi

printf '%s\n' "RESULT: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Behavioural test for developer-meta-files' package-build-freshness.bsh after
## dropping the reprepro published-version path: dm_package_needs_rebuild now
## decides purely from a source-CONTENT hash manifest. Sources the real library
## and drives the real functions over a fixture package tree; asserts:
##   * first sight (no manifest entry) -> rebuild;
##   * recorded + unchanged             -> skip;
##   * a source edit with NO changelog bump -> rebuild (content hash moved);
##   * a debian/changelog version bump  -> rebuild (the changelog is hashed too).
## Plus a structural guard that the reprepro path stayed removed and the function
## now takes two arguments (no repository_name).
##
## Self-contained; sources the side-effect-free library. dpkg-parsechangelog +
## sha256sum + find are real requirements. Needs no root, no network, no build.
## style-ok: no-has

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$((test_failures + 1))
   printf '%s\n' "FAIL: $*" >&2
}

rel='usr/libexec/developer-meta-files/package-build-freshness.bsh'
candidates=()
[ -z "${PACKAGE_BUILD_FRESHNESS_BSH:-}" ] || candidates+=( "${PACKAGE_BUILD_FRESHNESS_BSH}" )
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
   printf '%s\n' "SKIP: package-build-freshness.bsh not found (set PACKAGE_BUILD_FRESHNESS_BSH)." >&2
   exit 77
fi
for tool in dpkg-parsechangelog sha256sum find; do
   if ! command -v "${tool}" >/dev/null; then
      printf '%s\n' "FATAL: '${tool}' missing; a hard requirement of the library under test." >&2
      exit 1
   fi
done

## --- STRUCTURAL: the reprepro path stayed removed ---------------------------
if grep --quiet --fixed-strings -- 'dm_reprepro_published_source_version' "${subject}"; then
   fail "structural: the reprepro published-version function is back; the path should be content-hash only"
else
   pass "structural: the reprepro published-version path stays removed"
fi
block="$(sed -n '/^dm_package_needs_rebuild()/,/^}/p' -- "${subject}")"
if printf '%s\n' "${block}" | grep --quiet --fixed-strings -- 'repository_name'; then
   fail "structural: dm_package_needs_rebuild still takes a repository_name (reprepro arg)"
else
   pass "structural: dm_package_needs_rebuild no longer takes repository_name"
fi

## --- BEHAVIOURAL: drive the real functions ---------------------------------
workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## The library reads binary_build_folder_dist for the manifest location.
binary_build_folder_dist="${workdir}/build"
mkdir --parents -- "${binary_build_folder_dist}"
# shellcheck disable=SC1090 # path resolved at runtime
source "${subject}"

pkg_dir="${workdir}/src"
mkdir --parents -- "${pkg_dir}/debian"
printf '%s\n' 'payload one' > "${pkg_dir}/file_a"
printf '%s\n' 'payload two' > "${pkg_dir}/file_b"
write_changelog() {
   cat > "${pkg_dir}/debian/changelog" <<CHANGELOG
testpkg ($1) unstable; urgency=medium

  * Test entry.

 -- Test <test@example.com>  Mon, 01 Jan 2024 00:00:00 +0000
CHANGELOG
}
write_changelog '1.0-1'

codename='trixie'
manifest="$(dm_source_hash_manifest_path "${codename}")"

needs_rebuild() {
   local rc=0
   dm_package_needs_rebuild "${pkg_dir}" "${codename}" >/dev/null 2>&1 || rc="$?"
   printf '%s' "${rc}"
}
record_now() {
   dm_source_hash_record "${manifest}" 'testpkg' "$(dm_package_source_hash "${pkg_dir}")"
}

## First sight: nothing recorded -> rebuild (0).
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "first sight (no manifest entry) -> rebuild"
else
   fail "first sight should rebuild, but was skipped"
fi

## Record, then unchanged -> skip (1).
record_now
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "recorded + unchanged -> skip"
else
   fail "recorded + unchanged should skip, but wanted rebuild"
fi

## Edit a source file, NO changelog bump -> rebuild (0).
printf '%s\n' 'payload two EDITED' > "${pkg_dir}/file_b"
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "source edit without a changelog bump -> rebuild (content hash moved)"
else
   fail "an unrecorded source edit should rebuild, but was skipped"
fi

## Re-record at the edited content, then bump ONLY the changelog -> rebuild (0),
## because debian/changelog is part of the hashed tree.
record_now
write_changelog '1.0-2'
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "changelog version bump -> rebuild (the changelog is hashed too)"
else
   fail "a changelog bump should rebuild, but was skipped"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: dm_package_needs_rebuild is content-hash only (${pass_count} assertions)."

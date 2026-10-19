#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Behavioural test for developer-meta-files' package-build-freshness.bsh after
## dropping the reprepro published-version path: dm_package_needs_rebuild decides
## from a source-CONTENT hash manifest AND from whether the built .deb still exists
## in the local package output (never from reprepro / a version comparison). Sources
## the real library and drives the real functions over a fixture package tree;
## asserts:
##   * first sight (no manifest entry)  -> rebuild;
##   * recorded + unchanged + artifact present -> skip;
##   * recorded + unchanged + artifact ABSENT  -> rebuild (manifest stale vs pool);
##   * a source edit with NO changelog bump -> rebuild (content hash moved);
##   * a debian/changelog version bump  -> rebuild (the changelog is hashed too);
##   * an epoch version (3:1.0-2): the .deb drops the epoch, so an epoch-stripped
##     artifact present -> skip, absent -> rebuild;
##   * a 0-byte stub or a dangling symlink named like the .deb -> rebuild (a
##     regular, non-empty file is required);
##   * multi-binary source: EVERY produced binary's .deb must be present, so a
##     missing one -> rebuild;
##   * an arch-dependent binary ('any') needs _<arch>.deb: a wrong-suffix _all.deb
##     -> rebuild, the correct _<arch>.deb -> skip;
##   * control parsing robustness: a stanza with Architecture BEFORE Package is
##     still checked (Debian allows any field order); a udeb stanza is not required
##     as a .deb; a trailing CR ('Architecture: all\r') does not defeat the match.
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
export LC_ALL=C

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
   printf '%s\n' "FATAL: package-build-freshness.bsh not found (set PACKAGE_BUILD_FRESHNESS_BSH)." >&2
   exit 1
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
if grep --quiet --fixed-strings -- 'repository_name' <<< "${block}"; then
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
## dm_package_artifacts_present reads the binary package name(s) from debian/control.
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: testpkg

Package: testpkg
Architecture: all
Description: fixture package
 Fixture.
CONTROL

## The library looks for built .debs in genmkfile's DISTDIR under binary_build_folder_dist.
distdir="${binary_build_folder_dist}/genmkfile-packages-result"
mkdir --parents -- "${distdir}"
## A built .deb is a regular, non-empty file; write real bytes, not a 0-byte stub.
make_artifact() {
   printf '%s\n' 'fake deb payload' > "${distdir}/testpkg_${1}_all.deb"
}
clear_artifacts() {
   local f
   ## 'testpkg*' covers testpkg_ and the multi-binary testpkg-extra_ artifacts;
   ## '-L' also catches a dangling symlink, which '-e' (it follows the link) misses.
   for f in "${distdir}"/testpkg*.deb; do
      if [ -e "${f}" ] || [ -L "${f}" ]; then
         safe-rm --force -- "${f}"
      fi
   done
}
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

## Record + unchanged + the built artifact present -> skip (1).
record_now
make_artifact '1.0-1'
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "recorded + unchanged + artifact present -> skip"
else
   fail "recorded + unchanged + artifact present should skip, but wanted rebuild"
fi

## A 0-byte .deb stub must NOT satisfy the check (a regular, non-empty file is
## required) -> rebuild.
clear_artifacts
touch -- "${distdir}/testpkg_1.0-1_all.deb"
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "empty .deb stub -> rebuild (non-empty file required)"
else
   fail "an empty .deb stub was treated as a built artifact and skipped"
fi

## A dangling symlink named like the .deb must NOT satisfy the check -> rebuild.
clear_artifacts
ln -s -- /nonexistent/no-such.deb "${distdir}/testpkg_1.0-1_all.deb"
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "dangling .deb symlink -> rebuild (regular file required)"
else
   fail "a dangling .deb symlink was treated as a built artifact and skipped"
fi
clear_artifacts

## Record + unchanged but the built artifact GONE (pool reverted/cleared while the
## persistent manifest survived) -> rebuild (0). The old hash-only path skipped
## here and shipped the stale .deb.
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "recorded + unchanged + artifact absent -> rebuild (manifest stale vs pool)"
else
   fail "artifact absent must rebuild, but was skipped (stale .deb would ship)"
fi
make_artifact '1.0-1'

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

## Epoch in the changelog (3:1.0-2): the .deb filename drops the epoch (-> 1.0-2).
## With the hash recorded and the epoch-stripped artifact present -> skip; this
## fails if the version is not epoch-stripped (the glob would miss the artifact).
clear_artifacts
write_changelog '3:1.0-2'
record_now
make_artifact '1.0-2'
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "epoch version: epoch-stripped artifact present -> skip"
else
   fail "epoch version: epoch-stripped artifact present should skip, but wanted rebuild"
fi
## And absent again -> rebuild.
clear_artifacts
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "epoch version: artifact absent -> rebuild"
else
   fail "epoch version: artifact absent must rebuild, but was skipped"
fi

## --- multi-binary: EVERY produced binary's .deb must be present ------------
## Two Architecture: all binaries. Absence of EITHER forces a rebuild -- the old
## 'any one present' logic skipped when only one was there, risking a stale
## shipped binary.
clear_artifacts
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: testpkg

Package: testpkg
Architecture: all
Description: fixture
 Fixture.

Package: testpkg-extra
Architecture: all
Description: fixture extra
 Extra.
CONTROL
write_changelog '2.0-1'
record_now
printf '%s\n' 'deb a' > "${distdir}/testpkg_2.0-1_all.deb"
printf '%s\n' 'deb b' > "${distdir}/testpkg-extra_2.0-1_all.deb"
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "multi-binary: all produced .debs present -> skip"
else
   fail "multi-binary: all .debs present should skip, but wanted rebuild"
fi
safe-rm --force -- "${distdir}/testpkg-extra_2.0-1_all.deb"
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "multi-binary: one produced .deb absent -> rebuild"
else
   fail "multi-binary: a missing binary .deb must rebuild, but was skipped"
fi
clear_artifacts

## --- arch-dependent suffix: 'any' -> _<arch>.deb, never _all.deb -----------
export dist_build_target_arch='amd64'
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: testpkg

Package: testpkg
Architecture: any
Description: fixture arch-dependent
 Arch.
CONTROL
write_changelog '2.0-2'
record_now
## A wrongly-suffixed _all.deb must NOT satisfy an 'any' binary -> rebuild.
printf '%s\n' 'deb all' > "${distdir}/testpkg_2.0-2_all.deb"
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "arch-dependent 'any': only _all.deb present -> rebuild (needs _amd64.deb)"
else
   fail "arch-dependent 'any' matched a wrong-suffix _all.deb and skipped"
fi
## The correctly-suffixed _<arch>.deb present -> skip.
printf '%s\n' 'deb amd64' > "${distdir}/testpkg_2.0-2_amd64.deb"
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "arch-dependent 'any': _amd64.deb present -> skip"
else
   fail "arch-dependent 'any': correct _amd64.deb present should skip"
fi
unset dist_build_target_arch
clear_artifacts

## --- field order within a stanza is arbitrary (Debian policy) ---------------
## A binary stanza listing Architecture BEFORE Package must still be parsed, or
## its .deb goes unchecked and a sibling's presence yields a false skip.
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: testpkg

Package: testpkg
Architecture: all
Description: a
 a

Architecture: all
Package: testpkg-extra
Description: b
 b
CONTROL
write_changelog '3.0-1'
record_now
printf '%s\n' 'deb a' > "${distdir}/testpkg_3.0-1_all.deb"
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "reordered stanza (Architecture before Package): its missing .deb -> rebuild"
else
   fail "a reordered stanza was dropped; its missing .deb produced a false skip"
fi
printf '%s\n' 'deb b' > "${distdir}/testpkg-extra_3.0-1_all.deb"
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "reordered stanza: both .debs present -> skip"
else
   fail "reordered stanza: both .debs present should skip"
fi
clear_artifacts

## --- udeb stanza produces a .udeb, not a .deb, so it is not required ---------
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: testpkg

Package: testpkg
Architecture: all
Description: a
 a

Package: testpkg-udeb
Package-Type: udeb
Architecture: all
Description: u
 u
CONTROL
write_changelog '3.0-2'
record_now
printf '%s\n' 'deb a' > "${distdir}/testpkg_3.0-2_all.deb"
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "udeb stanza not required: the .deb binary present -> skip"
else
   fail "a udeb stanza was wrongly required as a .deb, forcing a rebuild"
fi
clear_artifacts

## --- a CRLF .deb control must not defeat the 'all' match ---------------------
## Written with a literal CR on the Architecture line (not trailing whitespace in
## this test's own source, which the style gate forbids).
cr=$'\r'
{
   printf '%s\n' 'Source: testpkg' ''
   printf '%s\n' 'Package: testpkg'
   printf '%s\n' "Architecture: all${cr}"
   printf '%s\n' 'Description: a' ' a'
} > "${pkg_dir}/debian/control"
write_changelog '3.0-3'
record_now
printf '%s\n' 'deb a' > "${distdir}/testpkg_3.0-3_all.deb"
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "CRLF 'Architecture: all' + .deb present -> skip (CR stripped)"
else
   fail "a trailing CR on Architecture defeated the 'all' match, forcing a rebuild"
fi
clear_artifacts

## Restore the single-binary Architecture: all fixture for the remaining checks.
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: testpkg

Package: testpkg
Architecture: all
Description: fixture package
 Fixture.
CONTROL

## A hash FAILURE ('nohash' sentinel) must force a rebuild, never be compared like
## a real digest -- otherwise a source tree that fails to hash twice reads as
## 'unchanged' and is skipped. Force the sentinel by overriding the hash function,
## record it as the stored hash too, and assert the decision is still rebuild.
record_now
dm_source_hash_record "${manifest}" 'testpkg' 'nohash'
dm_package_source_hash() {
   printf '%s\n' 'nohash'
}
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "hash failure (nohash) forces a rebuild even when stored == current == nohash"
else
   fail "nohash == nohash was treated as 'unchanged' and skipped (must rebuild)"
fi

## --- dm_architecture_covers_target: Debian arch wildcards -------------------
## Guards the switch from a hand-rolled 'any|linux-any|<arch>|linux-<arch>' case
## to dpkg-architecture --is, which also matches arch-qualified wildcards such as
## 'any-amd64'. A miss would make dm_package_artifacts_present skip the reprepro
## check for that binary and read a missing .deb as present ("fresh").
if dm_architecture_covers_target 'any-amd64' amd64; then
   pass "arch wildcard: any-amd64 covers amd64 (the case a hand-rolled match missed)"
else
   fail "arch wildcard: any-amd64 should cover amd64 but did not"
fi
if dm_architecture_covers_target 'amd64' amd64 \
   && dm_architecture_covers_target 'any' amd64 \
   && dm_architecture_covers_target 'linux-any' amd64 \
   && dm_architecture_covers_target 'linux-amd64' amd64; then
   pass "arch wildcard: plain / any / linux-any / linux-amd64 still cover amd64"
else
   fail "arch wildcard: a plain/any/linux-any/linux-amd64 token stopped covering amd64"
fi
if dm_architecture_covers_target 'i386' amd64 \
   || dm_architecture_covers_target 'any-i386' amd64; then
   fail "arch wildcard: an i386-only stanza must NOT cover amd64"
else
   pass "arch wildcard: i386 / any-i386 do not cover amd64"
fi
## Multiple tokens in one field: a covering token anywhere in the list wins.
if dm_architecture_covers_target 'i386 any-amd64' amd64; then
   pass "arch wildcard: a covering token later in a multi-token field still matches"
else
   fail "arch wildcard: a covering token in a multi-token field was missed"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: dm_package_needs_rebuild is content-hash + artifact-presence (${pass_count} assertions)."

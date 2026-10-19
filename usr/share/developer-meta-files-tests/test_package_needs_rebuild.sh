#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Behavioural test for developer-meta-files' package-build-freshness.bsh.
## dm_package_needs_rebuild decides from a source-CONTENT hash manifest AND from
## whether the built binaries are published in the LOCAL reprepro pool. The
## production artifact check (dm_package_artifacts_present) runs
## 'reprepro <opts> list local <pkg>' once per binary stanza and requires a
## 'local|<component>|<target-arch>: <pkg> <version>' line for every build target
## the stanza covers (arch:all is checked under the target arch, like reprepro's
## own per-arch listing). Sources the real library and drives the real functions
## over a fixture package tree with a STUBBED reprepro -- the real one needs a
## configured, gpg-signed pool, out of scope for a hermetic unit test.
##
## Asserts (reprepro semantics -- the version is matched VERBATIM, epoch and all):
##   * no binary published in the local pool  -> rebuild;
##   * published but no manifest entry (first sight) -> rebuild;
##   * recorded + unchanged + published       -> skip;
##   * recorded + published but the pool lost it -> rebuild (manifest stale vs pool);
##   * a source edit with NO changelog bump    -> rebuild (content hash moved);
##   * a debian/changelog version bump         -> rebuild (the changelog is hashed too);
##   * an epoch version (3:1.0-2): reprepro reports the full version, so the
##     function matches it verbatim -- published at 3:1.0-2 -> skip, absent -> rebuild
##     (a false epoch-strip would look for 1.0-2 and miss it);
##   * multi-binary source: EVERY binary must be published, so a missing one -> rebuild;
##   * an arch-dependent binary ('any') is required under the TARGET arch, not a
##     different one;
##   * control parsing robustness: a stanza with Architecture BEFORE Package is
##     still parsed (grep-dctrl, field-order safe), so its missing binary rebuilds;
##   * a hash FAILURE ('nohash' sentinel) forces a rebuild, never compared like a digest.
## Plus a structural guard that the removed reprepro published-VERSION path (a
## different, deleted function) stays gone and dm_package_needs_rebuild takes two
## arguments (no repository_name).
##
## Self-contained; sources the side-effect-free library. dpkg-parsechangelog,
## grep-dctrl, sha256sum and find are real requirements; reprepro is stubbed.
## Needs no root, no network, no build, no real reprepro.
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
for tool in dpkg-parsechangelog grep-dctrl sha256sum find; do
   if ! command -v "${tool}" >/dev/null; then
      printf '%s\n' "FATAL: '${tool}' missing; a hard requirement of the library under test." >&2
      exit 1
   fi
done

## --- STRUCTURAL: the removed reprepro published-VERSION path stayed removed ---
## (dm_package_artifacts_present uses 'reprepro list local'; the deleted function
## below is the OLD published-version comparison, a different thing.)
if grep --quiet --fixed-strings -- 'dm_reprepro_published_source_version' "${subject}"; then
   fail "structural: the reprepro published-version function is back; the removed path should stay removed"
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

## Pin the build target so the reprepro match is deterministic regardless of host.
export dist_build_target_arch='amd64'
unset make_cross_build_platform_list 2>/dev/null || true
## The library expands this array when invoking reprepro; empty for the stub.
# shellcheck disable=SC2034 # read by the sourced library at runtime
dist_build_reprepro_folder_options=()

## --- reprepro stub ----------------------------------------------------------
## Emulates 'reprepro [opts] list <distribution> [<pkg>]' from a controllable
## present-set REPREPRO_STUB_DB (one '<pkg> <arch> <version>' per line), printing
## reprepro's native 'local|<component>|<arch>: <pkg> <version>' for matches. A
## package absent from the set yields no line (reprepro still exits 0), so the
## library reads it as not-published and rebuilds.
stub_bin="${workdir}/stub-bin"
mkdir --parents -- "${stub_bin}"
export REPREPRO_STUB_DB="${workdir}/reprepro-present.txt"
printf '%s' '' > "${REPREPRO_STUB_DB}"
cat > "${stub_bin}/reprepro" <<'STUB'
#!/bin/bash
## Test stub for reprepro list; see test_package_needs_rebuild.sh.
## style-ok: no-has -- throwaway test stub.
set -o nounset
db="${REPREPRO_STUB_DB:-}"
seen_list=''
distribution=''
query_pkg=''
for arg in "$@"; do
   if [ "${arg}" = 'list' ]; then
      seen_list='yes'
      continue
   fi
   if [ -n "${seen_list}" ] && [ -z "${distribution}" ]; then
      distribution="${arg}"
      continue
   fi
   if [ -n "${distribution}" ] && [ -z "${query_pkg}" ]; then
      query_pkg="${arg}"
      continue
   fi
done
[ -n "${seen_list}" ] || exit 0
{ [ -n "${db}" ] && [ -f "${db}" ]; } || exit 0
while read -r entry_pkg entry_arch entry_version; do
   [ -n "${entry_pkg}" ] || continue
   if [ "${entry_pkg}" = "${query_pkg}" ]; then
      printf '%s\n' "${distribution}|main|${entry_arch}: ${entry_pkg} ${entry_version}"
   fi
done < "${db}"
STUB
chmod +x "${stub_bin}/reprepro"
export PATH="${stub_bin}:${PATH}"

pkg_dir="${workdir}/src"
mkdir --parents -- "${pkg_dir}/debian"
printf '%s\n' 'payload one' > "${pkg_dir}/file_a"
printf '%s\n' 'payload two' > "${pkg_dir}/file_b"
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: testpkg
Package: testpkg
Architecture: all
Description: fixture package
 Fixture.
CONTROL

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

cur_ver() {
   dpkg-parsechangelog --show-field Version --file "${pkg_dir}/debian/changelog"
}
## Publish a binary into the reprepro-stub pool (arch defaults to the target).
publish() {
   printf '%s\n' "$1 ${2:-amd64} ${3:-$(cur_ver)}" >> "${REPREPRO_STUB_DB}"
}
unpublish_all() {
   printf '%s' '' > "${REPREPRO_STUB_DB}"
}
needs_rebuild() {
   local rc=0
   dm_package_needs_rebuild "${pkg_dir}" "${codename}" >/dev/null 2>&1 || rc="$?"
   printf '%s' "${rc}"
}
record_now() {
   dm_source_hash_record "${manifest}" 'testpkg' "$(dm_package_source_hash "${pkg_dir}")"
}

## Nothing published in the local pool -> rebuild (0), regardless of the manifest.
unpublish_all
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "no binary in the local pool -> rebuild"
else
   fail "nothing published should rebuild, but was skipped"
fi

## Published but no manifest entry (first sight) -> rebuild (0).
publish testpkg
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "published + no manifest entry (first sight) -> rebuild"
else
   fail "first sight should rebuild, but was skipped"
fi

## Recorded + unchanged + published -> skip (1).
record_now
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "recorded + unchanged + published -> skip"
else
   fail "recorded + unchanged + published should skip, but wanted rebuild"
fi

## Recorded + unchanged but the pool lost it (reverted/cleared while the
## persistent manifest survived) -> rebuild (0). The hash-only path skipped here
## and would ship a stale binary.
unpublish_all
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "recorded + unchanged + pool lost it -> rebuild (manifest stale vs pool)"
else
   fail "a package absent from the pool must rebuild, but was skipped"
fi
publish testpkg

## Edit a source file, NO changelog bump -> rebuild (0): content hash moved while
## the published version is unchanged.
printf '%s\n' 'payload two EDITED' > "${pkg_dir}/file_b"
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "source edit without a changelog bump -> rebuild (content hash moved)"
else
   fail "an unrecorded source edit should rebuild, but was skipped"
fi

## Re-record at the edited content, then bump ONLY the changelog -> rebuild (0),
## because debian/changelog is part of the hashed tree. Republish at the new
## version so the artifact check passes and the HASH path is what is exercised.
record_now
write_changelog '1.0-2'
unpublish_all
publish testpkg
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "changelog version bump -> rebuild (the changelog is hashed too)"
else
   fail "a changelog bump should rebuild, but was skipped"
fi

## Epoch in the changelog (3:1.0-2): reprepro reports the FULL version, so the
## library must match it verbatim. Published at 3:1.0-2 with the hash recorded
## -> skip; a false epoch-strip would look for 1.0-2 and miss it.
unpublish_all
write_changelog '3:1.0-2'
record_now
publish testpkg
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "epoch version: published at the full epoch version -> skip (no epoch strip)"
else
   fail "epoch version: full-version published should skip, but wanted rebuild"
fi
## And absent again -> rebuild.
unpublish_all
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "epoch version: not published -> rebuild"
else
   fail "epoch version: not published must rebuild, but was skipped"
fi

## --- multi-binary: EVERY produced binary must be published ------------------
unpublish_all
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
publish testpkg
publish testpkg-extra
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "multi-binary: all produced binaries published -> skip"
else
   fail "multi-binary: all binaries published should skip, but wanted rebuild"
fi
## Only one of the two published -> rebuild.
unpublish_all
publish testpkg
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "multi-binary: a missing binary -> rebuild"
else
   fail "multi-binary: a missing binary must rebuild, but was skipped"
fi
unpublish_all

## --- arch-dependent 'any' is required under the TARGET arch -----------------
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: testpkg

Package: testpkg
Architecture: any
Description: fixture arch-dependent
 Arch.
CONTROL
write_changelog '2.0-2'
record_now
## Published only under a NON-target arch -> rebuild (the target amd64 is absent).
publish testpkg i386
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "arch 'any': published under a non-target arch only -> rebuild"
else
   fail "arch 'any': a non-target arch should not satisfy the target, but skipped"
fi
## Published under the target arch -> skip.
publish testpkg amd64
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "arch 'any': published under the target arch -> skip"
else
   fail "arch 'any': the target arch published should skip, but wanted rebuild"
fi
unpublish_all

## --- field order within a stanza is arbitrary (grep-dctrl, field-order safe) -
## A binary stanza listing Architecture BEFORE Package must still be parsed, or
## its binary goes unchecked and a sibling's presence yields a false skip.
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
publish testpkg
if [ "$(needs_rebuild)" -eq 0 ]; then
   pass "reordered stanza (Architecture before Package): its missing binary -> rebuild"
else
   fail "a reordered stanza was dropped; its missing binary produced a false skip"
fi
publish testpkg-extra
if [ "$(needs_rebuild)" -eq 1 ]; then
   pass "reordered stanza: both binaries published -> skip"
else
   fail "reordered stanza: both published should skip, but wanted rebuild"
fi
unpublish_all

## Restore the single-binary Architecture: all fixture for the remaining checks.
cat > "${pkg_dir}/debian/control" <<'CONTROL'
Source: testpkg

Package: testpkg
Architecture: all
Description: fixture package
 Fixture.
CONTROL
write_changelog '3.0-9'
publish testpkg

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
## check for that binary and read a missing one as present ("fresh").
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
printf '%s\n' "OK: dm_package_needs_rebuild is content-hash + reprepro artifact-presence (${pass_count} assertions)."

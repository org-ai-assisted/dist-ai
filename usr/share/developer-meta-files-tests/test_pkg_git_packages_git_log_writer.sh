#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards dm-packaging-helper-script's release-changelog generator:
##
## - pkg_git_packages_git_log_writer looks up each package's path in the OLD
##   and NEW release tags. The old-tag lookup is guarded (a miss -> new
##   package); the new-tag lookup MUST be guarded too. A package present in
##   the working tree but absent from the new release tag (added after the
##   tag, or removed by it) must be SKIPPED, not crash the whole batch under
##   errexit. Regression: dropping the new-tag guard re-aborts every release
##   run whose tree holds a package not in refs/tags/${new}.
##
## - generate_announcement must embed each project's changelog CONTENTS
##   (per project), not the literal changelog-file PATH, and the Whonix
##   announcement must draw from the Whonix changelog, not the Kicksecure
##   one. Regression: reverting either re-emits a bare path / the wrong file.
##
## Unit test of the REAL functions (awk-extracted from the current script
## text, so no drift) against throwaway git repos and the real helper-scripts
## binaries. No root, no network, no build.

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
   test_failures=$(( test_failures + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

## Required real dependencies (git, str_replace, overwrite, safe-rm) are
## assumed present and called directly; an absence fails loud at the call.

rel='usr/bin/dm-packaging-helper-script'
candidates=()
[ -z "${DM_PACKAGING_HELPER_SCRIPT:-}" ] || candidates+=( "${DM_PACKAGING_HELPER_SCRIPT}" )
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
   printf '%s\n' "FATAL: dm-packaging-helper-script not found (set DM_PACKAGING_HELPER_SCRIPT)." >&2
   exit 1
fi

## Extract one function's body. Its closing brace is the only '}' at column 0.
extract_func() {
   local name="${1}" text
   text="$(awk -v fn="^${name}\\\\(\\\\) \\\\{" '
      $0 ~ fn   { f=1 }
      f         { print }
      f && /^\}/ { exit }
   ' "${subject}")"
   if [ -z "${text}" ]; then
      printf '%s\n' "FATAL: could not extract ${name} from '${subject}'." >&2
      exit 1
   fi
   printf '%s\n' "${text}"
}

writer_text="$(extract_func pkg_git_packages_git_log_writer)"
dry_run_text="$(extract_func dry_run_or_run)"
filter_text="$(extract_func commit_filter)"
announce_text="$(extract_func generate_announcement)"

## Assert the resolved subject carries the new-tag guard; otherwise a stale
## subject (old /usr/bin copy, pre-fix checkout) would fail with a misleading
## "crashed" assertion against code that genuinely lacks the fix.
if [[ "${writer_text}" != *'not in refs/tags/'* ]]; then
   printf '%s\n' "FATAL: resolved dm-packaging-helper-script ('${subject}') predates the new-tag guard; point DEVELOPER_META_FILES_DIR at a checkout that has it." >&2
   exit 1
fi

tmp_root="$(mktemp -d)"
## Scrub inherited git location vars: an inherited GIT_DIR (e.g. from a git
## hook) makes git operate on the hook's repo, not the fixture.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
   GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_NAMESPACE
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${tmp_root}"
}
trap cleanup EXIT

git_c() {
   git -C "${1}" -c user.name=t -c user.email=t@t -c commit.gpgsign=false "${@:2}"
}

## A parent repo (plays the derivative-maker root) holding a package at
## packages/kicksecure/${pkg}. ${2}=present_in_new controls whether the
## package path exists in the tag the writer reads as the NEW release.
make_parent() {
   local pkg="${1}" present_in_new="${2}" parent
   parent="$(mktemp -d -p "${tmp_root}")"
   git -C "${parent}" init -q -b master
   mkdir --parents -- "${parent}/packages/kicksecure"
   if [ "${present_in_new}" = 'true' ]; then
      ## testpkg exists at the tagged commit: old == new -> equal-version skip.
      mkdir -- "${parent}/packages/kicksecure/${pkg}"
      printf 'x\n' > "${parent}/packages/kicksecure/${pkg}/f"
      git_c "${parent}" add -A
      git_c "${parent}" commit -q -m c1
      git_c "${parent}" tag oldtag
      git_c "${parent}" tag newtag
   else
      ## Tagged commit has NO testpkg; it appears only in the working tree
      ## afterwards -> absent from both tags (added after the release tag).
      printf 'y\n' > "${parent}/packages/kicksecure/keep"
      git_c "${parent}" add -A
      git_c "${parent}" commit -q -m c1
      git_c "${parent}" tag oldtag
      git_c "${parent}" tag newtag
      mkdir -- "${parent}/packages/kicksecure/${pkg}"
      printf 'x\n' > "${parent}/packages/kicksecure/${pkg}/f"
   fi
   printf '%s\n' "${parent}"
}

## Run the extracted writer for package ${pkg} inside ${parent}, via a
## dedicated inner SCRIPT (a child process). A plain subshell would inherit
## this test's errexit state, which the calling `if run_writer` context
## SUPPRESSES -- masking exactly the unguarded-rev-parse abort under test. A
## child process has its own active errexit, so the production failure is
## reproduced. (The inner script, not an inline -c, keeps R-192 happy.)
inner="$(dirname -- "${BASH_SOURCE[0]}")/pkg_git_log_writer_run_inner.sh"
run_writer() {
   local parent="${1}" pkg="${2}"
   WRITER_TEXT="${writer_text}" bash "${inner}" "${parent}" "${pkg}"
}

## --- Finding 1: new-tag miss is skipped, not crashed ------------------------
parent_absent="$(make_parent testpkg false)"
if run_writer "${parent_absent}" testpkg; then
   pass "package absent from new tag -> skipped (return 0)"
else
   fail "package absent from new tag -> non-zero (old code aborts the batch here)"
fi

## --- Finding 1 companion: the guarded lookups still drive the happy path ----
parent_present="$(make_parent testpkg true)"
if run_writer "${parent_present}" testpkg; then
   pass "package present, old == new -> equal-version skip (guarded rev-parse works)"
else
   fail "package present, old == new -> non-zero (guard broke the normal path)"
fi

## --- Finding 3: announcement embeds per-project changelog CONTENTS ----------
drafts="$(mktemp -d -p "${tmp_root}")"
printf '%s\n' 'KSENTINEL-changelog-line' > "${drafts}/kicksecure_giant_git_log.txt"
printf '%s\n' 'WSENTINEL-changelog-line' > "${drafts}/whonix_giant_git_log.txt"
(
   # shellcheck disable=SC2034  # consumed by the extracted functions
   {
      announcements_drafts_dir="${drafts}"
      derivative_name_list=( kicksecure whonix )
      derivative_version_old_main='18.2.1.0-developers-only'
      derivative_version_new_main='18.2.1.7-developers-only'
      derivative_release_type='point'
      batch_meta_dry_run='false'
   }
   eval "${dry_run_text}"
   eval "${announce_text}"
   generate_announcement >/dev/null 2>&1
)
ks="${drafts}/Kicksecure.txt"
ws="${drafts}/Whonix.txt"
if [ -r "${ks}" ] && grep --quiet -- 'KSENTINEL-changelog-line' "${ks}" \
   && ! grep --quiet -- 'kicksecure_giant_git_log.txt' "${ks}"; then
   pass "Kicksecure announcement embeds changelog contents, not the file path"
else
   fail "Kicksecure announcement missing changelog contents or emits the literal path"
fi
if [ -r "${ws}" ] && grep --quiet -- 'WSENTINEL-changelog-line' "${ws}" \
   && ! grep --quiet -- 'KSENTINEL-changelog-line' "${ws}"; then
   pass "Whonix announcement draws from the Whonix changelog, not the Kicksecure one"
else
   fail "Whonix announcement drew from the wrong (Kicksecure) changelog"
fi

## --- Single-pass commit loop emits correctly (guards the perf refactor) -----
## Cases A-C return before the commit loop; this drives it: a surviving commit,
## one with a multi-line body + an AI trailer that must be stripped and an AI
## author that earns credit, and a noise commit the filter must drop.
emit_inner="$(dirname -- "${BASH_SOURCE[0]}")/pkg_git_log_writer_emit_inner.sh"
emit_repo="$(mktemp -d -p "${tmp_root}")"
emit_out="$(mktemp -p "${tmp_root}")"
## Authors are set with explicit --author (overrides any ambient GIT_AUTHOR_*
## env) so credit mapping is deterministic: a human -> "(Thanks to X!)", the
## AI bot -> "(AI assisted)".
git -C "${emit_repo}" init -q -b master
git_c "${emit_repo}" commit -q --allow-empty -m base
git_c "${emit_repo}" tag emit_old
git_c "${emit_repo}" commit -q --allow-empty \
   --author='A Human <h@example.invalid>' -m 'real feature one'
printf '%s\n' 'feature two' '' 'a detail body line' '' \
   'Co-Authored-By: Claude <noreply@anthropic.com>' \
   | git_c "${emit_repo}" commit -q --allow-empty \
      --author='assisted-by-ai (Bot Account) <ai@example.invalid>' -F -
git_c "${emit_repo}" commit -q --allow-empty -m 'typo'
git_c "${emit_repo}" tag emit_new

WRITER_TEXT="${writer_text}" DRY_RUN_TEXT="${dry_run_text}" FILTER_TEXT="${filter_text}" \
   bash "${emit_inner}" "${emit_repo}" emit_old emit_new "${emit_out}"

emit_ok=true
grep --quiet --fixed-strings -- '* derivative-maker:'                   "${emit_out}" || emit_ok=false
grep --quiet --fixed-strings -- '  * real feature one (Thanks to A Human!)' "${emit_out}" || emit_ok=false
grep --quiet --fixed-strings -- '  * feature two (AI assisted)'        "${emit_out}" || emit_ok=false
grep --quiet --fixed-strings -- '    a detail body line'               "${emit_out}" || emit_ok=false
## AI trailer stripped and the noise commit filtered out.
! grep --quiet --fixed-strings -- 'Co-Authored-By' "${emit_out}" || emit_ok=false
! grep --quiet --fixed-strings -- 'typo'           "${emit_out}" || emit_ok=false
if [ "${emit_ok}" = 'true' ]; then
   pass "single-pass loop: bullets, credit, multi-line body, trailer-strip, filter"
else
   fail "single-pass loop emission wrong: $(tr '\n' '|' < "${emit_out}")"
fi

printf '%s\n' "${pass_count} pass, ${test_failures} fail, 0 skip"
[ "${test_failures}" -eq 0 ]

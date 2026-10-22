#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards dm-packaging-helper-script's git_commit_pathspecs (used by
## pkg_git_manpages and pkg_git_debinstfile):
## - A plain 'git commit -- A B' treats an UNMATCHED pathspec as fatal and
##   aborts the WHOLE commit. The old code ran
##   'git commit -m msg -- man auto-generated-man-pages || true', so for a
##   package with hand-written 'man/' pages and NO 'auto-generated-man-pages'
##   dir the commit aborted and '|| true' masked it, silently DROPPING the
##   staged 'man/' changes (package then neither bumped nor built).
## - The fix filters to the pathspecs that actually have staged content, so an
##   absent pathspec can no longer abort the commit, and needs no masking.
## Regression: reverting to the single multi-pathspec commit (or re-adding
## '|| true' around an unfiltered commit) reopens the silent-drop hole.
##
## Unit test of the REAL function (extracted from the current script text, so
## no drift -- the same drift-guarded pattern as test_pkg_git_branch_agnostic.sh;
## the subject is not source-able) against throwaway git repos. No root, no
## network, no build.

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

## Extract the function body. Its closing brace is the only '}' at column 0.
func_text="$(awk '
   /^git_commit_pathspecs\(\) \{/ { f=1 }
   f                              { print }
   f && /^\}/                     { exit }
' "${subject}")"
if [ -z "${func_text}" ]; then
   printf '%s\n' "FATAL: resolved dm-packaging-helper-script ('${subject}') predates the git_commit_pathspecs pathspec-abort fix; point DEVELOPER_META_FILES_DIR at a developer-meta-files checkout that has it." >&2
   exit 1
fi
if [[ "${func_text}" != *'--cached'* ]]; then
   printf '%s\n' "FATAL: git_commit_pathspecs in '${subject}' lacks the staged-content filter ('--cached' index check); subject predates the fix." >&2
   exit 1
fi

## The helper is dead code unless both callers use it.
for caller in pkg_git_manpages pkg_git_debinstfile; do
   caller_text="$(awk -v fn="${caller}" '
      $0 ~ "^" fn "\\(\\) \\{" { f=1 }
      f                        { print }
      f && /^\}/               { exit }
   ' "${subject}")"
   if [[ "${caller_text}" != *git_commit_pathspecs* ]]; then
      fail "${caller} does not call git_commit_pathspecs (wiring regressed)"
   else
      pass "${caller} wires through git_commit_pathspecs"
   fi
done

## pkg_git_manpages must stage the man dirs WHOLESALE, not a 'man'/* glob: the
## glob misses dotfiles and tracked-file deletions, leaving the index behind the
## worktree. Since git_commit_pathspecs commits with 'git commit -- <dir>' (git
## commit --only = records the worktree), a lagging index silently drops a
## deletion or commits an unstaged edit. Guard against a regression to the glob.
manpages_text="$(awk '
   /^pkg_git_manpages\(\) \{/ { f=1 }
   f                          { print }
   f && /^\}/                 { exit }
' "${subject}")"
if [[ "${manpages_text}" == *"add -- 'man'/*"* ]]; then
   fail "pkg_git_manpages stages a 'man'/* glob (misses dotfiles/deletions); stage the dir"
else
   pass "pkg_git_manpages stages the man dirs wholesale, not a glob"
fi

tmp_root="$(mktemp -d)"
## Scrub inherited git location vars: an inherited GIT_DIR (etc.) makes bare
## 'git' operate on this test runner's real repo, not the fixture.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
   GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_NAMESPACE
## Isolate from ambient git config: a global commit.gpgsign=true would make the
## fixture's own 'git commit' (and the helper's bare 'git commit') try to sign
## with a key the sandbox / CI lacks -- "gpg failed to sign ... failed to write
## commit object" -- falsely failing correct code. Also clear the inline-config
## env that git carries across a child process.
unset GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${tmp_root}"
}
trap cleanup EXIT

## A throwaway repo with the given dirs committed, then a fresh edit staged in
## each. Caller lists the dirs to seed+stage; 'auto-generated-man-pages' is
## omitted to model the hand-written-man-pages case.
make_repo() {
   local repo dir
   repo="$(mktemp -d -p "${tmp_root}")"
   git -C "${repo}" init -q -b master
   git -C "${repo}" config user.name t
   git -C "${repo}" config user.email t@t
   git -C "${repo}" config commit.gpgsign false
   for dir in "$@"; do
      mkdir -p "${repo}/${dir}"
      printf '%s\n' 'orig' > "${repo}/${dir}/page"
   done
   git -C "${repo}" add -A
   git -C "${repo}" commit -q -m seed
   ## Now stage a real change in each seeded dir.
   for dir in "$@"; do
      printf '%s\n' 'changed' > "${repo}/${dir}/page"
      git -C "${repo}" add -- "${dir}"
   done
   printf '%s\n' "${repo}"
}

## Run the extracted helper inside ${repo}. Remaining args are the pathspecs.
run_commit() {
   local repo="${1}"
   shift
   (
      cd -- "${repo}"
      # shellcheck disable=SC2034  # read by the dry-run branch of the eval'd function
      batch_meta_dry_run='false'
      ## Stub only exercised in the dry-run branch (not hit here).
      # shellcheck disable=SC2317  # invoked indirectly via the eval'd function
      dry_run_or_run() { "$@"; }
      eval "${func_text}"
      git_commit_pathspecs 'test commit' "$@"
   )
}

head_of() { git -C "${1}" rev-parse HEAD; }
## 'man/page' content at HEAD, or empty if the path is absent there.
head_man_page() { git -C "${1}" show 'HEAD:man/page' 2>/dev/null || true; }
staged_empty() { git -C "${1}" diff --cached --quiet; }

## --- 1. the bug scenario: man/ staged, auto-generated-man-pages ABSENT ------
repo1="$(make_repo man)"
before1="$(head_of "${repo1}")"
run_commit "${repo1}" man auto-generated-man-pages
after1="$(head_of "${repo1}")"
if [ "${before1}" = "${after1}" ]; then
   fail "man-only + absent sibling: no commit created (change dropped)"
elif [ "$(head_man_page "${repo1}")" != "changed" ]; then
   fail "man-only + absent sibling: committed HEAD lacks the man/ change"
elif ! staged_empty "${repo1}"; then
   fail "man-only + absent sibling: man/ change left staged, not committed"
else
   pass "man-only + absent sibling: man/ change committed (not dropped)"
fi

## --- 2. canary: the OLD unfiltered form DOES drop the change ----------------
## Proves the scenario is real (the test would be meaningless if a plain
## multi-pathspec commit already handled it).
repo2="$(make_repo man)"
before2="$(head_of "${repo2}")"
(
   cd -- "${repo2}"
   git commit -m 'old form' -- man auto-generated-man-pages || true
) >/dev/null 2>&1
after2="$(head_of "${repo2}")"
if [ "${before2}" != "${after2}" ]; then
   fail "canary: old 'git commit -- man auto-generated-man-pages || true' unexpectedly committed"
elif staged_empty "${repo2}"; then
   fail "canary: old form left nothing staged (scenario not reproduced)"
else
   pass "canary: old unfiltered commit aborts and leaves man/ staged (bug reproduced)"
fi

## --- 3. both dirs present + staged: one commit carries both -----------------
repo3="$(make_repo man auto-generated-man-pages)"
before3="$(head_of "${repo3}")"
run_commit "${repo3}" man auto-generated-man-pages
after3="$(head_of "${repo3}")"
if [ "${before3}" = "${after3}" ]; then
   fail "both staged: no commit created"
elif ! staged_empty "${repo3}"; then
   fail "both staged: changes left staged after commit"
elif [ "$(git -C "${repo3}" show 'HEAD:auto-generated-man-pages/page')" != "changed" ]; then
   fail "both staged: auto-generated-man-pages change not committed"
else
   pass "both staged: single commit carries both pathspecs"
fi

## --- 4. nothing staged: no-op, no error ------------------------------------
repo4="$(make_repo man)"
git -C "${repo4}" reset -q    ## unstage everything -> nothing to commit
before4="$(head_of "${repo4}")"
if run_commit "${repo4}" man auto-generated-man-pages; then
   after4="$(head_of "${repo4}")"
   if [ "${before4}" = "${after4}" ]; then
      pass "nothing staged: no-op (no commit, no error)"
   else
      fail "nothing staged: unexpectedly created a commit"
   fi
else
   fail "nothing staged: returned non-zero (should be a clean no-op)"
fi

printf '%s\n' "${pass_count} pass, ${test_failures} fail, 0 skip"
[ "${test_failures}" -eq 0 ]

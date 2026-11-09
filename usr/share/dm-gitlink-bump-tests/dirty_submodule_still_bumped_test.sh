#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression guard: a submodule whose committed HEAD is published-ahead of the
## pin must stay VISIBLE to dm-gitlink-bump even when its worktree has
## uncommitted tracked changes. The gitlink pin is the committed HEAD, so an
## unrelated dirty file (a sibling session's WIP on the shared multi-session
## tree) must NOT exempt it: a dirty submodule is the COMMON case here, and
## hiding its stale pin makes the --check pre-push gate a false green (CI then
## builds the old submodule tree with nothing flagging it).
##
## Canary: the old filter skipped any submodule with uncommitted tracked changes
## BEFORE the published-ahead test, so '--check' returned 0 (clean) and the bump
## pin stayed c0 -> BOTH assertions FAIL on old code. A filter broken to accept
## everything is caught by published_org_only_test.sh (the mirror-only cases).
##
## Drives the REAL dm-gitlink-bump against a throwaway superproject + submodule.
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Resolve dm-gitlink-bump under test (runner exports DM_GITLINK_BUMP).
locate_bin() {
   local candidate
   for candidate in \
      "${DM_GITLINK_BUMP:-}" \
      "$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/../../bin/dm-gitlink-bump" \
      /usr/bin/dm-gitlink-bump
   do
      [ -n "${candidate}" ] || continue
      if test -x "${candidate}"; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

if ! bin="$(locate_bin)"; then
   printf '%s\n' 'FATAL: dm-gitlink-bump not found (set DM_GITLINK_BUMP).' >&2
   exit 1
fi

## Not testing a possibly-stale install when nothing was wired.
if [ -z "${DM_GITLINK_BUMP:-}" ] && [ "${bin}" = "/usr/bin/dm-gitlink-bump" ]; then
   printf '%s\n' "SKIP: no dm-gitlink-bump checkout wired (set DM_GITLINK_BUMP); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() { safe-rm -r -f -- "${test_root}"; }
trap cleanup EXIT

## Hermetic: ignore host global/system config (hooksPath, identity).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

git_fx() { git -c core.hooksPath=/dev/null -c commit.gpgsign=false "$@"; }
set_identity() { git -C "$1" config user.email fx@example.invalid && git -C "$1" config user.name fx; }

## Published-ahead fixture WITH a tracked file so the worktree can be dirtied:
## submodule 'ai' HEAD (c1) one commit ahead of the pin (c0), the org remote's
## tracking 'ai' ref set to c1 (published tip), then a tracked file modified so
## 'git status' reports the worktree dirty. Emits "${c0} ${c1}".
make_dirty_fixture() {
   local dir="$1"
   local super="${dir}/super" sub
   sub="${super}/sub"
   local url='git@github.com:org-ai-assisted/sub.git'
   mkdir -p -- "${sub}"
   git_fx -C "${sub}" init -q -b ai
   set_identity "${sub}"
   printf '%s\n' v0 > "${sub}/data.txt"
   git_fx -C "${sub}" add data.txt
   git_fx -C "${sub}" commit -q -m c0
   local c0 c1
   c0="$(git -C "${sub}" rev-parse HEAD)"
   printf '%s\n' v1 > "${sub}/data.txt"
   git_fx -C "${sub}" commit -q -m c1 -- data.txt
   c1="$(git -C "${sub}" rev-parse HEAD)"
   git_fx -C "${sub}" remote add org-ai-assisted "${url}"
   git_fx -C "${sub}" update-ref 'refs/remotes/org-ai-assisted/ai' "${c1}"

   ## build-steps.d + help-steps mark the superproject as a derivative-maker
   ## checkout (the tool refuses anything else).
   mkdir -p -- "${super}/build-steps.d" "${super}/help-steps"
   git_fx -C "${super}" init -q -b ai
   set_identity "${super}"
   cat > "${super}/.gitmodules" <<EOF
[submodule "sub"]
	path = sub
	url = ${url}
EOF
   git_fx -C "${super}" add .gitmodules
   git_fx -C "${super}" update-index --add --cacheinfo "160000,${c0},sub"
   git_fx -C "${super}" commit -q -m init

   ## Dirty the submodule worktree AFTER pinning c0: a tracked file with an
   ## uncommitted change (stands in for a sibling session's WIP).
   printf '%s\n' dirty >> "${sub}/data.txt"

   printf '%s\n' "${c0} ${c1}"
}

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }
fail() { tests_failed=$(( tests_failed + 1 )); printf '%s\n' "FAIL  $1" >&2; }
count() { tests_total=$(( tests_total + 1 )); }

read -r c0 c1 < <(make_dirty_fixture "${test_root}/case")
super="${test_root}/case/super"

## Sanity: the submodule worktree really is dirty (else the test is vacuous).
if [ -n "$(git -C "${super}/sub" status --porcelain --untracked-files=no)" ]; then
   pass "fixture: submodule worktree is dirty"
else
   fail "fixture: submodule worktree is NOT dirty (test would be vacuous)"
fi
count

## CASE 1: '--check' must DETECT the stale pin (exit 3) despite the dirty tree.
check_rc=0
"${bin}" --check --dir "${super}" >/dev/null 2>&1 || check_rc=$?
count
if [ "${check_rc}" -eq 3 ]; then
   pass "check: dirty published-ahead pin flagged (exit 3)"
else
   fail "check: dirty published-ahead pin NOT flagged (exit ${check_rc}, want 3)"
fi

## CASE 2: the bump must pin c0 -> c1 despite the dirty tree.
"${bin}" --dir "${super}" >/dev/null 2>&1 || true
pin="$(git -C "${super}" rev-parse --verify --quiet 'HEAD:sub' || true)"
count
if [ "${pin}" = "${c1}" ]; then
   pass "bump: dirty submodule pinned ${c0:0:12} -> ${c1:0:12}"
else
   fail "bump: dirty submodule NOT pinned (pin=${pin:0:12}, want ${c1:0:12})"
fi

## CASE 3: the bump records the committed HEAD only -- the submodule worktree
## stays dirty (the gitlink never captures uncommitted files).
if [ -n "$(git -C "${super}/sub" status --porcelain --untracked-files=no)" ]; then
   pass "bump: submodule worktree still dirty (gitlink is HEAD, not worktree)"
else
   fail "bump: submodule worktree unexpectedly clean after bump"
fi
count

## CASE 4: after the bump the superproject index matches HEAD. The tool commits
## the validated sha via a private index, then syncs the SHARED index to it, so
## no staged gitlink "downgrade" (index c0 vs HEAD c1) is left for a later
## sibling commit to carry. A commit-tree without that sync leaves this RED.
count
if git -C "${super}" diff --cached --quiet; then
   pass "post-bump: superproject index consistent with HEAD"
else
   fail "post-bump: superproject index has a staged gitlink mismatch vs HEAD"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "dirty_submodule_still_bumped_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "dirty_submodule_still_bumped_test: ${tests_total} pass, 0 fail, 0 skip"

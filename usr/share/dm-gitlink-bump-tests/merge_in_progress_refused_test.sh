#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression guard: dm-gitlink-bump commits the parent gitlink with plumbing
## (commit-tree), which -- unlike the porcelain 'git commit' it replaced -- does
## NOT refuse a commit while a merge or sequencer operation is unfinished. A
## single-parent plumbing commit in that state would drop the second parent and
## the staged merge result and leave MERGE_HEAD dangling. The tool must therefore
## refuse (exit 2) and make no commit when a *_HEAD marker is present.
##
## Canary: without the refusal the tool exits 0, advances the branch, and the
## superproject HEAD subject becomes the bump -- this test FAILS on that.
##
## Drives the REAL dm-gitlink-bump against a throwaway superproject. No root,
## no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

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

if [ -z "${DM_GITLINK_BUMP:-}" ] && [ "${bin}" = "/usr/bin/dm-gitlink-bump" ]; then
   printf '%s\n' "SKIP: no dm-gitlink-bump checkout wired (set DM_GITLINK_BUMP); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() { safe-rm -r -f -- "${test_root}"; }
trap cleanup EXIT

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

git_fx() { git -c core.hooksPath=/dev/null -c commit.gpgsign=false "$@"; }
set_identity() { git -C "$1" config user.email fx@example.invalid && git -C "$1" config user.name fx; }

super="${test_root}/super"
sub="${super}/sub"
url='git@github.com:org-ai-assisted/sub.git'
mkdir -p -- "${sub}"
git_fx -C "${sub}" init -q -b ai
set_identity "${sub}"
git_fx -C "${sub}" commit -q --allow-empty -m c0
c0="$(git -C "${sub}" rev-parse HEAD)"
git_fx -C "${sub}" commit -q --allow-empty -m c1
c1="$(git -C "${sub}" rev-parse HEAD)"
git_fx -C "${sub}" remote add org-ai-assisted "${url}"
git_fx -C "${sub}" update-ref 'refs/remotes/org-ai-assisted/ai' "${c1}"

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
pre_tip="$(git -C "${super}" rev-parse HEAD)"

## Simulate a merge in progress: a MERGE_HEAD marker at a real commit, written to
## the ABSOLUTE gitdir ('--git-path' alone is cwd-relative).
printf '%s\n' "${pre_tip}" > "$(git -C "${super}" rev-parse --absolute-git-dir)/MERGE_HEAD"

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }
fail() { tests_failed=$(( tests_failed + 1 )); printf '%s\n' "FAIL  $1" >&2; }
count() { tests_total=$(( tests_total + 1 )); }

rc=0
"${bin}" --dir "${super}" >/dev/null 2>&1 || rc=$?
count
if [ "${rc}" -eq 2 ]; then
   pass "bump refused (exit 2) while MERGE_HEAD present"
else
   fail "bump NOT refused with MERGE_HEAD (exit ${rc}, want 2)"
fi

count
if [ "$(git -C "${super}" rev-parse HEAD)" = "${pre_tip}" ]; then
   pass "superproject HEAD unchanged (no commit made during merge)"
else
   fail "superproject HEAD moved despite in-progress merge"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "merge_in_progress_refused_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "merge_in_progress_refused_test: ${tests_total} pass, 0 fail, 0 skip"

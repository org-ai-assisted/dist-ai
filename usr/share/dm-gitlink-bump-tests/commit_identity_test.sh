#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression guard: dm-gitlink-bump must commit the parent gitlink bump under
## a CLEAN author/committer NAME ('claude'), never the session-id-suffixed name
## the harness exports via GIT_AUTHOR_NAME / GIT_COMMITTER_NAME. That export
## OVERRIDES git config, so a bump committed without a per-command override
## lands the session id in the public commit object -- and the tool commits
## internally, so a caller has no hook to fix it. The tool is the only place
## the leak can be closed.
##
## Drives the REAL dm-gitlink-bump against a throwaway superproject + submodule
## with a file:// 'published' remote-tracking tip, run under a deliberately
## dirty GIT_*_NAME, and asserts the recorded identity is clean AND the bump
## actually happened (so the identity check is not vacuous). No root, no
## network (the file:// remote is never fetched; the tracking ref is set
## directly).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Resolve dm-gitlink-bump under test. The runner exports DM_GITLINK_BUMP
## (the dist-ai checkout copy); fall back to a sibling, then the install.
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

## Testing the installed copy when nothing was wired tests a tree that may drift
## from the one under review -> SKIP rather than a confusing FAIL.
if [ -z "${DM_GITLINK_BUMP:-}" ] && [ "${bin}" = "/usr/bin/dm-gitlink-bump" ]; then
   printf '%s\n' "SKIP: no dm-gitlink-bump checkout wired (set DM_GITLINK_BUMP); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() { safe-rm -r -f -- "${test_root}"; }
trap cleanup EXIT

super="${test_root}/super"
sub="${super}/sub"

## Hermetic: ignore the host's global/system git config so the outcome does not
## depend on an ambient user.email / hooksPath, and set identity per repo below.
## The REAL dm-gitlink-bump commit runs without our -c flags, so without a
## resolvable local identity it would abort "Please tell me who you are" in a
## clean CI home and report a false regression.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

## git without the operator's hooks (this tests dm-gitlink-bump, not the
## operator's pre-commit guards); gpgsign off: no signing in a throwaway.
git_fx() { git -c core.hooksPath=/dev/null -c commit.gpgsign=false "$@"; }
## Persist an identity in the repo so both fixture commits and the real tool
## commit (which does not see our -c flags) resolve an author; the tool still
## pins the NAME to 'claude', which is what this suite asserts.
set_identity() { git -C "$1" config user.email fx@example.invalid && git -C "$1" config user.name fx; }

## Submodule: two commits on 'ai'; HEAD (c1) ahead of the pin (c0). A file://
## remote whose tracking ref equals HEAD makes the tool treat c1 as a published
## ai tip (it reads the tracking ref only -- never fetches).
mkdir -p -- "${sub}"
git_fx -C "${sub}" init -q -b ai
set_identity "${sub}"
git_fx -C "${sub}" commit -q --allow-empty -m c0
c0="$(git -C "${sub}" rev-parse HEAD)"
git_fx -C "${sub}" commit -q --allow-empty -m c1
c1="$(git -C "${sub}" rev-parse HEAD)"
git_fx -C "${sub}" remote add org-ai-assisted "file://${test_root}/subrem.git"
git_fx -C "${sub}" update-ref "refs/remotes/org-ai-assisted/ai" "${c1}"

## Superproject: a derivative-maker-shaped checkout (build-steps.d + help-steps
## must exist) on 'ai', pinning the submodule at c0 while its worktree is at c1.
mkdir -p -- "${super}/build-steps.d" "${super}/help-steps"
git_fx -C "${super}" init -q -b ai
set_identity "${super}"
cat > "${super}/.gitmodules" <<EOF
[submodule "sub"]
	path = sub
	url = file://${test_root}/subrem.git
EOF
## Stage the gitlink at c0 directly (no 'git add sub', which warns about an
## embedded repo), while the submodule worktree stays on 'ai' at c1 -- the
## published-ahead state the tool must bump.
git_fx -C "${super}" add .gitmodules
git_fx -C "${super}" update-index --add --cacheinfo "160000,${c0},sub"
git_fx -C "${super}" commit -q -m init

parent_before="$(git -C "${super}" rev-parse HEAD)"

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }
fail() { tests_failed=$(( tests_failed + 1 )); printf '%s\n' "FAIL  $1" >&2; }
count() { tests_total=$(( tests_total + 1 )); }

## Run the REAL bump under a session-id-leaking identity. The old code let this
## reach the commit object; the fix pins the NAME to 'claude' per-command.
leak='claude (devCANARY 00000000-0000-0000-0000-000000000000)'
rc=0
out="$( GIT_AUTHOR_NAME="${leak}" GIT_COMMITTER_NAME="${leak}" \
   "${bin}" --dir "${super}" 2>&1 )" || rc=$?

parent_after="$(git -C "${super}" rev-parse HEAD)"
new_pin="$(git -C "${super}" rev-parse --verify --quiet 'HEAD:sub' || true)"
an="$(git -C "${super}" log -1 --format='%an')"
cn="$(git -C "${super}" log -1 --format='%cn')"

## T1: the bump actually ran (so the identity assertions below are not vacuous).
count
if [ "${rc}" -eq 0 ] && [ "${parent_after}" != "${parent_before}" ] && [ "${new_pin}" = "${c1}" ]; then
   pass 'T1 bump committed and gitlink advanced c0 -> c1'
else
   fail "T1 bump did not happen (rc=${rc}, pin=${new_pin:0:12}, want=${c1:0:12}); out=[${out}]"
fi

## T2: the regression -- author NAME is clean, carries no session id.
count
if [ "${an}" = "claude" ]; then
   pass 'T2 author name is clean (claude)'
else
   fail "T2 author name leaked session id: [${an}]"
fi

## T3: committer NAME is clean too (the leak export hits both).
count
if [ "${cn}" = "claude" ]; then
   pass 'T3 committer name is clean (claude)'
else
   fail "T3 committer name leaked session id: [${cn}]"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "commit_identity_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "commit_identity_test: ${tests_total} pass, 0 fail, 0 skip"

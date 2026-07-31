#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pin the companion-branch resolution in developer-meta-files'
## .github/actions/resolve-dist-ai-ref/resolve-dist-ai-ref.sh.
##
## WHY IT EXISTS: dist-ai was pinned to 'master' for every consumer.
## dist-ai holds the tests; consumers hold the behaviour those tests
## assert. A change altering both could not be tested atomically -- the
## consumer PR ran against dist-ai@master with the OLD expectations
## (red), and pushing new expectations to dist-ai master first broke
## dist-ai's own CI against the consumer's unchanged master (also red).
## No green path between the two states.
##
## The resolver breaks that: a same-named branch in dist-ai wins, so both
## halves of a cross-repo change travel under one branch name.
##
## The fallback direction is what actually matters. Every failure mode --
## no companion, no branch name, an unreachable repo -- must land on
## 'master', because this runs in front of unrelated jobs and must never
## be the thing that fails them.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## The subject lives in the developer-meta-files checkout, wired by
## dist-ai-tests-all via --component developer-meta-files. Absent
## subject -> 77 (SKIP), the convention this suite already uses; the
## runner reports it rather than counting it green.
if [ -z "${DMF_REPO:-}" ]; then
   printf '%s\n' 'test_resolve_dist_ai_ref: DMF_REPO unset; skipping.' >&2
   exit 77
fi

resolver="${DMF_REPO}/.github/actions/resolve-dist-ai-ref/resolve-dist-ai-ref.sh"
if [ ! -x "${resolver}" ]; then
   printf '%s\n' "test_resolve_dist_ai_ref: '${resolver}' not found; skipping." >&2
   exit 77
fi

work=''
pass_count=0
fail_count=0

# shellcheck disable=SC2317  # invoked via the EXIT trap, not inline
cleanup() {
   ## '|| true': a failing cleanup must not replace the suite's verdict.
   [ -z "${work}" ] || safe-rm --recursive --force -- "${work}" || true
}
trap cleanup EXIT

work="$(mktemp --directory)"

## A LOCAL repository standing in for dist-ai, carrying one companion
## branch named 'ai'.
##
## Hermetic on purpose. An earlier version probed github.com for a branch
## that really existed -- and merging the PR which carried that branch
## auto-deleted it, so the test silently started measuring the fallback
## path and failed. An assertion whose subject can be deleted by
## unrelated work is not an assertion. This also takes the network out of
## every case.
companion_remote="${work}/fake-dist-ai"
git -c init.defaultBranch=master init --quiet --bare -- "${companion_remote}"
seed="${work}/seed"
git -c init.defaultBranch=master init --quiet -- "${seed}"
printf '%s\n' 'seed' > "${seed}/file"
git -C "${seed}" -c core.hooksPath=/dev/null add --all
git -C "${seed}" \
   -c core.hooksPath=/dev/null \
   -c user.name='test' -c user.email='test@example.com' \
   commit --quiet --message 'seed'
git -C "${seed}" -c core.hooksPath=/dev/null branch ai
git -C "${seed}" push --quiet -- "${companion_remote}" master ai

## Run the resolver and echo the ref it chose.
## Args: repo, sha, branch, dist-ai-repo, [remote-url].
resolve() {
   local out
   out="${work}/github_output"
   ## Truncate with printf, not ':' -- R-130 forbids ':' as a command.
   printf '%s' '' > "${out}"
   GITHUB_OUTPUT="${out}" \
   THIS_REPO="$1" THIS_SHA="$2" BRANCH_NAME="$3" DIST_AI_REPO="$4" \
   DIST_AI_REMOTE_URL="${5:-}" \
      "${resolver}" 2>/dev/null || true
   sed -n 's/^ref=//p' "${out}"
}

## Args: description, expected, then the four resolve() arguments.
check() {
   local desc want got
   desc="$1"
   want="$2"
   shift 2
   got="$(resolve "$@")"
   if [ "${got}" = "${want}" ]; then
      pass_count=$(( pass_count + 1 ))
      printf 'PASS: %s -> %s\n' "${desc}" "${got}"
   else
      fail_count=$(( fail_count + 1 ))
      printf 'FAIL: %s -> got %s, want %s\n' "${desc}" "${got:-<empty>}" "${want}" >&2
   fi
}

## dist-ai is the repo under test there, not a dependency.
check 'dist-ai resolves to its own commit' 'deadbeefcafe' \
   'org-ai-assisted/dist-ai' 'deadbeefcafe' 'ai' 'org-ai-assisted/dist-ai'

## The companion hit, against the local stand-in above. A branch that
## does NOT exist would make this indistinguishable from the fallback,
## which is the whole point of asserting it.
check 'an existing companion branch wins' 'ai' \
   'org-ai-assisted/some-consumer' 'sha1' 'ai' 'org-ai-assisted/dist-ai' "${companion_remote}"

## Every fallback path. All must reach 'master' rather than fail.
check 'no companion branch falls back' 'master' \
   'org-ai-assisted/some-consumer' 'sha1' 'no-such-branch-9f3a2b' 'org-ai-assisted/dist-ai' "${companion_remote}"
check 'an empty branch name falls back' 'master' \
   'org-ai-assisted/some-consumer' 'sha1' '' 'org-ai-assisted/dist-ai'
check 'the branch literally named master falls back' 'master' \
   'org-ai-assisted/some-consumer' 'sha1' 'master' 'org-ai-assisted/dist-ai'
check 'an unreachable remote falls back, does not fail' 'master' \
   'org-ai-assisted/some-consumer' 'sha1' 'ai' 'org-ai-assisted/dist-ai' "${work}/no-such-repo-9f3a2b"

printf '\n%s pass, %s fail, 0 skip\n' "${pass_count}" "${fail_count}"
[ "${fail_count}" -eq 0 ]

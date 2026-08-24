#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## DM_REPRO_SUBMODULE_OVERRIDES decides WHICH SOURCE a reproducibility build
## compiles. An override that is accepted and then not applied is the worst
## outcome the tool has: the build silently uses the parent gitlink instead,
## and the artifact comparison reports the difference as a reproducibility
## defect rather than as an unapplied override. That is what this pins.
##
## The override logic lives inside a heredoc that dm-local-repro-build sends to
## the sandbox, so it cannot be sourced. Rather than restate it here -- a copy
## would drift and then pass while the real thing broke -- the block is
## extracted from the shipped script and expanded by bash exactly as the real
## heredoc expands it. The test therefore fails if the escaping regresses, which
## is the likeliest way for this to break: one missing backslash and a
## remote-local variable is expanded away on the host into the empty string.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

failures=0

pass() {
   printf '%s\n' "PASS: $1"
}

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## Resolve the script under test the same way the sibling suites do.
if [ -n "${DIST_AI_REPO:-}" ]; then
   subject="${DIST_AI_REPO}/usr/bin/dm-local-repro-build"
else
   here="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
   subject="${here}/../../bin/dm-local-repro-build"
   if [ ! -f "${subject}" ]; then
      subject='/usr/bin/dm-local-repro-build'
   fi
fi

if [ ! -f "${subject}" ]; then
   printf '%s\n' 'FATAL: test_dm_local_repro_overrides: dm-local-repro-build not found.' >&2
   exit 1
fi

git_plain() {
   ## The fixture is not testing the operator's hooks or identity.
   git -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com "$@"
}

## Extract the override block verbatim from the shipped script.
block="$( sed -n '/^## Apply the submodule overrides/,/^## Remove UNTRACKED/p' -- "${subject}" | sed '$d' )"
if [ -z "${block}" ]; then
   fail 'could not extract the override block -- dm-local-repro-build changed shape and this test is now blind'
   printf '%s\n' '' "FAILED: ${failures} check(s) failed" >&2
   exit 1
fi
if ! grep --quiet -- 'repro_overrides' <<< "${block}"; then
   fail 'the extracted block does not mention repro_overrides -- extraction is matching the wrong region'
   printf '%s\n' '' "FAILED: ${failures} check(s) failed" >&2
   exit 1
fi

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$( mktemp --directory )"

## Render the block exactly as dm-local-repro-build's heredoc would: same
## unquoted-heredoc expansion, so host-side interpolation and the backslash
## escaping of remote-local variables are both exercised for real.
render() {
   local overrides="$1" renderer="${workdir}/render.sh"
   {
      printf '%s\n' "submodule_overrides='${overrides}'"
      printf '%s\n' 'cat <<REMOTE'
      printf '%s\n' "${block}"
      printf '%s\n' 'REMOTE'
   } > "${renderer}"
   bash "${renderer}"
}

## A submodule with TWO commits: the parent pins the first, the override asks
## for the second. Anything that fails to apply the override leaves the first
## checked out, which is exactly the silent-wrong-source case.
sub_repo="${workdir}/sub-origin"
mkdir --parents -- "${sub_repo}"
git_plain init --quiet -- "${sub_repo}"
printf '%s\n' 'v1' > "${sub_repo}/file"
git_plain -C "${sub_repo}" add file
git_plain -C "${sub_repo}" commit --quiet --message 'v1'
gitlink_sha="$( git_plain -C "${sub_repo}" rev-parse HEAD )"
printf '%s\n' 'v2' > "${sub_repo}/file"
git_plain -C "${sub_repo}" add file
git_plain -C "${sub_repo}" commit --quiet --message 'v2'
override_sha="$( git_plain -C "${sub_repo}" rev-parse HEAD )"

parent="${workdir}/parent"
mkdir --parents -- "${parent}"
git_plain init --quiet -- "${parent}"
git_plain -C "${parent}" -c protocol.file.allow=always submodule --quiet add -- "${sub_repo}" sub
git_plain -C "${parent}" -C "${parent}/sub" checkout --quiet "${gitlink_sha}"
git_plain -C "${parent}" add .
git_plain -C "${parent}" commit --quiet --message 'pin the submodule to v1'

reset_to_gitlink() {
   git_plain -C "${parent}/sub" checkout --quiet "${gitlink_sha}"
}

run_block() {
   local overrides="$1" script="${workdir}/rendered.sh"
   render "${overrides}" > "${script}"
   ( cd -- "${parent}" && sh "${script}" ) > "${workdir}/out.txt" 2>&1
}

## ---- 1: a valid override is actually applied ------------------------------
reset_to_gitlink
rc=0
run_block "sub=${override_sha}" || rc=$?
head_now="$( git_plain -C "${parent}/sub" rev-parse HEAD )"
if [ "${rc}" != '0' ]; then
   fail "a valid override should succeed, got rc=${rc}: $( cat -- "${workdir}/out.txt" )"
elif [ "${head_now}" != "${override_sha}" ]; then
   fail "the override was not applied: submodule is at ${head_now}, wanted ${override_sha}"
else
   pass 'a valid override checks the submodule out at the requested sha'
fi

## ---- 2: an unknown sha ABORTS rather than building the gitlink ------------
reset_to_gitlink
rc=0
run_block 'sub=0000000000000000000000000000000000000000' || rc=$?
head_now="$( git_plain -C "${parent}/sub" rev-parse HEAD )"
if [ "${rc}" = '0' ]; then
   fail 'an unresolvable override sha must abort, not fall back to the gitlink'
elif [ "${head_now}" != "${gitlink_sha}" ]; then
   fail 'an aborted override left the submodule somewhere unexpected'
else
   pass 'an unresolvable override sha aborts instead of silently building the gitlink'
fi

## ---- 3: a malformed entry aborts ------------------------------------------
reset_to_gitlink
rc=0
run_block 'sub-with-no-equals-sign' || rc=$?
if [ "${rc}" = '0' ]; then
   fail 'a malformed override entry must abort'
else
   pass 'a malformed override entry aborts'
fi

## ---- 4: a path that is not in the tree aborts -----------------------------
reset_to_gitlink
rc=0
run_block "no-such-sub=${override_sha}" || rc=$?
if [ "${rc}" = '0' ]; then
   fail 'an override naming a path that is not in the tree must abort'
else
   pass 'an override for an absent path aborts'
fi

## ---- 5: no overrides is a clean no-op -------------------------------------
reset_to_gitlink
rc=0
run_block '' || rc=$?
head_now="$( git_plain -C "${parent}/sub" rev-parse HEAD )"
if [ "${rc}" != '0' ]; then
   fail "an empty override list must be a no-op, got rc=${rc}: $( cat -- "${workdir}/out.txt" )"
elif [ "${head_now}" != "${gitlink_sha}" ]; then
   fail 'an empty override list changed the submodule checkout'
else
   pass 'an empty override list is a clean no-op'
fi

printf '%s\n' ''
if [ "${failures}" != '0' ]; then
   printf '%s\n' "FAILED: ${failures} check(s) failed" >&2
   exit 1
fi
printf '%s\n' 'test_dm_local_repro_overrides: OK -- override applied, unresolvable/malformed/absent-path aborted, empty is a no-op.'

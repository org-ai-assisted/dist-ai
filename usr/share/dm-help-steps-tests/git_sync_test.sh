#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-git-sync (usr/bin/dm-git-sync) -- the orchestrator that
## propagates committed 'ai' work in the one SOUND order.
##
## WHAT IT GUARDS -- the ORDERING and DISPATCH, which is the whole value:
##   - from a SUBMODULE it must PUBLISH the submodule BEFORE bumping the parent
##     (bumping first pins an unfetchable sha -- the exact trap dm-git-sync
##     replaces);
##   - from the PARENT it must bump -> push -> mirror-to-master, in that order;
##   - it must REFUSE (touch nothing) off 'ai', on master, when dirty, or outside
##     a derivative-maker checkout.
##
## Each sub-command (dm-push, dm-gitlink-bump, dm-cherry-pick-ai-nonlink) has its
## own suite; this test injects recording STUBS via the DM_GIT_SYNC_* overrides so
## the REAL dm-git-sync orchestration runs and its call sequence is asserted, with
## no real push/clone. A stale submodule pin looks like ' M sub' to git status, so
## the fixtures also prove the tool does NOT read that as "dirty".

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

dist_ai_bin="$(cd -- "${test_dir}/../../bin" && pwd)"
tool="${dist_ai_bin}/dm-git-sync"
if [ ! -x "${tool}" ]; then
   printf '%s\n' "FATAL: dm-git-sync not found/executable at '${tool}'." >&2
   exit 1
fi

export GIT_AUTHOR_NAME="test" GIT_AUTHOR_EMAIL="test@example.invalid"
export GIT_COMMITTER_NAME="test" GIT_COMMITTER_EMAIL="test@example.invalid"

workspace="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${workspace}"; }
trap cleanup EXIT

## Setup git ops run with hooks OFF (fixtures, not the tested behaviour).
gitq() { git -c core.hooksPath="${workspace}/nohooks" -c protocol.file.allow=always "$@"; }
mkdir --parents -- "${workspace}/nohooks"

## --- Recording stubs for the three orchestrated sub-commands -------------------
## Each appends one line to SYNC_LOG. PUSH records its cwd (dm-git-sync cd's into
## the repo before calling it); BUMP/CHERRY record their arguments.
SYNC_LOG="${workspace}/sync.log"
export SYNC_LOG
stubs="${workspace}/stubs"
mkdir --parents -- "${stubs}"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "PUSH %s\n" "$(pwd -P)" >> "${SYNC_LOG}"'
} > "${stubs}/push"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "BUMP %s\n" "$*" >> "${SYNC_LOG}"'
} > "${stubs}/bump"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "CHERRY %s\n" "$*" >> "${SYNC_LOG}"'
} > "${stubs}/cherry"
chmod +x -- "${stubs}/push" "${stubs}/bump" "${stubs}/cherry"

export DM_GIT_SYNC_PUSH="${stubs}/push"
export DM_GIT_SYNC_GITLINK_BUMP="${stubs}/bump"
export DM_GIT_SYNC_CHERRY="${stubs}/cherry"

## --- Fixture: bare fork + submodule + derivative-maker-shaped superproject -----
fork="${workspace}/fork.git"
sub_src="${workspace}/sub-src"
super="${workspace}/super"

gitq init --quiet --bare -- "${fork}"
gitq init --quiet -- "${sub_src}"
gitq -C "${sub_src}" checkout --quiet -b ai
printf 'v1\n' > "${sub_src}/file"
gitq -C "${sub_src}" add file
gitq -C "${sub_src}" commit --quiet -m "sub v1"
gitq -C "${sub_src}" remote add fork "file://${fork}"
gitq -C "${sub_src}" push --quiet fork ai

gitq init --quiet -- "${super}"
gitq -C "${super}" checkout --quiet -b ai
mkdir --parents -- "${super}/build-steps.d" "${super}/help-steps"
printf 'x\n' > "${super}/build-steps.d/keep"
printf 'x\n' > "${super}/help-steps/keep"
gitq -C "${super}" add build-steps.d help-steps
gitq -C "${super}" commit --quiet -m "super base"
gitq -C "${super}" -c protocol.file.allow=always submodule --quiet add -b ai "file://${fork}" sub
gitq -C "${super}" commit --quiet -m "add sub"
## Submodule on 'ai', clean.
gitq -C "${super}/sub" checkout --quiet ai

## Advance the submodule so the parent pin is stale ( M sub in status): proves
## is_clean does NOT read that as dirty.
printf 'v2\n' > "${super}/sub/file"
gitq -C "${super}/sub" add file
gitq -C "${super}/sub" commit --quiet -m "sub v2"

log_lines() { cat -- "${SYNC_LOG}" 2>/dev/null || true; }
reset_log() { printf '' > "${SYNC_LOG}"; }

## --- Case 1: PARENT sync -> BUMP, PUSH, CHERRY in that order --------------------
reset_log
if "${tool}" --dir "${super}" >/dev/null 2>&1; then
   pass "parent sync exits 0"
else
   fail "parent sync exited non-zero: $?"
fi
got="$(log_lines)"
expected="$(printf 'BUMP --dir %s\nPUSH %s\nCHERRY %s' "${super}" "${super}" "${super}")"
if [ "${got}" = "${expected}" ]; then
   pass "parent sync order is bump -> push -> cherry (stale pin not read as dirty)"
else
   fail "parent sync order wrong; got:<<<${got}>>> expected:<<<${expected}>>>"
fi

## --- Case 2: SUBMODULE sync -> PUBLISH submodule FIRST, then parent chain -------
reset_log
if "${tool}" --dir "${super}/sub" >/dev/null 2>&1; then
   pass "submodule sync exits 0"
else
   fail "submodule sync exited non-zero: $?"
fi
got="$(log_lines)"
sub_real="$(cd -- "${super}/sub" && pwd -P)"
expected="$(printf 'PUSH %s\nBUMP --dir %s\nPUSH %s\nCHERRY %s' "${sub_real}" "${super}" "${super}" "${super}")"
if [ "${got}" = "${expected}" ]; then
   pass "submodule sync PUBLISHES the submodule before bumping the parent pin"
else
   fail "submodule sync order wrong; got:<<<${got}>>> expected:<<<${expected}>>>"
fi
## Explicit: the first recorded action is the submodule push (the soundness point).
if [ "$(log_lines | head -1)" = "PUSH ${sub_real}" ]; then
   pass "the FIRST action is the submodule publish (bump can never precede it)"
else
   fail "first action was not the submodule publish: '$(log_lines | head -1)'"
fi

## --- Case 3: refusals must touch NOTHING (empty log, exit 2) --------------------
refuse_touches_nothing() {
   local desc="$1" ; shift
   reset_log
   ## Capture the tool's OWN exit: '$?' after a false 'if...fi' with no else is 0,
   ## not the condition's status, so read it via '|| rc=$?' instead.
   local rc=0
   "${tool}" "$@" >/dev/null 2>&1 || rc=$?
   if [ "${rc}" -ne 2 ]; then
      fail "${desc}: expected exit 2, got ${rc}"
      return
   fi
   if [ -n "$(log_lines)" ]; then
      fail "${desc}: refusal still invoked a sub-command: <<<$(log_lines)>>>"
      return
   fi
   pass "${desc}: refused (exit 2) and touched nothing"
}

## 3a. detached submodule HEAD.
gitq -C "${super}/sub" checkout --quiet --detach HEAD
refuse_touches_nothing "detached HEAD" --dir "${super}/sub"
gitq -C "${super}/sub" checkout --quiet ai

## 3b. parent on master.
gitq -C "${super}" checkout --quiet -b master
refuse_touches_nothing "superproject on master" --dir "${super}"
gitq -C "${super}" checkout --quiet ai

## 3c. dirty parent (a real, non-submodule file change).
printf 'dirty\n' >> "${super}/build-steps.d/keep"
refuse_touches_nothing "dirty working tree" --dir "${super}"
gitq -C "${super}" checkout --quiet -- build-steps.d/keep

## 3d. a plain git repo: neither a derivative-maker checkout nor its submodule.
plain="${workspace}/plain"
gitq init --quiet -- "${plain}"
gitq -C "${plain}" checkout --quiet -b ai
printf 'x\n' > "${plain}/f"
gitq -C "${plain}" add f
gitq -C "${plain}" commit --quiet -m base
refuse_touches_nothing "non-derivative-maker repo" --dir "${plain}"

## --- Case 4: --dry-run bumps in dry mode, cherry-picks --no-push, NEVER pushes --
reset_log
if "${tool}" --dir "${super}" --dry-run >/dev/null 2>&1; then
   pass "dry-run exits 0"
else
   fail "dry-run exited non-zero: $?"
fi
got="$(log_lines)"
if grep --quiet -- '^BUMP --dir .* --dry-run$' <<< "${got}"; then
   pass "dry-run calls dm-gitlink-bump with --dry-run"
else
   fail "dry-run did not pass --dry-run to the bump; got:<<<${got}>>>"
fi
if grep --quiet -- '^CHERRY --no-push ' <<< "${got}"; then
   pass "dry-run calls the cherry-pick with --no-push"
else
   fail "dry-run did not pass --no-push to the cherry-pick; got:<<<${got}>>>"
fi
if grep --quiet -- '^PUSH ' <<< "${got}"; then
   fail "dry-run pushed (must never mutate remotes); got:<<<${got}>>>"
else
   pass "dry-run performed no push"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-git-sync publishes-before-bumping, dispatches parent/submodule, refuses safely, dry-runs clean."

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-submodule-ai-sync (usr/bin/dm-submodule-ai-sync) -- the
## dm-tidy step-1/2 helper that fetches each submodule's fork remote and brings
## its local 'ai' to the published fork tip.
##
## WHAT IT GUARDS -- the happy-path/STOP boundary, which is the whole value:
##   AUTO (must mutate): behind -> fast-forward; detached -> re-attach then FF.
##   STOP (must NOT mutate, exit 1, surface a reason): ahead, diverged, dirty,
##        no fork 'ai' tip, no fork remote.
##   And: it must NEVER run 'git submodule update' (the mess it undoes).
##
## Drives the REAL tool against local file-remote fixtures (no network). A 'git'
## shim on PATH records any 'submodule update' call so the never-detach invariant
## is asserted, not assumed.

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
tool="${dist_ai_bin}/dm-submodule-ai-sync"
if [ ! -x "${tool}" ]; then
   printf '%s\n' "FATAL: dm-submodule-ai-sync not found/executable at '${tool}'." >&2
   exit 1
fi

export GIT_AUTHOR_NAME="test" GIT_AUTHOR_EMAIL="test@example.invalid"
export GIT_COMMITTER_NAME="test" GIT_COMMITTER_EMAIL="test@example.invalid"

workspace="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${workspace}"; }
trap cleanup EXIT

## Setup git ops run with hooks OFF and file transport allowed (fixtures, not the
## tested behaviour).
gitq() { git -c core.hooksPath="${workspace}/nohooks" -c protocol.file.allow=always "$@"; }
mkdir --parents -- "${workspace}/nohooks"

## --- 'git' shim: forward to real git, record any 'submodule update' -------------
## The tool must never detach submodules via 'git submodule update'. Fixture
## setup uses 'submodule add' only, so an empty log across the whole test proves
## the invariant.
REAL_GIT="$(type -P git)"
export REAL_GIT
SUBUPDATE_LOG="${workspace}/subupdate.log"
export SUBUPDATE_LOG
printf '' > "${SUBUPDATE_LOG}"
shimbin="${workspace}/shimbin"
mkdir --parents -- "${shimbin}"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'prev=""'
   printf '%s\n' 'for a in "$@"; do'
   printf '%s\n' '   if [ "${prev}" = "submodule" ] && [ "${a}" = "update" ]; then'
   printf '%s\n' '      printf "SUBMODULE_UPDATE %s\n" "$*" >> "${SUBUPDATE_LOG}"'
   printf '%s\n' '   fi'
   printf '%s\n' '   prev="${a}"'
   printf '%s\n' 'done'
   printf '%s\n' 'exec "${REAL_GIT}" "$@"'
} > "${shimbin}/git"
chmod +x -- "${shimbin}/git"
export PATH="${shimbin}:${PATH}"

## --- Fixture helpers ------------------------------------------------------------
## A bare "fork" (the org-ai-assisted remote) with an 'ai' branch, plus a driver
## clone that advances the fork independently of any submodule.
new_fork() {
   local fork="$1" driver="$2"
   gitq init --quiet --bare -- "${fork}"
   gitq init --quiet -- "${driver}"
   gitq -C "${driver}" checkout --quiet -b ai
   printf 'c1\n' > "${driver}/f"
   gitq -C "${driver}" add f
   gitq -C "${driver}" commit --quiet -m c1
   gitq -C "${driver}" remote add fork "file://${fork}"
   gitq -C "${driver}" push --quiet fork ai
}

## Add a commit to the fork's 'ai' tip via its driver clone.
advance_fork() {
   local driver="$1" fork="$2"
   printf 'c2\n' > "${driver}/f"
   gitq -C "${driver}" add f
   gitq -C "${driver}" commit --quiet -m c2
   gitq -C "${driver}" push --quiet fork ai
}

## Create a dm-shaped superproject on 'ai'.
new_super() {
   local super="$1"
   gitq init --quiet -- "${super}"
   gitq -C "${super}" checkout --quiet -b ai
   mkdir --parents -- "${super}/build-steps.d" "${super}/help-steps"
   printf 'x\n' > "${super}/build-steps.d/keep"
   printf 'x\n' > "${super}/help-steps/keep"
   gitq -C "${super}" add build-steps.d help-steps
   gitq -C "${super}" commit --quiet -m "super base"
}

## Add a submodule from 'fork' at path 'name', remote renamed to org-ai-assisted,
## checked out on 'ai'.
add_sub() {
   local super="$1" fork="$2" name="$3"
   gitq -C "${super}" submodule --quiet add -b ai "file://${fork}" "${name}"
   gitq -C "${super}/${name}" remote rename origin org-ai-assisted
   gitq -C "${super}/${name}" config protocol.file.allow always
   ## Fixture commits are unsigned; the operator's global merge.verifySignatures
   ## would reject the fast-forward. Real fork tips are bot-signed. Keep the
   ## fixture hermetic (repo-local, not a production concern).
   gitq -C "${super}/${name}" config merge.verifySignatures false
   gitq -C "${super}/${name}" checkout --quiet ai
}

head_of() { gitq -C "$1" rev-parse HEAD; }
branch_of() { gitq -C "$1" symbolic-ref --quiet HEAD 2>/dev/null || printf 'DETACHED\n'; }

## =============================================================================
## Superproject A: AUTO cases (behind, current, detached) -> must exit 0.
## =============================================================================
superA="${workspace}/superA"
new_super "${superA}"

## behind: local ai = c1, fork advanced to c2.
new_fork "${workspace}/fork-behind.git" "${workspace}/drv-behind"
add_sub "${superA}" "${workspace}/fork-behind.git" behind
advance_fork "${workspace}/drv-behind" "${workspace}/fork-behind.git"
behind_tip="$(gitq -C "${workspace}/drv-behind" rev-parse ai)"

## current: local ai = c1 = fork tip.
new_fork "${workspace}/fork-current.git" "${workspace}/drv-current"
add_sub "${superA}" "${workspace}/fork-current.git" current
current_tip="$(gitq -C "${workspace}/drv-current" rev-parse ai)"

## detached: local ai = c1, fork advanced to c2, HEAD detached at c1.
new_fork "${workspace}/fork-detached.git" "${workspace}/drv-detached"
add_sub "${superA}" "${workspace}/fork-detached.git" detached
advance_fork "${workspace}/drv-detached" "${workspace}/fork-detached.git"
detached_tip="$(gitq -C "${workspace}/drv-detached" rev-parse ai)"
gitq -C "${superA}/detached" checkout --quiet --detach ai

## --- A / dry-run FIRST: classify, report, but mutate nothing --------------------
rc=0
dry_out="$("${tool}" --dir "${superA}" --dry-run 2>&1)" || rc=$?
if [ "${rc}" -eq 0 ]; then
   pass "dry-run (all AUTO) exits 0"
else
   fail "dry-run exited ${rc}; output:<<<${dry_out}>>>"
fi
if [ "$(head_of "${superA}/behind")" != "${behind_tip}" ]; then
   pass "dry-run did NOT fast-forward the behind submodule"
else
   fail "dry-run fast-forwarded the behind submodule (must not mutate)"
fi
if [ "$(branch_of "${superA}/detached")" = "DETACHED" ]; then
   pass "dry-run did NOT re-attach the detached submodule"
else
   fail "dry-run re-attached the detached submodule (must not mutate)"
fi
require_result "${dry_out}" "would fast-forward" "dry-run reports a planned fast-forward"
require_result "${dry_out}" "would re-attach"    "dry-run reports a planned re-attach"

## --- A / real run: behind FF'd, detached re-attached+FF'd, current untouched ----
rc=0
real_out="$("${tool}" --dir "${superA}" 2>&1)" || rc=$?
if [ "${rc}" -eq 0 ]; then
   pass "real run (all AUTO) exits 0"
else
   fail "real run exited ${rc}; output:<<<${real_out}>>>"
fi
if [ "$(head_of "${superA}/behind")" = "${behind_tip}" ] && [ "$(branch_of "${superA}/behind")" = "refs/heads/ai" ]; then
   pass "behind submodule fast-forwarded to the fork tip, on ai"
else
   fail "behind submodule not at fork tip / not on ai (head=$(head_of "${superA}/behind") branch=$(branch_of "${superA}/behind"))"
fi
if [ "$(head_of "${superA}/current")" = "${current_tip}" ] && [ "$(branch_of "${superA}/current")" = "refs/heads/ai" ]; then
   pass "current submodule left at the tip, on ai"
else
   fail "current submodule changed unexpectedly (head=$(head_of "${superA}/current"))"
fi
if [ "$(head_of "${superA}/detached")" = "${detached_tip}" ] && [ "$(branch_of "${superA}/detached")" = "refs/heads/ai" ]; then
   pass "detached submodule re-attached to ai and fast-forwarded to the fork tip"
else
   fail "detached submodule not re-attached/FF'd (head=$(head_of "${superA}/detached") branch=$(branch_of "${superA}/detached"))"
fi

## =============================================================================
## Superproject B: STOP cases -> must exit 1, mutate nothing, surface reasons.
## =============================================================================
superB="${workspace}/superB"
new_super "${superB}"

## ahead: local ai committed past the fork tip.
new_fork "${workspace}/fork-ahead.git" "${workspace}/drv-ahead"
add_sub "${superB}" "${workspace}/fork-ahead.git" ahead
printf 'local-ahead\n' > "${superB}/ahead/f"
gitq -C "${superB}/ahead" add f
gitq -C "${superB}/ahead" commit --quiet -m "local ahead"
ahead_head="$(head_of "${superB}/ahead")"

## diverged: fork advanced to c2 AND local ai committed a different c2.
new_fork "${workspace}/fork-diverged.git" "${workspace}/drv-diverged"
add_sub "${superB}" "${workspace}/fork-diverged.git" diverged
advance_fork "${workspace}/drv-diverged" "${workspace}/fork-diverged.git"
printf 'local-diverged\n' > "${superB}/diverged/f"
gitq -C "${superB}/diverged" add f
gitq -C "${superB}/diverged" commit --quiet -m "local diverged"
diverged_head="$(head_of "${superB}/diverged")"

## dirty: uncommitted tracked change.
new_fork "${workspace}/fork-dirty.git" "${workspace}/drv-dirty"
add_sub "${superB}" "${workspace}/fork-dirty.git" dirty
dirty_head="$(head_of "${superB}/dirty")"
printf 'uncommitted\n' > "${superB}/dirty/f"

## nofork-ai: fork has master but no 'ai'.
gitq init --quiet --bare -- "${workspace}/fork-noai.git"
gitq init --quiet -- "${workspace}/drv-noai"
gitq -C "${workspace}/drv-noai" checkout --quiet -b master
printf 'm\n' > "${workspace}/drv-noai/f"
gitq -C "${workspace}/drv-noai" add f
gitq -C "${workspace}/drv-noai" commit --quiet -m m
gitq -C "${workspace}/drv-noai" remote add fork "file://${workspace}/fork-noai.git"
gitq -C "${workspace}/drv-noai" push --quiet fork master
gitq -C "${superB}" submodule --quiet add "file://${workspace}/fork-noai.git" noforkai
gitq -C "${superB}/noforkai" remote rename origin org-ai-assisted
gitq -C "${superB}/noforkai" config protocol.file.allow always
gitq -C "${superB}/noforkai" checkout --quiet -b ai
noforkai_head="$(head_of "${superB}/noforkai")"

## noremote: submodule without the org-ai-assisted remote at all.
new_fork "${workspace}/fork-noremote.git" "${workspace}/drv-noremote"
gitq -C "${superB}" submodule --quiet add -b ai "file://${workspace}/fork-noremote.git" noremote
## leave the remote named 'origin' (no org-ai-assisted)
gitq -C "${superB}/noremote" config protocol.file.allow always
gitq -C "${superB}/noremote" checkout --quiet ai
noremote_head="$(head_of "${superB}/noremote")"

rc=0
stop_out="$("${tool}" --dir "${superB}" 2>&1)" || rc=$?
if [ "${rc}" -eq 1 ]; then
   pass "STOP run exits 1"
else
   fail "STOP run exited ${rc} (expected 1); output:<<<${stop_out}>>>"
fi
## Nothing mutated.
if [ "$(head_of "${superB}/ahead")" = "${ahead_head}" ]; then
   pass "ahead submodule left untouched"
else
   fail "ahead submodule was mutated"
fi
if [ "$(head_of "${superB}/diverged")" = "${diverged_head}" ]; then
   pass "diverged submodule left untouched"
else
   fail "diverged submodule was mutated"
fi
if [ "$(head_of "${superB}/dirty")" = "${dirty_head}" ] && [ "$(cat -- "${superB}/dirty/f")" = "uncommitted" ]; then
   pass "dirty submodule left untouched (uncommitted change intact)"
else
   fail "dirty submodule was mutated / lost its uncommitted change"
fi
if [ "$(head_of "${superB}/noforkai")" = "${noforkai_head}" ]; then
   pass "nofork-ai submodule left untouched"
else
   fail "nofork-ai submodule was mutated"
fi
if [ "$(head_of "${superB}/noremote")" = "${noremote_head}" ]; then
   pass "noremote submodule left untouched"
else
   fail "noremote submodule was mutated"
fi
## Reasons surfaced.
require_result "${stop_out}" "ahead of / diverged" "STOP surfaces the ahead/diverged reason"
require_result "${stop_out}" "dirty working tree"  "STOP surfaces the dirty reason"
require_result "${stop_out}" "never published"     "STOP surfaces the unpublished-ai reason"
require_result "${stop_out}" "no 'org-ai-assisted' remote" "STOP surfaces the missing-remote reason"

## =============================================================================
## Invariant: no 'git submodule update' ever ran.
## =============================================================================
if [ ! -s "${SUBUPDATE_LOG}" ]; then
   pass "the tool never ran 'git submodule update'"
else
   fail "the tool ran 'git submodule update': <<<$(cat -- "${SUBUPDATE_LOG}")>>>"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-submodule-ai-sync fast-forwards/re-attaches happy-path, STOPs on ahead/diverged/dirty/unpublished/no-remote, never detaches via submodule update."

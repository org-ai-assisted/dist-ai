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
cat > "${shimbin}/git" <<'SHIM'
#!/bin/bash
prev=""
for a in "$@"; do
   if [ "${prev}" = "submodule" ] && [ "${a}" = "update" ]; then
      printf 'SUBMODULE_UPDATE %s\n' "$*" >> "${SUBUPDATE_LOG}"
   fi
   prev="${a}"
done
exec "${REAL_GIT}" "$@"
SHIM
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
## Superproject C: mutation-failure and containment STOPs must not crash the loop
## or lose work; a healthy submodule ordered AFTER them is still processed.
## =============================================================================
superC="${workspace}/superC"
new_super "${superC}"

## aa_collide: behind, but an untracked file collides with a file the incoming
## fork commit adds -> 'merge --ff-only' fails; must STOP (guarded), not crash.
gitq init --quiet --bare -- "${workspace}/fork-collide.git"
gitq init --quiet -- "${workspace}/drv-collide"
gitq -C "${workspace}/drv-collide" checkout --quiet -b ai
printf 'c1\n' > "${workspace}/drv-collide/f"
gitq -C "${workspace}/drv-collide" add f
gitq -C "${workspace}/drv-collide" commit --quiet -m c1
gitq -C "${workspace}/drv-collide" remote add fork "file://${workspace}/fork-collide.git"
gitq -C "${workspace}/drv-collide" push --quiet fork ai
add_sub "${superC}" "${workspace}/fork-collide.git" aa_collide
## fork adds a NEW tracked file 'newfile'.
printf 'from-fork\n' > "${workspace}/drv-collide/newfile"
gitq -C "${workspace}/drv-collide" add newfile
gitq -C "${workspace}/drv-collide" commit --quiet -m "add newfile"
gitq -C "${workspace}/drv-collide" push --quiet fork ai
## untracked collision in the submodule working tree.
printf 'attacker\n' > "${superC}/aa_collide/newfile"
collide_head="$(head_of "${superC}/aa_collide")"

## detuniq: local ai == fork tip, but HEAD is detached at a UNIQUE extra commit.
## Re-attaching would orphan it -> must STOP, not silently drop the commit.
new_fork "${workspace}/fork-detuniq.git" "${workspace}/drv-detuniq"
add_sub "${superC}" "${workspace}/fork-detuniq.git" detuniq
gitq -C "${superC}/detuniq" checkout --quiet --detach ai
printf 'unique\n' > "${superC}/detuniq/g"
gitq -C "${superC}/detuniq" add g
gitq -C "${superC}/detuniq" commit --quiet -m "unique detached commit"
detuniq_head="$(head_of "${superC}/detuniq")"

## evil: a '.gitmodules' path that escapes the superproject -> must STOP.
gitq -C "${superC}" config --file "${superC}/.gitmodules" submodule.evil.path ../outside
gitq -C "${superC}" config --file "${superC}/.gitmodules" submodule.evil.url "file:///unused"

## evilself: a '.gitmodules' path that resolves to the superproject ITSELF
## (path='.') -> must STOP, never fast-forward the superproject.
gitq -C "${superC}" config --file "${superC}/.gitmodules" submodule.evilself.path .
gitq -C "${superC}" config --file "${superC}/.gitmodules" submodule.evilself.url "file:///unused"
superC_head_before="$(gitq -C "${superC}" rev-parse HEAD)"

## zz_healthy: behind + clean, ordered AFTER the failing ones -> must still FF.
new_fork "${workspace}/fork-healthy.git" "${workspace}/drv-healthy"
add_sub "${superC}" "${workspace}/fork-healthy.git" zz_healthy
advance_fork "${workspace}/drv-healthy" "${workspace}/fork-healthy.git"
healthy_tip="$(gitq -C "${workspace}/drv-healthy" rev-parse ai)"

rc=0
c_out="$("${tool}" --dir "${superC}" 2>&1)" || rc=$?
if [ "${rc}" -eq 1 ]; then
   pass "mixed STOP+healthy run exits 1"
else
   fail "mixed run exited ${rc} (expected 1); output:<<<${c_out}>>>"
fi
if [ "$(head_of "${superC}/aa_collide")" = "${collide_head}" ] && [ "$(cat -- "${superC}/aa_collide/newfile")" = "attacker" ]; then
   pass "untracked-collision submodule STOPped without mutation (no errexit crash)"
else
   fail "untracked-collision submodule was mutated / lost its untracked file"
fi
if [ "$(head_of "${superC}/detuniq")" = "${detuniq_head}" ]; then
   pass "detached-at-unique-commit submodule left untouched (commit not orphaned)"
else
   fail "detached-at-unique-commit submodule was mutated (orphaned the unique commit)"
fi
if [ "$(head_of "${superC}/zz_healthy")" = "${healthy_tip}" ]; then
   pass "healthy submodule after a STOP is STILL fast-forwarded (loop not abandoned)"
else
   fail "healthy submodule after a STOP was skipped (loop abandoned mid-run)"
fi
require_result "${c_out}" "untracked-file collision" "STOP surfaces the fast-forward-failure reason"
require_result "${c_out}" "not contained in"          "STOP surfaces the detached-not-contained reason"
require_result "${c_out}" "resolves outside the superproject" "STOP surfaces the out-of-tree-path reason"
require_result "${c_out}" "resolves to the superproject itself" "STOP surfaces the path-is-superproject reason"
if [ "$(gitq -C "${superC}" rev-parse HEAD)" = "${superC_head_before}" ]; then
   pass "a 'path=.' entry does NOT fast-forward the superproject itself"
else
   fail "a 'path=.' entry fast-forwarded the superproject (containment bypass)"
fi

## =============================================================================
## Superproject D: an inherited GIT_DIR/GIT_WORK_TREE must NOT redirect the tool
## at the superproject; the submodule (not the super) is fast-forwarded.
## =============================================================================
superD="${workspace}/superD"
new_super "${superD}"
new_fork "${workspace}/fork-gd.git" "${workspace}/drv-gd"
add_sub "${superD}" "${workspace}/fork-gd.git" gd
advance_fork "${workspace}/drv-gd" "${workspace}/fork-gd.git"
gd_tip="$(gitq -C "${workspace}/drv-gd" rev-parse ai)"
superD_head_before="$(gitq -C "${superD}" rev-parse HEAD)"

rc=0
GIT_DIR="${superD}/.git" GIT_WORK_TREE="${superD}" "${tool}" --dir "${superD}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 0 ]; then
   pass "run with inherited GIT_DIR/GIT_WORK_TREE exits 0"
else
   fail "run with inherited GIT_DIR exited ${rc}"
fi
if [ "$(head_of "${superD}/gd")" = "${gd_tip}" ]; then
   pass "with GIT_DIR set, the SUBMODULE is fast-forwarded (not the superproject)"
else
   fail "with GIT_DIR set, the submodule was not fast-forwarded (redirected at super)"
fi
if [ "$(gitq -C "${superD}" rev-parse HEAD)" = "${superD_head_before}" ]; then
   pass "with GIT_DIR set, the superproject HEAD is untouched"
else
   fail "with GIT_DIR set, the superproject was mutated"
fi

## =============================================================================
## Superproject E: a detached HEAD that is an ancestor of the fork tip but
## DISTINCT from a behind local 'ai', with an untracked-file collision on the FF.
## The re-attach must ROLL BACK on the failed FF -> a STOP leaves HEAD as found.
## =============================================================================
superE="${workspace}/superE"
new_super "${superE}"
gitq init --quiet --bare -- "${workspace}/fork-detcol.git"
gitq init --quiet -- "${workspace}/drv-detcol"
gitq -C "${workspace}/drv-detcol" checkout --quiet -b ai
printf 'c0\n' > "${workspace}/drv-detcol/f"
gitq -C "${workspace}/drv-detcol" add f
gitq -C "${workspace}/drv-detcol" commit --quiet -m c0
gitq -C "${workspace}/drv-detcol" remote add fork "file://${workspace}/fork-detcol.git"
gitq -C "${workspace}/drv-detcol" push --quiet fork ai
add_sub "${superE}" "${workspace}/fork-detcol.git" detcol
## fork advances: c1 (adds g), then c2 (adds newfile).
printf 'g\n' > "${workspace}/drv-detcol/g"
gitq -C "${workspace}/drv-detcol" add g
gitq -C "${workspace}/drv-detcol" commit --quiet -m c1
detcol_c1="$(gitq -C "${workspace}/drv-detcol" rev-parse ai)"
gitq -C "${workspace}/drv-detcol" push --quiet fork ai
printf 'from-fork\n' > "${workspace}/drv-detcol/newfile"
gitq -C "${workspace}/drv-detcol" add newfile
gitq -C "${workspace}/drv-detcol" commit --quiet -m c2
gitq -C "${workspace}/drv-detcol" push --quiet fork ai
## sub: fetch c1/c2 objects, detach at c1 (distinct from local ai=c0), untracked collision.
gitq -C "${superE}/detcol" fetch --quiet org-ai-assisted
gitq -C "${superE}/detcol" checkout --quiet --detach "${detcol_c1}"
printf 'attacker\n' > "${superE}/detcol/newfile"

rc=0
e_out="$("${tool}" --dir "${superE}" 2>&1)" || rc=$?
if [ "${rc}" -eq 1 ]; then
   pass "detached-behind + FF-collision run exits 1"
else
   fail "detached-behind + FF-collision run exited ${rc}; output:<<<${e_out}>>>"
fi
if [ "$(gitq -C "${superE}/detcol" rev-parse HEAD)" = "${detcol_c1}" ] && [ "$(branch_of "${superE}/detcol")" = "DETACHED" ]; then
   pass "failed FF after re-attach ROLLS BACK to the original detached HEAD (no mutation on STOP)"
else
   fail "failed FF left the submodule moved (HEAD=$(gitq -C "${superE}/detcol" rev-parse HEAD) branch=$(branch_of "${superE}/detcol"))"
fi
if [ "$(cat -- "${superE}/detcol/newfile")" = "attacker" ]; then
   pass "the untracked file is intact after the rolled-back STOP"
else
   fail "the untracked file was clobbered on the rolled-back STOP"
fi

## =============================================================================
## Superproject F: an inherited GIT_OBJECT_DIRECTORY must not send fetched objects
## to the wrong store; the fast-forwarded submodule stays self-consistent.
## =============================================================================
superF="${workspace}/superF"
new_super "${superF}"
new_fork "${workspace}/fork-god.git" "${workspace}/drv-god"
add_sub "${superF}" "${workspace}/fork-god.git" god
advance_fork "${workspace}/drv-god" "${workspace}/fork-god.git"
god_tip="$(gitq -C "${workspace}/drv-god" rev-parse ai)"
rc=0
GIT_OBJECT_DIRECTORY="${superF}/.git/objects" "${tool}" --dir "${superF}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 0 ]; then
   pass "run with inherited GIT_OBJECT_DIRECTORY exits 0"
else
   fail "run with inherited GIT_OBJECT_DIRECTORY exited ${rc}"
fi
if [ "$(head_of "${superF}/god")" = "${god_tip}" ] && gitq -C "${superF}/god" cat-file -e HEAD 2>/dev/null; then
   pass "with GIT_OBJECT_DIRECTORY set, the submodule FF'd and its HEAD object is in its OWN store"
else
   fail "with GIT_OBJECT_DIRECTORY set, the submodule HEAD object is missing (objects went to the wrong store)"
fi

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

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-tidy (usr/bin/dm-tidy) -- the OUTER orchestrator that runs
## the whole dm-tidy happy path (submodule 'ai' sync -> remaster+merge -> pin/mirror/
## push -> fsck) as one command and aggregates the phase verdicts into ONE exit code.
##
## WHAT IT GUARDS -- the aggregation + ordering + abort policy, which is the whole
## value (each phase's real logic has its OWN suite):
##   - the four phases run in the fixed order sync -> remaster -> parent-sync -> fsck;
##   - a per-repo BLOCKED verdict (sync exit 1, remaster exit 3) does NOT stop the
##     sweep -- later phases still run -- and dm-tidy exits 3 (NONZERO, so a caller
##     cannot mistake a needs-a-human run for a clean one: the CANARY the user asked
##     for; a naive orchestrator that returns the last phase's status, or always 0,
##     fails these);
##   - a STRUCTURAL failure (a phase exit that is neither ok nor the known blocked
##     code, or a failed parent-sync) ABORTS the remaining MUTATING phases -- never
##     push on a half-done tree -- and exits 1;
##   - fsck is read-only and runs even after an abort; a corrupt store makes exit 1;
##   - --dry-run drives each phase in its own dry mode (remaster --dry-run, NOT
##     --apply) and mutates nothing;
##   - it REFUSES (exit 2, touching nothing) off 'ai' or outside a derivative-maker
##     checkout, and resolves a submodule arg up to its parent superproject.
##
## Recording STUBS injected via the DM_TIDY_* overrides run the REAL dm-tidy
## orchestration with no real git mutation; each stub records its call + args and
## exits with a per-phase code read from the environment (<PHASE>_RC).

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
## DM_TIDY_BIN is a test-only seam so the canary can point the suite at a
## deliberately-broken dm-tidy and confirm these assertions FAIL on it.
tool="${DM_TIDY_BIN:-${dist_ai_bin}/dm-tidy}"
if [ ! -x "${tool}" ]; then
   printf '%s\n' "FATAL: dm-tidy not found/executable at '${tool}'." >&2
   exit 1
fi

export GIT_AUTHOR_NAME="test" GIT_AUTHOR_EMAIL="test@example.invalid"
export GIT_COMMITTER_NAME="test" GIT_COMMITTER_EMAIL="test@example.invalid"

workspace="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${workspace}"; }
trap cleanup EXIT

## dm-tidy's phase 0 runs its DESTRUCTIVE remote ensure ONLY on the tree the ensure
## helper hardcodes, REMOTES_TARGET_TREE="${HOME}/derivative-maker". Point HOME into
## the throwaway workspace so that tree is a FIXTURE, never the operator's real
## ~/derivative-maker. HOME is a subdir (not the workspace root) so the EXIT cleanup
## can still safe-rm the workspace without targeting $HOME itself.
export HOME="${workspace}/home"
mkdir --parents -- "${HOME}"

## Fixture git ops run with hooks OFF (they are fixtures, not the tested behaviour).
gitq() { git -c core.hooksPath="${workspace}/nohooks" -c protocol.file.allow=always "$@"; }
mkdir --parents -- "${workspace}/nohooks"

## --- Recording stubs for the four orchestrated phases --------------------------
## Each appends "<LABEL> <args>" to TIDY_LOG and exits with ${<LABEL>_RC:-0}, so a
## case sets e.g. SYNC_RC=1 inline on the dm-tidy invocation to simulate a verdict.
TIDY_LOG="${workspace}/tidy.log"
export TIDY_LOG
stubs="${workspace}/stubs"
mkdir --parents -- "${stubs}"

make_stub() {
   ## $1 label (also the stub filename, lowercased-ish is fine), $2 RC env var name.
   local path="${stubs}/$1" label="$1" rc_var="$2"
   {
      printf '%s\n' '#!/bin/bash'
      # shellcheck disable=SC2016
      printf 'printf "%s %%s\\n" "$*" >> "${TIDY_LOG}"\n' "${label}"
      # shellcheck disable=SC2016
      printf 'exit "${%s:-0}"\n' "${rc_var}"
   } > "${path}"
   chmod +x -- "${path}"
}

make_stub REMOTES  REMOTES_RC
make_stub SYNC     SYNC_RC
make_stub REMASTER REMASTER_RC
make_stub GITSYNC  GITSYNC_RC
make_stub FSCK     FSCK_RC

## REMOTES is the phase-0 ensure (dm-packaging-helper-script); stubbed so the suite
## never runs the real remote-add. It only RECORDS its call -- it does NOT add
## remotes -- so phase 0's VALIDATION runs against the fixture's real remotes below.
export DM_TIDY_REMOTES_ENSURE="${stubs}/REMOTES"
export DM_TIDY_SUBMODULE_SYNC="${stubs}/SYNC"
export DM_TIDY_REMASTER_ALL="${stubs}/REMASTER"
export DM_TIDY_GIT_SYNC="${stubs}/GITSYNC"
export DM_TIDY_FSCK="${stubs}/FSCK"

## --- Fixture: derivative-maker-shaped superproject on 'ai' + one submodule ------
fork="${workspace}/fork.git"
## The superproject IS the helper's hardcoded tree (${HOME}/derivative-maker), so the
## phase-0 ensure runs here -- the right-tree path these cases exercise.
super="${HOME}/derivative-maker"

gitq init --quiet --bare -- "${fork}"
## Seed the fork with an 'ai' branch from a scratch repo.
scratch="${workspace}/scratch"
gitq init --quiet -- "${scratch}"
gitq -C "${scratch}" checkout --quiet -b ai
printf 'v1\n' > "${scratch}/file"
gitq -C "${scratch}" add file
gitq -C "${scratch}" commit --quiet -m "sub v1"
gitq -C "${scratch}" remote add fork "file://${fork}"
gitq -C "${scratch}" push --quiet fork ai

gitq init --quiet -- "${super}"
gitq -C "${super}" checkout --quiet -b ai
mkdir --parents -- "${super}/build-steps.d" "${super}/help-steps"
printf 'x\n' > "${super}/build-steps.d/keep"
printf 'x\n' > "${super}/help-steps/keep"
gitq -C "${super}" add build-steps.d help-steps
gitq -C "${super}" commit --quiet -m "super base"
gitq -C "${super}" submodule --quiet add -b ai "file://${fork}" sub
gitq -C "${super}" commit --quiet -m "add sub"
gitq -C "${super}/sub" checkout --quiet ai

## Phase-0 validation requires the dm-tidy-critical remotes (org-ai-assisted,
## ArrayBolt3) on every ai-workflow repo. Add them (URLs are never contacted -- the
## validation is a local 'git remote get-url' presence check). A case below removes
## one to prove the phase-0 early-abort fires.
for repo in "${super}" "${super}/sub"; do
   gitq -C "${repo}" remote add org-ai-assisted "file://${fork}"
   gitq -C "${repo}" remote add ArrayBolt3 "file://${fork}"
done

## The exact 'top' dm-tidy resolves (so expected log lines match byte-for-byte).
super_top="$(gitq -C "${super}" rev-parse --show-toplevel)"
sub_resolved_top="$(gitq -C "${super}/sub" rev-parse --show-superproject-working-tree)"

log_lines() { cat -- "${TIDY_LOG}" 2>/dev/null || true; }
reset_log() { printf '' > "${TIDY_LOG}"; }

## Run dm-tidy, capturing its own exit code without tripping the test's errexit.
## Env assignments for the run are passed as leading NAME=VALUE args.
tidy_rc=0
run_tidy() {
   local env_pairs=()
   while [ "$#" -gt 0 ]; do
      case "$1" in
         *=*)
            env_pairs+=( "$1" )
            shift
            ;;
         *)
            break
            ;;
      esac
   done
   reset_log
   tidy_rc=0
   env "${env_pairs[@]}" "${tool}" "$@" >/dev/null 2>&1 || tidy_rc="$?"
}

## Assert the ordered list of phase LABELS actually invoked (ignores args).
labels_seen() { log_lines | awk '{print $1}' | paste -sd, -; }

## --- Case 1: all phases OK -> exit 0, order sync,remaster,gitsync,fsck ----------
run_tidy --dir "${super}"
if [ "${tidy_rc}" -eq 0 ]; then
   pass "all-ok run exits 0"
else
   fail "all-ok run exited ${tidy_rc}; log:<<<$(log_lines)>>>"
fi
if [ "$(labels_seen)" = "REMOTES,SYNC,REMASTER,GITSYNC,FSCK" ]; then
   pass "phases run in order remotes -> sync -> remaster -> parent-sync -> fsck"
else
   fail "phase order wrong: $(labels_seen)"
fi
## The apply run must pass --apply to remaster and NOT --dry-run anywhere.
if grep --quiet -- "^REMASTER --apply ${super_top}\$" <<< "$(log_lines)"; then
   pass "apply run calls remaster with --apply on the resolved parent"
else
   fail "apply run remaster args wrong; log:<<<$(log_lines)>>>"
fi
if grep --quiet -- '--dry-run' <<< "$(log_lines)"; then
   fail "apply run leaked --dry-run into a phase; log:<<<$(log_lines)>>>"
else
   pass "apply run passes no --dry-run to any phase"
fi

## --- Case 2 (CANARY): sync BLOCKED (exit 1) -> exit 3, sweep CONTINUES ----------
run_tidy SYNC_RC=1 --dir "${super}"
if [ "${tidy_rc}" -eq 3 ]; then
   pass "a BLOCKED submodule-sync makes dm-tidy exit 3 (nonzero: not mistaken for clean)"
else
   fail "blocked sync did not exit 3; got ${tidy_rc}"
fi
if [ "$(labels_seen)" = "REMOTES,SYNC,REMASTER,GITSYNC,FSCK" ]; then
   pass "a blocked sync does NOT stop the sweep (remaster/parent-sync/fsck still run)"
else
   fail "blocked sync stopped the sweep: $(labels_seen)"
fi

## --- Case 3 (CANARY): remaster BLOCKED (exit 3) -> exit 3, parent-sync still runs
run_tidy REMASTER_RC=3 --dir "${super}"
if [ "${tidy_rc}" -eq 3 ]; then
   pass "a BLOCKED remaster makes dm-tidy exit 3"
else
   fail "blocked remaster did not exit 3; got ${tidy_rc}"
fi
if [ "$(labels_seen)" = "REMOTES,SYNC,REMASTER,GITSYNC,FSCK" ]; then
   pass "a blocked remaster does not stop the parent-sync/fsck phases"
else
   fail "blocked remaster stopped the sweep: $(labels_seen)"
fi

## --- Case 4: remaster ERROR (exit 1) -> exit 1, parent-sync ABORTED (no push) ---
run_tidy REMASTER_RC=1 --dir "${super}"
if [ "${tidy_rc}" -eq 1 ]; then
   pass "a structural remaster error makes dm-tidy exit 1"
else
   fail "errored remaster did not exit 1; got ${tidy_rc}"
fi
if [ "$(labels_seen)" = "REMOTES,SYNC,REMASTER,FSCK" ]; then
   pass "a remaster error ABORTS parent-sync (never pushes on a half-done tree) but still fscks"
else
   fail "remaster error did not abort parent-sync correctly: $(labels_seen)"
fi

## --- Case 5: sync STRUCTURAL (exit 2) -> exit 1, remaster+parent-sync aborted ---
run_tidy SYNC_RC=2 --dir "${super}"
if [ "${tidy_rc}" -eq 1 ]; then
   pass "a structural sync error (exit 2) makes dm-tidy exit 1"
else
   fail "structural sync error did not exit 1; got ${tidy_rc}"
fi
if [ "$(labels_seen)" = "REMOTES,SYNC,FSCK" ]; then
   pass "a structural sync error aborts BOTH mutating phases, still fscks"
else
   fail "structural sync error did not abort correctly: $(labels_seen)"
fi

## --- Case 6: parent-sync fails (exit 1) -> exit 1 ------------------------------
run_tidy GITSYNC_RC=1 --dir "${super}"
if [ "${tidy_rc}" -eq 1 ]; then
   pass "a failed parent-sync makes dm-tidy exit 1"
else
   fail "failed parent-sync did not exit 1; got ${tidy_rc}"
fi

## --- Case 7: corrupt store (fsck nonzero) -> exit 1 ---------------------------
run_tidy FSCK_RC=1 --dir "${super}"
if [ "${tidy_rc}" -eq 1 ]; then
   pass "a nonzero fsck (corruption) makes dm-tidy exit 1"
else
   fail "corrupt-store fsck did not exit 1; got ${tidy_rc}"
fi

## --- Case 8: --dry-run drives each phase in its dry mode ------------------------
run_tidy --dir "${super}" --dry-run
if [ "${tidy_rc}" -eq 0 ]; then
   pass "dry-run all-ok exits 0"
else
   fail "dry-run exited ${tidy_rc}; log:<<<$(log_lines)>>>"
fi
got="$(log_lines)"
if grep --quiet -- "^SYNC --dir ${super_top} --dry-run\$" <<< "${got}" \
   && grep --quiet -- "^REMASTER --dry-run ${super_top}\$" <<< "${got}" \
   && grep --quiet -- "^GITSYNC --dir ${super_top} --dry-run\$" <<< "${got}"; then
   pass "dry-run passes the dry flag to sync/remaster/parent-sync (remaster --dry-run, not --apply)"
else
   fail "dry-run flags wrong; log:<<<${got}>>>"
fi
if grep --quiet -- "^REMOTES --dry-run --batch pkg_git_remotes_add\$" <<< "${got}"; then
   pass "dry-run passes --dry-run to the phase-0 remote ensure (reports, adds nothing)"
else
   fail "dry-run remote-ensure flag wrong; log:<<<${got}>>>"
fi
if grep --quiet -- '^REMASTER --apply' <<< "${got}"; then
   fail "dry-run still called remaster with --apply; log:<<<${got}>>>"
else
   pass "dry-run never calls remaster --apply"
fi

## --- Case 9: the REAL git fsck default path (no FSCK override) is clean ---------
run_tidy DM_TIDY_FSCK= --dir "${super}"
if [ "${tidy_rc}" -eq 0 ]; then
   pass "default 'git fsck --full --no-dangling' reports the fixture superproject clean (submodule gitlink not read as corruption)"
else
   fail "default fsck path did not report clean; got ${tidy_rc}; log:<<<$(log_lines)>>>"
fi

## --- Case 10: submodule arg resolves up to the parent superproject -------------
run_tidy --dir "${super}/sub"
if [ "${tidy_rc}" -eq 0 ]; then
   pass "a submodule arg is accepted (resolved to its parent)"
else
   fail "submodule arg run exited ${tidy_rc}; log:<<<$(log_lines)>>>"
fi
if grep --quiet -- "^SYNC --dir ${sub_resolved_top}\$" <<< "$(log_lines)"; then
   pass "a submodule arg resolves to the parent superproject before running the phases"
else
   fail "submodule arg did not resolve to the parent; log:<<<$(log_lines)>>>"
fi

## --- Case 11: refusals touch nothing (empty log, exit 2) -----------------------
refuse_touches_nothing() {
   local desc="$1" ; shift
   run_tidy "$@"
   if [ "${tidy_rc}" -ne 2 ]; then
      fail "${desc}: expected exit 2, got ${tidy_rc}"
      return
   fi
   if [ -n "$(log_lines)" ]; then
      fail "${desc}: refusal still ran a phase: <<<$(log_lines)>>>"
      return
   fi
   pass "${desc}: refused (exit 2) and ran no phase"
}

## 11a. parent on master (not 'ai').
gitq -C "${super}" checkout --quiet -b master
refuse_touches_nothing "superproject on master" --dir "${super}"
gitq -C "${super}" checkout --quiet ai

## 11b. a plain git repo: neither a derivative-maker checkout nor its submodule.
plain="${workspace}/plain"
gitq init --quiet -- "${plain}"
gitq -C "${plain}" checkout --quiet -b ai
printf 'x\n' > "${plain}/f"
gitq -C "${plain}" add f
gitq -C "${plain}" commit --quiet -m base
refuse_touches_nothing "non-derivative-maker repo" --dir "${plain}"

## 11c. an empty --dir value is a usage error, not a silent cwd run.
refuse_touches_nothing "empty --dir value" --dir ""

## --- Case 12 (CANARY): phase 0 refuses early on a MISSING expected remote --------
## Remove a dm-tidy-critical remote from the submodule; phase 0's validation must
## ABORT before any mutating phase, so a missing remote cannot SILENTLY skip
## downstream work (e.g. the arraybolt3/trixie merge is gated on the ArrayBolt3
## remote). On OLD dm-tidy (no phase 0) the mutating phases would run -> this case
## fails, as a canary must. Only the read-only fsck still runs after the abort.
gitq -C "${super}/sub" remote remove ArrayBolt3
run_tidy --dir "${super}"
if [ "${tidy_rc}" -eq 1 ]; then
   pass "a missing expected remote makes dm-tidy exit 1"
else
   fail "missing remote did not exit 1; got ${tidy_rc}; log:<<<$(log_lines)>>>"
fi
if [ "$(labels_seen)" = "REMOTES,FSCK" ]; then
   pass "a missing remote ABORTS sync/remaster/parent-sync at phase 0 (only read-only fsck runs)"
else
   fail "missing remote did not abort the mutating phases: $(labels_seen)"
fi
## 12b. the SAME early-abort fires under --dry-run: surface it before any run (the
## ensure is --dry-run so it adds nothing, leaving the remote genuinely missing).
run_tidy --dir "${super}" --dry-run
if [ "${tidy_rc}" -eq 1 ] && [ "$(labels_seen)" = "REMOTES,FSCK" ]; then
   pass "dry-run errors early on a missing expected remote (no sync/remaster/parent-sync)"
else
   fail "dry-run did not fail early on missing remote; rc=${tidy_rc} labels=$(labels_seen)"
fi
gitq -C "${super}/sub" remote add ArrayBolt3 "file://${fork}"

## --- Case 13 (CANARY): a submodule path WITH A SPACE is still validated ----------
## submodule_paths() must parse a whitespace-containing path (NUL-delimited config
## records), or that submodule is SILENTLY skipped from phase 0 -- the bug a lone
## 'sed' split on the first space has. Add one, omit a critical remote from it, and
## require the early abort. On the old sed-split code the spaced path garbles to a
## non-existent dir, is skipped, and dm-tidy wrongly proceeds -- so this case fails.
gitq -C "${super}" submodule --quiet add -b ai "file://${fork}" "my sub"
gitq -C "${super}" commit --quiet -m "add spaced submodule"
gitq -C "${super}/my sub" checkout --quiet ai
gitq -C "${super}/my sub" remote add org-ai-assisted "file://${fork}"
## deliberately NO ArrayBolt3 on "my sub"
run_tidy --dir "${super}"
if [ "${tidy_rc}" -eq 1 ] && [ "$(labels_seen)" = "REMOTES,FSCK" ]; then
   pass "a submodule path with a space is parsed + validated (its missing remote aborts phase 0)"
else
   fail "spaced submodule path was not validated; rc=${tidy_rc} labels=$(labels_seen)"
fi

## --- Case 14 (CANARY): phase 0's DESTRUCTIVE ensure is SKIPPED off the helper's tree
## The ensure (dm-packaging-helper-script pkg_git_remotes_add) takes no target dir and
## only ever rewrites remotes on its hardcoded ${HOME}/derivative-maker tree. So when
## 'top' is a DIFFERENT valid derivative-maker checkout, dm-tidy must NOT invoke it --
## else it silently mutates ${HOME}/derivative-maker (NOT 'top') and reports tidy, a
## destructive false green. Build a second superproject OUTSIDE the helper's tree and
## prove the ensure is skipped. On OLD dm-tidy (unconditional ensure) REMOTES IS
## invoked here, so these assertions FAIL -- as a canary must.
other="${workspace}/other"
gitq init --quiet -- "${other}"
gitq -C "${other}" checkout --quiet -b ai
mkdir --parents -- "${other}/build-steps.d" "${other}/help-steps"
printf 'x\n' > "${other}/build-steps.d/keep"
printf 'x\n' > "${other}/help-steps/keep"
gitq -C "${other}" add build-steps.d help-steps
gitq -C "${other}" commit --quiet -m "other base"
gitq -C "${other}" remote add org-ai-assisted "file://${fork}"
gitq -C "${other}" remote add ArrayBolt3 "file://${fork}"

run_tidy --dir "${other}"
if [ "${tidy_rc}" -eq 0 ]; then
   pass "off the helper's tree with all remotes present: dm-tidy exits 0"
else
   fail "off-tree all-present did not exit 0; got ${tidy_rc}; log:<<<$(log_lines)>>>"
fi
if grep --quiet -- '^REMOTES' <<< "$(log_lines)"; then
   fail "off-tree run INVOKED the destructive remote ensure (would mutate the wrong tree): <<<$(log_lines)>>>"
else
   pass "off-tree run does NOT invoke the remote ensure (no wrong-tree mutation, no false green)"
fi

## --- Case 15 (CANARY): off-tree + a missing remote -> ERROR, still no ensure --------
## Validation still runs on 'top', so a genuinely missing remote aborts (no false
## green) -- but the ensure stays skipped, so only the read-only fsck runs after the
## abort. OLD dm-tidy records REMOTES,FSCK here -> the labels check FAILS on it.
gitq -C "${other}" remote remove ArrayBolt3
run_tidy --dir "${other}"
if [ "${tidy_rc}" -eq 1 ] && [ "$(labels_seen)" = "FSCK" ]; then
   pass "off-tree missing remote: dm-tidy exits 1 and runs ONLY fsck (ensure skipped, no false green)"
else
   fail "off-tree missing remote wrong; rc=${tidy_rc} labels=$(labels_seen) log:<<<$(log_lines)>>>"
fi
gitq -C "${other}" remote add ArrayBolt3 "file://${fork}"

## --- Case 16 (CANARY): a MALFORMED .gitmodules ERRORS, never silent-skips -----------
## A .gitmodules parse failure must NOT be swallowed as "zero submodules" (which would
## validate nothing and report clean -- the silent-skip phase 0 exists to prevent).
## Corrupt the superproject's .gitmodules and require the early abort. On OLD dm-tidy
## the failure was 2>/dev/null-swallowed to an empty list, so it validated only the
## parent and PROCEEDED (exit 0) -- this case fails on it. 'super' IS the helper's tree,
## so the ensure runs first (REMOTES), then the parse error aborts before the rest.
printf 'this is not valid config\n[unterminated\n' > "${super}/.gitmodules"
run_tidy --dir "${super}"
if [ "${tidy_rc}" -eq 1 ] && [ "$(labels_seen)" = "REMOTES,FSCK" ]; then
   pass "a malformed .gitmodules ERRORS (exit 1, only fsck after) instead of silently validating zero submodules"
else
   fail "malformed .gitmodules not caught; rc=${tidy_rc} labels=$(labels_seen) log:<<<$(log_lines)>>>"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-tidy ensures+validates remotes (only on the helper's own tree, never the wrong one), orders the phases, exits nonzero on block/error, aborts safely (incl. a missing remote), dry-runs clean, refuses off-ai."

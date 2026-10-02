#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-iso-build (usr/bin/dm-iso-build) -- the fast single-flavor
## image/ISO build wrapper. It drives dm-iso-build through the OFFICIAL orchestration
## (help-steps/dm-build-official-one) so a test image is as close to a RELEASE image as
## possible -- most importantly it ships the derivative APT repository ENABLED.
##
## Most assertions drive the REAL wrapper against a STUB
## 'help-steps/dm-build-official-one' (records its args + selected env, exits with a
## controllable code), so nothing is actually built. One end-to-end assertion drives the
## wrapper against the REAL derivative-maker checkout with --show-steps (dry-plan, no build)
## to prove the official path actually emits '--repo true' -- a thing a stub cannot show,
## because '--repo true' is dm-build-official-one's OWN internal default.
##
## WHAT IT GUARDS:
##   - the wrapper drives dm-build-official-one, NOT a bare ./derivative-maker: a bare
##     call leaves build_remote_repo_enable false, so the opts file is not written and
##     the ISO ships repo-DISABLED (systemcheck check_apt_repository == Disabled);
##   - the official path produces a repo-ENABLED build ('--repo true' in the dry-plan);
##   - a caller cannot fiddle --repo (always repo-enabled) -- --repo is REFUSED;
##   - uploads are forced to simulate (rsync_cmd) -- a test/gate builder never publishes;
##   - CI=true is set -- help-steps/sign-and-tag refuses a redistributable sign+tag unless
##     CI=true, so without it --sign-and-tag true cannot run on the official (redistributable)
##     path; uploads stay simulated regardless;
##   - the build is ALWAYS the frozen snapshot: freshness is hardcoded, so DM_FRESHNESS
##     cannot leak a non-frozen snapshot into the arch-keyed shared base/package repo;
##   - the single flavor + arch + VM-target set reach dm-build-official-one via the
##     environment (flavors_list / dist_build_target_arch / dist_build_multi_target_list);
##   - the wrapper does NOT pass --skip-published-packages itself (the official path owns
##     it); it passes --reuse-cowbuilder-base, which DM_CLEAN drops for a fresh base;
##   - NO freshness marker/state file is ever written (the reuse decision is stateless);
##   - a build FAILURE propagates (nonzero).

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
## DM_ISO_BUILD_BIN is a test-only seam so the canary can point the suite at a
## deliberately-broken dm-iso-build and confirm these assertions FAIL on it.
tool="${DM_ISO_BUILD_BIN:-${dist_ai_bin}/dm-iso-build}"
if [ ! -x "${tool}" ]; then
   printf '%s\n' "FATAL: dm-iso-build not found/executable at '${tool}'." >&2
   exit 1
fi

workspace="$(mktemp --directory)"
cleanup() { chmod --recursive u+w -- "${workspace}" 2>/dev/null || true ; safe-rm --recursive --force -- "${workspace}"; }
trap cleanup EXIT

## ${HOME}/.cache/dm-iso-build.last-freshness is the marker path the stateless-check
## below asserts is absent; keep HOME inside the throwaway workspace so that check never
## depends on the operator's real ~/.cache. The wrapper also creates ${HOME}/.ssh (the
## official path's upload-readiness guard); confine that here too.
export HOME="${workspace}/home"
mkdir --parents -- "${HOME}/.cache"
marker="${HOME}/.cache/dm-iso-build.last-freshness"

## A derivative-maker-shaped repo whose 'help-steps/dm-build-official-one' is a recording
## stub: it logs its args and the build-param env the wrapper sets, then exits STUB_RC.
repo="${workspace}/repo"
mkdir --parents -- "${repo}/help-steps"
args_log="${workspace}/dm-args.log"
env_log="${workspace}/dm-env.log"
run_out="${workspace}/dm-run.out"
{
   printf '%s\n' '#!/bin/bash'
   # shellcheck disable=SC2016
   printf '%s\n' 'printf "%s\n" "$*" >> "${DM_ARGS_LOG}"'
   # shellcheck disable=SC2016
   printf '%s\n' '{ printf "rsync_cmd=%s\n" "${rsync_cmd-<unset>}"; printf "flavors_list=%s\n" "${flavors_list-<unset>}"; printf "dist_build_target_arch=%s\n" "${dist_build_target_arch-<unset>}"; printf "dist_build_multi_target_list=%s\n" "${dist_build_multi_target_list-<unset>}"; printf "CI=%s\n" "${CI-<unset>}"; } >> "${DM_ENV_LOG}"'
   # shellcheck disable=SC2016
   printf '%s\n' 'exit "${STUB_RC:-0}"'
} > "${repo}/help-steps/dm-build-official-one"
chmod +x -- "${repo}/help-steps/dm-build-official-one"

## Run dm-iso-build, capturing its exit code without tripping the test's errexit. Leading
## NAME=VALUE args become the run's environment; DM_REPO + the log paths are always set.
iso_rc=0
run_iso() {
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
   printf '' > "${args_log}"
   printf '' > "${env_log}"
   iso_rc=0
   env "${env_pairs[@]}" DM_REPO="${repo}" DM_ARGS_LOG="${args_log}" DM_ENV_LOG="${env_log}" \
      "${tool}" "$@" > "${run_out}" 2>&1 || iso_rc="$?"
}

has_arg() { grep --quiet -- "$1" "${args_log}" 2>/dev/null ; }
has_env() { grep --quiet --fixed-strings --line-regexp -- "$1" "${env_log}" 2>/dev/null ; }

## --- Case 1: a normal run drives the official path repo-enabled, upload-simulated -------
run_iso
if [ "${iso_rc}" -eq 0 ] \
   && has_arg '--reuse-cowbuilder-base' \
   && ! has_arg '--repo' \
   && ! has_arg '--skip-published-packages' \
   && has_env 'rsync_cmd=true simulate-only' \
   && has_env 'flavors_list=kicksecure-lxqt' \
   && has_env 'dist_build_target_arch=amd64' \
   && has_env 'dist_build_multi_target_list=' \
   && has_env 'CI=true'; then
   pass "a normal build drives dm-build-official-one repo-enabled (no --repo), upload-simulated, CI=true (redistributable sign+tag gate), flavor/arch/iso via env"
else
   fail "normal build contract wrong; rc=${iso_rc} args=<<<$(cat -- "${args_log}")>>> env=<<<$(cat -- "${env_log}")>>>"
fi

## --- Case 2 (CANARY): DM_FRESHNESS is IGNORED -- always the frozen snapshot -----------
## Freshness is hardcoded, so a non-frozen DM_FRESHNESS must NOT leak a non-frozen snapshot
## into the build (which would cross-contaminate the arch-keyed shared base/package repo in
## either direction). On a wrapper that honors DM_FRESHNESS this FAILS (passes --freshness current).
run_iso DM_FRESHNESS=current
if [ "${iso_rc}" -eq 0 ] && has_arg '--freshness frozen' && ! has_arg '--freshness current'; then
   pass "DM_FRESHNESS is ignored -- the build is always the frozen snapshot"
else
   fail "DM_FRESHNESS leaked a non-frozen snapshot; rc=${iso_rc} args=<<<$(cat -- "${args_log}")>>>"
fi

## --- Case 3 (CANARY): the wrapper writes NO marker/state file --------------------
## The wrapper is stateless: a successful build must write no freshness marker at
## ${HOME}/.cache/dm-iso-build.last-freshness. A wrapper that records one fails this.
safe-rm --force -- "${marker}"
run_iso
if [ "${iso_rc}" -eq 0 ] && [ ! -e "${marker}" ]; then
   pass "a successful build writes no freshness marker (stateless)"
else
   fail "a marker/state file was written; rc=${iso_rc} marker='$(cat -- "${marker}" 2>/dev/null)'"
fi

## --- Case 4: DM_CLEAN drops the wrapper's reuse knob (fresh cowbuilder base) ------------
## dm-iso-build's only reuse knob is --reuse-cowbuilder-base; --skip-published-packages is
## owned by dm-build-official-one, so the wrapper never passes it either way.
run_iso DM_CLEAN=1
if [ "${iso_rc}" -eq 0 ] && ! has_arg '--reuse-cowbuilder-base' && ! has_arg '--skip-published-packages'; then
   pass "DM_CLEAN drops --reuse-cowbuilder-base (fresh cowbuilder base)"
else
   fail "DM_CLEAN still passed a reuse knob; rc=${iso_rc} args=<<<$(cat -- "${args_log}")>>>"
fi

## --- Case 5: a non-iso DM_TARGET selects a VM image via the multi-target env ------------
run_iso DM_TARGET=qcow2
if [ "${iso_rc}" -eq 0 ] && has_env 'dist_build_multi_target_list=qcow2'; then
   pass "DM_TARGET=qcow2 selects the VM image via dist_build_multi_target_list"
else
   fail "DM_TARGET did not map to dist_build_multi_target_list; rc=${iso_rc} env=<<<$(cat -- "${env_log}")>>>"
fi

## --- Case 6 (CANARY): a build FAILURE propagates --------------------------------
run_iso STUB_RC=2
if [ "${iso_rc}" -eq 2 ]; then
   pass "a build failure propagates (exit 2)"
else
   fail "build failure did not propagate; got ${iso_rc}"
fi

## --- Case 7 (CANARY): a caller-passed --repo is REFUSED --------------------------
## This builder is ALWAYS repo-enabled via the official path; a caller must not fiddle
## --repo (true duplicates the default; false would ride past -one's --repo true into a
## late, cryptic redistributable-incompatibility error). The refusal fires before any
## build work, so the stub is never called. On the old wrapper (no guard) this FAILS.
for repo_flag_arg in '--repo true' '--repo false'; do
   # shellcheck disable=SC2086  ## deliberate word-split of the test arg pair
   run_iso ${repo_flag_arg}
   if [ "${iso_rc}" -ne 0 ] && grep --quiet -- "refusing '--repo'" "${run_out}" && [ ! -s "${args_log}" ]; then
      pass "a caller-passed '${repo_flag_arg}' is refused before any build"
   else
      fail "'${repo_flag_arg}' was not refused; rc=${iso_rc} out=<<<$(cat -- "${run_out}")>>> args=<<<$(cat -- "${args_log}")>>>"
   fi
done
## The '--repo=VALUE' form cannot go through run_iso (its leading NAME=VALUE parsing
## would eat it as an env pair), so drive the tool directly.
printf '' > "${args_log}"
repo_eq_rc=0
DM_REPO="${repo}" DM_ARGS_LOG="${args_log}" DM_ENV_LOG="${env_log}" "${tool}" --repo=false > "${run_out}" 2>&1 || repo_eq_rc="$?"
if [ "${repo_eq_rc}" -ne 0 ] && grep --quiet -- "refusing '--repo'" "${run_out}" && [ ! -s "${args_log}" ]; then
   pass "a caller-passed '--repo=false' is refused before any build"
else
   fail "'--repo=false' was not refused; rc=${repo_eq_rc} out=<<<$(cat -- "${run_out}")>>> args=<<<$(cat -- "${args_log}")>>>"
fi

## --- Case 8: END-TO-END -- the REAL official path emits '--repo true' (repo enabled) ----
## A stub cannot prove this: '--repo true' is dm-build-official-one's OWN default, added
## internally, not passed by the wrapper. Dry-plan the REAL checkout with --show-steps
## (no build) and assert the per-flavor ISO build step carries '--repo true'. Requires a
## derivative-maker checkout (dm_checkout, from help_steps_test_lib.bsh); SKIP that single
## assertion when absent -- the stub cases above still gate the wrapper's own behavior.
if [ -f "${dm_checkout}/help-steps/dm-build-official-one" ]; then
   plan="$(DM_REPO="${dm_checkout}" DM_FLAVOR=kicksecure-lxqt DM_ARCH=amd64 \
      "${tool}" --show-steps 2>/dev/null || true)"
   iso_line="$(printf '%s\n' "${plan}" \
      | grep -- './derivative-maker' | grep -- '--target iso' | grep -- '--flavor kicksecure-lxqt' \
      | head -n1 || true)"
   if [ -n "${iso_line}" ] && grep --quiet -- '--repo true' <<< "${iso_line}"; then
      pass "the real official path dry-plans the ISO build with --repo true (repo enabled)"
   else
      fail "the real official path did not emit '--repo true' for the ISO build; iso_line=<<<${iso_line}>>>"
   fi
else
   printf '%s\n' "SKIP (end-to-end): no derivative-maker checkout at '${dm_checkout}' (set DERIVATIVE_MAKER_DIR)." >&2
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-iso-build drives dm-build-official-one repo-enabled (refuses caller --repo, real path emits --repo true), upload-simulated, frozen-only, stateless, drops its reuse knob under DM_CLEAN, and propagates a build failure."

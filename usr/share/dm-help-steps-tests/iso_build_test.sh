#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-iso-build (usr/bin/dm-iso-build) -- the fast image/ISO build
## wrapper. It drives the REAL wrapper against a STUB './derivative-maker' (records its
## args, exits with a controllable code), so nothing is actually built.
##
## WHAT IT GUARDS:
##   - the build is ALWAYS the frozen snapshot: freshness is hardcoded, so DM_FRESHNESS
##     cannot leak a non-frozen snapshot into the arch-keyed shared base/package repo;
##   - every build reuses the cowbuilder base (BOTH --skip-published-packages and
##     --reuse-cowbuilder-base), safe because there is only one snapshot;
##   - NO freshness marker/state file is ever written (the reuse decision is stateless);
##   - DM_CLEAN forces a from-scratch build (neither reuse knob);
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

## HOME is where a pre-fix dm-iso-build wrote its freshness marker
## (${HOME}/.cache/dm-iso-build.last-freshness); keep it inside the throwaway workspace so
## the absence check below never depends on the operator's real ~/.cache.
export HOME="${workspace}/home"
mkdir --parents -- "${HOME}/.cache"
marker="${HOME}/.cache/dm-iso-build.last-freshness"

## A derivative-maker-shaped repo whose './derivative-maker' is a recording stub.
repo="${workspace}/repo"
mkdir --parents -- "${repo}"
args_log="${workspace}/dm-args.log"
run_out="${workspace}/dm-run.out"
{
   printf '%s\n' '#!/bin/bash'
   # shellcheck disable=SC2016
   printf '%s\n' 'printf "%s\n" "$*" >> "${DM_ARGS_LOG}"'
   # shellcheck disable=SC2016
   printf '%s\n' 'exit "${STUB_RC:-0}"'
} > "${repo}/derivative-maker"
chmod +x -- "${repo}/derivative-maker"

## Run dm-iso-build, capturing its exit code without tripping the test's errexit. Leading
## NAME=VALUE args become the run's environment; DM_REPO + DM_ARGS_LOG are always set.
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
   iso_rc=0
   env "${env_pairs[@]}" DM_REPO="${repo}" DM_ARGS_LOG="${args_log}" "${tool}" "$@" > "${run_out}" 2>&1 || iso_rc="$?"
}

has_knob() { grep --quiet -- "$1" "${args_log}" 2>/dev/null ; }

## --- Case 1: a normal run reuses the base (both speed knobs) ---------------------
run_iso DM_FRESHNESS=frozen
if [ "${iso_rc}" -eq 0 ] && has_knob '--skip-published-packages' && has_knob '--reuse-cowbuilder-base'; then
   pass "a normal build passes both reuse knobs"
else
   fail "a normal build did not pass both reuse knobs; rc=${iso_rc} args=<<<$(cat -- "${args_log}")>>>"
fi

## --- Case 2 (CANARY): DM_FRESHNESS is IGNORED -- always the frozen snapshot -----------
## Freshness is hardcoded, so a non-frozen DM_FRESHNESS must NOT leak a non-frozen snapshot
## into the build (which would cross-contaminate the arch-keyed shared base/package repo in
## either direction). The run must still pass '--freshness frozen' and reuse the base. On a
## wrapper that honors DM_FRESHNESS this FAILS (it would pass '--freshness current').
run_iso DM_FRESHNESS=current
if [ "${iso_rc}" -eq 0 ] && has_knob '--freshness frozen' && ! has_knob '--freshness current' && has_knob '--reuse-cowbuilder-base'; then
   pass "DM_FRESHNESS is ignored -- the build is always the frozen snapshot"
else
   fail "DM_FRESHNESS leaked a non-frozen snapshot; rc=${iso_rc} args=<<<$(cat -- "${args_log}")>>>"
fi

## --- Case 3 (CANARY): the wrapper writes NO marker/state file --------------------
## OLD dm-iso-build recorded the freshness in ${HOME}/.cache/dm-iso-build.last-freshness
## on a successful build. The stateless wrapper writes nothing; this fails on the old one.
safe-rm --force -- "${marker}"
run_iso DM_FRESHNESS=frozen
if [ "${iso_rc}" -eq 0 ] && [ ! -e "${marker}" ]; then
   pass "a successful build writes no freshness marker (stateless)"
else
   fail "a marker/state file was written; rc=${iso_rc} marker='$(cat -- "${marker}" 2>/dev/null)'"
fi

## --- Case 4: DM_CLEAN -> from-scratch (neither reuse knob) -----------------------
run_iso DM_FRESHNESS=frozen DM_CLEAN=1
if [ "${iso_rc}" -eq 0 ] && ! has_knob '--skip-published-packages' && ! has_knob '--reuse-cowbuilder-base'; then
   pass "DM_CLEAN builds from scratch (neither reuse knob passed)"
else
   fail "DM_CLEAN still passed a reuse knob; rc=${iso_rc} args=<<<$(cat -- "${args_log}")>>>"
fi

## --- Case 5 (CANARY): a build FAILURE propagates --------------------------------
run_iso DM_FRESHNESS=frozen STUB_RC=2
if [ "${iso_rc}" -eq 2 ]; then
   pass "a build failure propagates (exit 2)"
else
   fail "build failure did not propagate; got ${iso_rc}"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-iso-build always builds the frozen snapshot (DM_FRESHNESS ignored), reuses the cowbuilder base, writes no marker/state, drops both knobs only under DM_CLEAN, and propagates a build failure."

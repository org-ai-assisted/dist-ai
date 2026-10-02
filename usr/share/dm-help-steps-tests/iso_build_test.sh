#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-iso-build (usr/bin/dm-iso-build) -- the fast image/ISO build
## wrapper. It drives the REAL wrapper against a STUB './derivative-maker' (records its
## args, exits with a controllable code), so nothing is actually built.
##
## WHAT IT GUARDS:
##   - the cowbuilder-base reuse decision: reuse only when the freshness marker CONFIRMS
##     the last build used this freshness; a freshness switch OR an UNKNOWN freshness
##     (no readable marker) rebuilds the base (snapshot-specific) -- never reuse a
##     wrong-snapshot base;
##   - DM_CLEAN forces a from-scratch build (no reuse knobs);
##   - a SUCCESSFUL build whose freshness-marker write FAILS still exits 0 (an unwritable
##     ~/.cache must NOT mask success as failure), AND drops the stale marker so the next
##     build rebuilds the base instead of reusing a wrong-snapshot one off a stale value;
##   - a build FAILURE propagates (nonzero) and leaves the marker unchanged.

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

## HOME holds the marker (${HOME}/.cache/dm-iso-build.last-freshness); keep it inside the
## throwaway workspace, never the operator's real ~/.cache.
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

set_marker() { mkdir --parents -- "${HOME}/.cache" ; printf '%s\n' "$1" > "${marker}" ; }
clear_marker() { chmod u+w -- "${marker}" 2>/dev/null || true ; safe-rm --force -- "${marker}" ; }
marker_value() { cat -- "${marker}" 2>/dev/null || true ; }

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

## --- Case 1: marker matches the freshness -> reuse the base ----------------------
clear_marker
set_marker frozen
run_iso DM_FRESHNESS=frozen
if [ "${iso_rc}" -eq 0 ] && has_knob '--reuse-cowbuilder-base'; then
   pass "marker matching the freshness reuses the cowbuilder base"
else
   fail "matching marker did not reuse; rc=${iso_rc} args=<<<$(cat -- "${args_log}")>>>"
fi

## --- Case 2: freshness switch -> rebuild the base -------------------------------
clear_marker
set_marker frozen
run_iso DM_FRESHNESS=current
if [ "${iso_rc}" -eq 0 ] && has_knob '--skip-published-packages' && ! has_knob '--reuse-cowbuilder-base'; then
   pass "a freshness switch rebuilds the cowbuilder base (no --reuse-cowbuilder-base)"
else
   fail "freshness switch still reused; rc=${iso_rc} args=<<<$(cat -- "${args_log}")>>>"
fi
if [ "$(marker_value)" = "current" ]; then
   pass "a successful build records the new freshness in the marker"
else
   fail "marker not updated to 'current'; got '$(marker_value)'"
fi

## --- Case 3 (CANARY): an UNKNOWN freshness (no marker) rebuilds the base ---------
## On OLD dm-tidy the reuse-drop was gated on a NON-EMPTY marker, so a missing marker
## kept --reuse-cowbuilder-base and could reuse a wrong-snapshot base. This case fails
## on that code.
clear_marker
run_iso DM_FRESHNESS=frozen
if [ "${iso_rc}" -eq 0 ] && ! has_knob '--reuse-cowbuilder-base'; then
   pass "an unknown freshness (no marker) rebuilds the base instead of reusing one"
else
   fail "unknown freshness reused the base; rc=${iso_rc} args=<<<$(cat -- "${args_log}")>>>"
fi

## --- Case 4: DM_CLEAN -> from-scratch (no reuse knobs) --------------------------
clear_marker
set_marker frozen
run_iso DM_FRESHNESS=frozen DM_CLEAN=1
if [ "${iso_rc}" -eq 0 ] && ! has_knob '--skip-published-packages' && ! has_knob '--reuse-cowbuilder-base'; then
   pass "DM_CLEAN builds from scratch (neither reuse knob passed)"
else
   fail "DM_CLEAN still passed a reuse knob; rc=${iso_rc} args=<<<$(cat -- "${args_log}")>>>"
fi

## --- Case 5 (CANARY): a build FAILURE propagates, marker untouched --------------
clear_marker
set_marker frozen
run_iso DM_FRESHNESS=frozen STUB_RC=2
if [ "${iso_rc}" -eq 2 ]; then
   pass "a build failure propagates (exit 2)"
else
   fail "build failure did not propagate; got ${iso_rc}"
fi
if [ "$(marker_value)" = "frozen" ]; then
   pass "a failed build leaves the marker unchanged"
else
   fail "failed build altered the marker; got '$(marker_value)'"
fi

## --- Case 6 (CANARY): a failed marker write -> rc 0 + drop branch (uid-independent) -
## OLD dm-iso-build (no best-effort guard) aborted under errexit on the failed marker
## write and exited NONZERO -- masking a SUCCESSFUL build as a failure. Force the write
## failure with a non-directory marker PARENT ('.cache' is a FILE), which blocks the
## mkdir+write for ANY uid -- 'chmod 400' would NOT, since the suite re-execs under root
## and root bypasses file permissions. The drop branch is confirmed by its warning.
home6="${workspace}/home6"
mkdir --parents -- "${home6}"
printf '' > "${home6}/.cache"
run_iso HOME="${home6}" DM_FRESHNESS=current STUB_RC=0
if [ "${iso_rc}" -eq 0 ]; then
   pass "an unwritable marker on a successful build still exits 0 (success not masked as failure)"
else
   fail "unwritable marker masked a successful build as failure; rc=${iso_rc} out=<<<$(cat -- "${run_out}")>>>"
fi
if grep --quiet -- 'could not persist the freshness marker' "${run_out}"; then
   pass "a failed marker write takes the drop branch (warns)"
else
   fail "a failed marker write did not take the drop branch; out=<<<$(cat -- "${run_out}")>>>"
fi

## --- Case 6b (CANARY): the DROP removes an EXISTING stale marker --------------------
## Observable only when a real marker FILE exists AND the write fails -- which, for a
## plain unwritable file, is a NON-ROOT scenario (root bypasses file permissions, so the
## write just succeeds and no drop is needed; there is no stale-marker-with-failed-write
## case for root). Under non-root, prove the stale marker is removed; a dm-iso-build that
## omits the 'safe-rm' drop leaves it behind and fails here.
if [ "$(id -u)" -ne 0 ]; then
   home6b="${workspace}/home6b"
   mkdir --parents -- "${home6b}/.cache"
   marker6b="${home6b}/.cache/dm-iso-build.last-freshness"
   printf 'frozen\n' > "${marker6b}"
   chmod 400 -- "${marker6b}"
   run_iso HOME="${home6b}" DM_FRESHNESS=current STUB_RC=0
   chmod u+w -- "${marker6b}" 2>/dev/null || true
   if [ "${iso_rc}" -eq 0 ] && [ ! -e "${marker6b}" ]; then
      pass "non-root: a failed write to an existing marker DROPS it (no wrong-snapshot reuse)"
   else
      fail "non-root: stale marker not dropped on a failed write; rc=${iso_rc} marker='$(cat -- "${marker6b}" 2>/dev/null)'"
   fi
else
   printf '%s\n' "note: Case 6b (stale-marker drop) is non-root-only; root bypasses file perms, so no stale-marker-with-failed-write scenario exists to exercise."
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-iso-build reuses the base only on a confirmed-matching freshness, rebuilds on a switch/unknown/clean, preserves a successful build's exit code when the marker is unwritable, and drops a stale marker so no wrong-snapshot base is reused."

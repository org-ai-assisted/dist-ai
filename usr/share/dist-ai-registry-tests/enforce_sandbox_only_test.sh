#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dist-ai-tests-all's enforce_sandbox_only() escape set. Outside GitHub CI a
## dist-ai run must go through the sandbox (a suite may mount, remove files, or need
## root); the gate's OWN comment names exactly two escapes plus the in-sandbox route:
##   GITHUB_ACTIONS=true         -- ephemeral GitHub runner
##   DIST_AI_IN_SANDBOX=1        -- already routed into the sandbox
##   DIST_AI_ALLOW_HOST_TESTS=1  -- the one documented, WARNED host override
##
## THE BUG IT GUARDS: a generic 'CI=true' escape. 'CI' is set by countless unrelated
## tools and CI systems, so 'CI=true dist-ai-tests-all --core' on a bare workstation
## ran the mount/rm/root core suites on the REAL HOST, silently bypassing the gate.
## Only GITHUB_ACTIONS (which is specific to the isolated runner) may stand in for it.
##
## Drives the SHIPPED function: extracts it from dist-ai-tests-all and calls it, so a
## reintroduced 'CI=true' (or a dropped legitimate escape) fails here.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_script="$(readlink --canonicalize -- "${BASH_SOURCE[0]}")"
test_dir="${test_script%/*}"

## Installed layout is /usr/share/...; from a checkout the entrypoints sit at ../../bin.
orch="${test_dir}/../../bin/dist-ai-tests-all"
[ -r "${orch}" ] || orch='/usr/bin/dist-ai-tests-all'
if [ ! -r "${orch}" ]; then
   printf '%s\n' 'FATAL: enforce_sandbox_only_test: dist-ai-tests-all not found' >&2
   exit 1
fi

## Extract the function definition (header and closing brace both at column 0) and
## source only it -- sourcing the whole orchestrator would run the entire registry.
slice="$(sed -n '/^enforce_sandbox_only() {$/,/^}$/p' -- "${orch}")"
if [[ "${slice}" != *'exit 3'* ]]; then
   printf '%s\n' 'FATAL: could not extract enforce_sandbox_only(); the slice is wrong, not the code' >&2
   exit 1
fi
slice_file="$(mktemp)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --force -- "${slice_file}"; }
trap cleanup EXIT
printf '%s\n' "${slice}" > "${slice_file}"
# shellcheck disable=SC1090  # sourcing an extracted slice by design
source "${slice_file}"

failures=0

## Run the gate with a chosen env, all four gate vars cleared first, and report its
## exit status. return 0 -> 0 (allowed); the refuse path exits 3.
gate_rc() {
   local rc=0
   (
      unset GITHUB_ACTIONS DIST_AI_IN_SANDBOX DIST_AI_ALLOW_HOST_TESTS CI
      "$@"
      enforce_sandbox_only
   ) >/dev/null 2>&1 || rc="$?"
   printf '%s\n' "${rc}"
}

check() {
   local desc="$1" want="$2" got="$3"
   if [ "${got}" = "${want}" ]; then
      printf 'PASS: %s (rc %s)\n' "${desc}" "${got}"
   else
      printf 'FAIL: %s: rc %s, expected %s\n' "${desc}" "${got}" "${want}" >&2
      failures=$((failures + 1))
   fi
}

## The bug: a bare generic CI=true must NO LONGER exempt -> refuse (exit 3).
check 'bare CI=true does not exempt the host gate' 3 "$(gate_rc export CI=true)"
## No escape at all -> refuse.
check 'no escape refuses on the host' 3 "$(gate_rc true)"
## The three legitimate escapes still work.
check 'GITHUB_ACTIONS=true is exempt' 0 "$(gate_rc export GITHUB_ACTIONS=true)"
check 'DIST_AI_IN_SANDBOX=1 is exempt' 0 "$(gate_rc export DIST_AI_IN_SANDBOX=1)"
check 'DIST_AI_ALLOW_HOST_TESTS=1 is exempt' 0 "$(gate_rc export DIST_AI_ALLOW_HOST_TESTS=1)"
## CI=true must not combine with an unrelated non-escape to slip through.
check 'CI=true plus a stray var still refuses' 3 "$(gate_rc export CI=true SOME_OTHER=1)"

if [ "${failures}" -gt 0 ]; then
   printf 'enforce_sandbox_only_test: %s assertion(s) FAILED.\n' "${failures}" >&2
   exit 1
fi
printf 'enforce_sandbox_only_test: OK\n'

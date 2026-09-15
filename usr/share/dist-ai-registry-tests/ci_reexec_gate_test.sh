#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dist-ai-tests-all's CI re-exec gate (should_ci_reexec). The re-exec runs
## ci/dist-ai-tests-ci-run.sh, whose setup is PRIVILEGED: useradd dm-ci-build, a
## NOPASSWD:ALL /etc/sudoers.d drop-in, and chown -R the workspace. Because exec runs
## no EXIT trap, those side effects cannot be undone by a later refusal.
##
## THE BUG IT GUARDS: the re-exec fired on root + a STRAY GITHUB_WORKSPACE +
## component=derivative-maker with NO CI/sandbox signal -- BEFORE the sandbox gate --
## so it installed passwordless sudo and chowned the tree on a bare workstation. The
## fix makes sandbox_gate_exempt (the SAME exempt set enforce_sandbox_only uses) a
## PRECONDITION: the privileged re-exec may fire only where running outside the sandbox
## is already permitted (GITHUB_ACTIONS / DIST_AI_IN_SANDBOX / DIST_AI_ALLOW_HOST_TESTS).
##
## Drives the SHIPPED functions: extracts sandbox_gate_exempt + should_ci_reexec from
## dist-ai-tests-all and calls them, so a reintroduced ungated re-exec fails here.
## CANARY: dropping `sandbox_gate_exempt || return 1` from should_ci_reexec makes the
## first assertion (no re-exec on a bare host) FAIL.

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
   printf '%s\n' 'FATAL: ci_reexec_gate_test: dist-ai-tests-all not found' >&2
   exit 1
fi

## Extract the two function definitions (header and closing brace at column 0) and
## source only them -- sourcing the whole orchestrator would run the entire registry.
slice="$(sed -n \
   -e '/^sandbox_gate_exempt() {$/,/^}$/p' \
   -e '/^should_ci_reexec() {/,/^}$/p' \
   -- "${orch}")"
if [[ "${slice}" != *'sandbox_gate_exempt() {'* ]] || [[ "${slice}" != *'should_ci_reexec() {'* ]]; then
   printf '%s\n' 'FATAL: could not extract the gate functions; the slice is wrong, not the code' >&2
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

## Run should_ci_reexec with a chosen euid and env. Every gate var is cleared first and
## the two globals it reads (list_only, component) are set to the RE-EXEC-eligible values,
## so each case only has to add what it wants via a single trailing `export ...` command
## (or `true` for none). Echoes 'reexec' (would re-exec) or 'no' (would not).
reexec_verdict() {  ## $1=euid  $2...=a command, e.g. `export GITHUB_WORKSPACE=/ws GITHUB_ACTIONS=true`
   local euid="$1"; shift
   (
      unset GITHUB_ACTIONS DIST_AI_IN_SANDBOX DIST_AI_ALLOW_HOST_TESTS CI GITHUB_WORKSPACE
      list_only='false'
      component='derivative-maker'
      "$@"
      if should_ci_reexec "${euid}"; then printf '%s\n' reexec; else printf '%s\n' no; fi
   )
}

check() {
   local desc="$1" want="$2" got="$3"
   if [ "${got}" = "${want}" ]; then
      printf 'PASS: %s (%s)\n' "${desc}" "${got}"
   else
      printf 'FAIL: %s: got %s, expected %s\n' "${desc}" "${got}" "${want}" >&2
      failures=$((failures + 1))
   fi
}

## THE BUG: root + stray GITHUB_WORKSPACE + derivative-maker, NO escape -> must NOT re-exec.
check 'root + stray GITHUB_WORKSPACE, no CI/sandbox signal does NOT re-exec' \
   no "$(reexec_verdict 0 export GITHUB_WORKSPACE=/some/workspace)"
## Real CI and sandbox-as-root are legitimate re-exec contexts.
check 'root + GITHUB_WORKSPACE + GITHUB_ACTIONS=true re-execs' \
   reexec "$(reexec_verdict 0 export GITHUB_WORKSPACE=/some/workspace GITHUB_ACTIONS=true)"
check 'root + GITHUB_WORKSPACE + DIST_AI_IN_SANDBOX=1 re-execs' \
   reexec "$(reexec_verdict 0 export GITHUB_WORKSPACE=/some/workspace DIST_AI_IN_SANDBOX=1)"
## The host override is an exempt context too (privileged, but the operator opted in explicitly).
check 'root + GITHUB_WORKSPACE + DIST_AI_ALLOW_HOST_TESTS=1 re-execs' \
   reexec "$(reexec_verdict 0 export GITHUB_WORKSPACE=/some/workspace DIST_AI_ALLOW_HOST_TESTS=1)"
## Non-root never re-execs (no privileged setup needed; the resolver runs fine as the invoker).
check 'non-root does NOT re-exec even with every signal set' \
   no "$(reexec_verdict 1000 export GITHUB_WORKSPACE=/some/workspace GITHUB_ACTIONS=true)"
## Missing GITHUB_WORKSPACE -> not a CI workspace run -> no re-exec.
check 'root + GITHUB_ACTIONS but no GITHUB_WORKSPACE does NOT re-exec' \
   no "$(reexec_verdict 0 export GITHUB_ACTIONS=true)"
## Wrong component -> the resolver is not sourced -> no re-exec.
check 'wrong component does NOT re-exec' \
   no "$(reexec_verdict 0 export GITHUB_WORKSPACE=/some/workspace GITHUB_ACTIONS=true component=secure-terminal)"
## --list is a free, machine-readable path -> never re-exec.
check 'list_only does NOT re-exec' \
   no "$(reexec_verdict 0 export GITHUB_WORKSPACE=/some/workspace GITHUB_ACTIONS=true list_only=true)"
## A generic CI=true (set by countless tools) is NOT an exempt signal on its own.
check 'bare CI=true does NOT re-exec' \
   no "$(reexec_verdict 0 export GITHUB_WORKSPACE=/some/workspace CI=true)"

if [ "${failures}" -gt 0 ]; then
   printf 'ci_reexec_gate_test: %s assertion(s) FAILED.\n' "${failures}" >&2
   exit 1
fi
printf 'ci_reexec_gate_test: OK\n'

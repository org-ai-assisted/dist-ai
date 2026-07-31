#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Runs the private-ai-config test surface from a PRIVATE_AI_CONFIG_PATH checkout.
## Split into lanes because the repo's tests have sharply different runtime
## requirements: the core lane is container-safe, the fuzz lane is randomized
## and time-boxed, and the resilience lane needs a live 'systemd --user'
## manager plus a journal, which a debian:trixie-slim CI container does not
## have.
##
## Exit contract (dist-ai-tests-all): 0 PASS / 77 SKIP / anything else FAIL.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

lane='core'

while [ "$#" -gt 0 ]; do
   case "$1" in
      '--lane')
         [ "$#" -ge 2 ] || { printf 'run-tests.sh: --lane requires a value\n' >&2; exit 64; }
         lane="$2"
         shift 2
         ;;
      '--lane='*)
         lane="${1#*=}"
         shift
         ;;
      *)
         ## Remaining arguments are forwarded to the lane's tests (e.g.
         ## --iters / --seed for the fuzzer).
         break
         ;;
   esac
done

repo="${PRIVATE_AI_CONFIG_PATH:-}"
if [ -z "${repo}" ] || [ ! -d "${repo}/tests" ]; then
   printf 'private-ai-config-tests: PRIVATE_AI_CONFIG_PATH unset or has no tests/ dir; skipping.\n' >&2
   exit 77
fi

## Per-lane test lists. Paths are relative to the checkout root.
##
## These are DATA, not comments, because check_registration below compares the
## checkout against them: a test file that is in neither a lane nor the
## exclusion list is reported as unregistered. A hand-maintained list drifts
## silently otherwise -- the suite keeps passing while covering less than it
## claims, which is indistinguishable from covering everything.
core_tests=(
   'tests/claude-goal-state-test.py'
   'tests/redactor-date-shape-test.py'
   'tests/safe-pkill-guard-test.py'
   'tests/ci-status-checkruns-test.py'
   'tests/git-hooks-unicode-test.sh'
   'tests/git-hooks-branch-policy-test.py'
   'tests/ci-status-test.sh'
   'tests/kcov-shell-coverage-test.sh'
   'tests/anti-stall-supervisor-wake-arity-test.sh'
   'tests/claude-session-on-mobile-test.sh'
   'tests/string-parsing-stress-test.sh'
   'tests/sandbox-transfer-perms-test.sh'
   'tests/sandbox-confine-profile-test.sh'
   'tests/sandbox-run-confine-wiring-test.sh'
   'claude/hooks/tests/test-cowbuilder-guard.py'
   'claude/hooks/tests/test-git-command-parse.py'
   'claude/hooks/tests/test-git-policy-config.py'
   'claude/hooks/tests/test-git-policy-guard.py'
)
fuzz_tests=( 'tests/string-parsing-fuzz.sh' )
resilience_tests=(
   'tests/resilience/wake-detach-cgroup-test.sh'
   'tests/resilience/run-resilience-tests.sh'
   'tests/resilience/durable-bg-run-chaos.sh'
)

## Deliberately NOT a lane member, with the reason, so an omission reads as a
## decision rather than an oversight. Support files that a test invokes are
## listed here too: they are not tests and must not be run as one.
excluded_tests=(
   'tests/ci-status-fixtures.py'                    # fixture generator
   'tests/redactor-selftest-value.py'               # test-support helper
   'tests/cpu-governance-test.sh'                   # root; writes /sys/fs/cgroup
   'tests/run-cpu-governance-test.sh'               # sandbox wrapper; re-enters
   'tests/run-string-parsing-fuzz.sh'               # sandbox wrapper; re-enters
   'tests/run-string-parsing-stress-test.sh'        # sandbox wrapper; re-enters
   'tests/run-confine-enforcement-test.sh'          # sandbox integration; real bwrap in temp-claude
   'tests/resilience/chaos-tick-worker.sh'          # workload for the chaos test
   'tests/resilience/resilience-workload.sh'        # workload, not a test
   'tests/resilience/resilience-stall-supervisor.sh' # support supervisor
   'tests/resilience/mock-404-server.py'            # support server
   'tests/resilience/netns-api-down-probe.sh'       # root unshare; real creds
   'tests/resilience/netns-run.sh'                  # root unshare; real creds
   'tests/resilience/run-claude-inner.sh'           # netns probe invokes it
   'tests/resilience/self-supervision-gate.sh'      # drives real claude; quota
)

## Fail when the checkout holds a test-shaped file that no lane runs and no
## exclusion accounts for. Cheap, so it runs on every lane rather than waiting
## for a full sweep.
check_registration() {
   local candidate rel known entry unregistered=()
   while IFS= read -r candidate; do
      rel="${candidate#"${repo}/"}"
      known='false'
      for entry in "${core_tests[@]}" "${fuzz_tests[@]}" \
         "${resilience_tests[@]}" "${excluded_tests[@]}"
      do
         if [ "${entry}" = "${rel}" ]; then
            known='true'
            break
         fi
      done
      if [ "${known}" = 'false' ]; then
         unregistered+=( "${rel}" )
      fi
   ## Scan roots are DISCOVERED, not hardcoded. Two fixed paths meant a tests/
   ## directory added anywhere else in the repo was silently ungoverned -- the
   ## guard would keep passing while covering less than it claims, which is the
   ## failure class it exists to catch.
   done < <( find "${repo}" -path "${repo}/.git" -prune -o \
      -type d -name tests -print0 2>/dev/null \
      | xargs --null --no-run-if-empty find \
        -type f \( -name '*.sh' -o -name '*.py' \) 2>/dev/null | sort )

   if [ "${#unregistered[@]}" -gt 0 ]; then
      printf '\n########## UNREGISTERED TEST FILE(S) ##########\n' >&2
      printf '%s\n' "${unregistered[@]}" >&2
      printf '%s\n' \
         'Add each to a lane list, or to excluded_tests WITH a reason.' \
         'A file in neither is never run and never reported.' >&2
      return 1
   fi
   return 0
}

tests=()
case "${lane}" in
   'core')
      tests=( "${core_tests[@]}" )
      ;;
   'fuzz')
      tests=( "${fuzz_tests[@]}" )
      ## The fuzzer defaults to 500 iterations per phase across four phases,
      ## which overruns the runner's 600s fuzz budget on a loaded CI box and
      ## would be reported TIMEOUT rather than a fuzz result. Bound it unless
      ## the caller passed its own budget.
      if [ "$#" -eq 0 ]; then
         set -- '--iters' '150'
      fi
      ;;
   'resilience')
      ## Every test in this lane drives transient 'systemd --user' units and
      ## reads the user journal.
      if ! systemctl --user show-environment >/dev/null 2>&1; then
         printf 'private-ai-config-tests: no systemd --user manager; skipping the resilience lane.\n' >&2
         exit 77
      fi
      tests=( "${resilience_tests[@]}" )
      ;;
   *)
      printf 'run-tests.sh: unknown lane %s (want: core | fuzz | resilience)\n' "${lane}" >&2
      exit 64
      ;;
esac

registration_status=0
check_registration || registration_status=1

passes=0
failures=0
skips=0

for rel in "${tests[@]}"; do
   path="${repo}/${rel}"
   if [ ! -f "${path}" ]; then
      ## A renamed or deleted test must be loud: silently dropping it is how a
      ## suite keeps reporting green while covering less than it claims.
      printf '\n########## MISSING: %s ##########\n' "${rel}" >&2
      failures=$(( failures + 1 ))
      continue
   fi
   printf '\n########## %s ##########\n' "${rel}"
   rc=0
   case "${path}" in
      *.py)
         python3 -- "${path}" "$@" || rc=$?
         ;;
      *)
         bash -- "${path}" "$@" || rc=$?
         ;;
   esac
   if [ "${rc}" -eq 77 ]; then
      printf '########## SKIPPED: %s ##########\n' "${rel}"
      skips=$(( skips + 1 ))
   elif [ "${rc}" -ne 0 ]; then
      printf '########## FAILED (%s): %s ##########\n' "${rc}" "${rel}" >&2
      failures=$(( failures + 1 ))
   else
      printf '########## PASSED: %s ##########\n' "${rel}"
      passes=$(( passes + 1 ))
   fi
done

printf '\n===== summary (%s lane): %s pass, %s fail, %s skip =====\n' \
   "${lane}" "${passes}" "${failures}" "${skips}"

if [ "${failures}" -ne 0 ]; then
   exit 1
fi
## An unregistered test file fails the lane even when everything that DID run
## passed: the point is that something was never run at all.
if [ "${registration_status}" -ne 0 ]; then
   printf '===== unregistered test file(s): see above =====\n' >&2
   exit 1
fi
## Nothing actually ran: report SKIP so the runner does not record a vacuous
## pass for a lane whose prerequisites were all absent.
if [ "${passes}" -eq 0 ]; then
   exit 77
fi
exit 0

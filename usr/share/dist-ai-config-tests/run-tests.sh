#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Runs the dist-ai-config test surface from a DIST_AI_CONFIG_PATH checkout.
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

repo="${DIST_AI_CONFIG_PATH:-}"
if [ -z "${repo}" ] || [ ! -d "${repo}/tests" ]; then
   printf 'dist-ai-config-tests: DIST_AI_CONFIG_PATH unset or has no tests/ dir; skipping.\n' >&2
   exit 77
fi

## Per-lane test lists. Paths are relative to the checkout root.
##
## Deliberately EXCLUDED from every lane, with the reason, so an omission reads
## as a decision rather than an oversight:
##   tests/redactor-selftest-value.py      test-support helper, not a test
##   tests/cpu-governance-test.sh          needs root, writes /sys/fs/cgroup and
##                                         saturates every core
##   tests/run-*.sh                        Qubes sandbox wrappers; they require
##                                         sandbox-run and re-enter the inner
##                                         tests this runner already invokes
##   tests/resilience/netns-*.sh           root 'unshare --net' plus real claude
##                                         credentials and network
##   tests/resilience/run-claude-inner.sh  invoked by the netns probe only
##   tests/resilience/self-supervision-gate.sh
##                                         drives a real claude and costs plan
##                                         quota; manual only
tests=()
case "${lane}" in
   'core')
      tests=(
         'tests/claude-goal-state-test.py'
         'tests/redactor-date-shape-test.py'
         'tests/safe-pkill-guard-test.py'
         'tests/ci-status-checkruns-test.py'
         'tests/git-hooks-unicode-test.sh'
         'tests/ci-status-test.sh'
         'tests/string-parsing-stress-test.sh'
         'claude/hooks/tests/test-cowbuilder-guard.py'
      )
      ;;
   'fuzz')
      tests=( 'tests/string-parsing-fuzz.sh' )
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
         printf 'dist-ai-config-tests: no systemd --user manager; skipping the resilience lane.\n' >&2
         exit 77
      fi
      tests=(
         'tests/resilience/wake-detach-cgroup-test.sh'
         'tests/resilience/run-resilience-tests.sh'
         'tests/resilience/durable-bg-run-chaos.sh'
      )
      ;;
   *)
      printf 'run-tests.sh: unknown lane %s (want: core | fuzz | resilience)\n' "${lane}" >&2
      exit 64
      ;;
esac

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
## Nothing actually ran: report SKIP so the runner does not record a vacuous
## pass for a lane whose prerequisites were all absent.
if [ "${passes}" -eq 0 ]; then
   exit 77
fi
exit 0

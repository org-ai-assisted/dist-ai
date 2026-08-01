#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'docker/derivative-maker-docker-start':
## the BUILD's exit status must be the script's, never the log writer's.
##
## THE BUG IT GUARDS: the script ends with
##     "$@" 2>&1 | tee -a -- "${BUILD_LOG}"
## and runs under 'set -o pipefail', so the pipeline reports the RIGHTMOST
## failure. When 'tee' cannot write -- a full disk on the log path -- its status
## became the script's, and therefore the docker run's, and therefore the build
## verdict the caller sees. 'ci/reproducible-build-twice' documents exit 1 as
## "images differ", so a log-disk failure reported a bit-for-bit REPRODUCIBLE run
## as a reproducibility defect and pointed the reader at the image instead of at
## the disk.
##
## Observed exactly that: a local run whose comparator printed
## "RESULT: identical (reproducible)" exited 1 because tee had hit ENOSPC on the
## container log earlier in the same run.
##
## Asserts the shipped contract AND the semantics it depends on, with a canary:
## the pre-fix form must come out WRONG on the same fixture, or this proves
## nothing. Uses /dev/full for a real, deterministic write failure.
##
## Needs no root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

docker_start=""
locate_subject() {
   local candidate

   for candidate in "${DM_DOCKER_START:-}" \
      "${DERIVATIVE_MAKER_DIR:-}/docker/derivative-maker-docker-start" \
      "${HOME}/derivative-maker/docker/derivative-maker-docker-start"; do
      case "${candidate}" in
         ''|'/docker/derivative-maker-docker-start')
            continue
            ;;
      esac
      if [ -r "${candidate}" ]; then
         docker_start="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: no derivative-maker docker/derivative-maker-docker-start found." >&2
   exit 77
fi

if [ ! -c /dev/full ]; then
   printf '%s\n' "SKIP: /dev/full is not available; cannot produce a deterministic write failure." >&2
   exit 77
fi

## --- semantics, on a real write failure ------------------------------------
## Each idiom is its own script beside this one, run standalone so the assertions
## are about behaviour rather than about reading the shipped file.
run_fixed() {
   local log_target="$1"
   shift

   env LOG_TARGET="${log_target}" bash -- "${test_dir}/docker_start_fixed_inner.sh" "$@"
}

## The pre-fix idiom, for the canary.
run_prefix() {
   local log_target="$1"
   shift

   env LOG_TARGET="${log_target}" bash -- "${test_dir}/docker_start_prefix_inner.sh" "$@"
}

scratch_log="$(mktemp)"
cleanup() {
   safe-rm --force -- "${scratch_log}"
}
trap cleanup EXIT

## A SUCCEEDING build whose log cannot be written must still report success.
rc=0
run_fixed /dev/full bash -c 'printf "%s\n" build-output; exit 0' >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "successful build with an unwritable log reports success"
else
   fail "successful build with an unwritable log reported ${rc}"
fi

## CANARY: the pre-fix form MUST get this wrong, else the check above is empty.
rc=0
run_prefix /dev/full bash -c 'printf "%s\n" build-output; exit 0' >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "canary: pre-fix form does turn an unwritable log into a failure (${rc})"
else
   fail "canary broken: pre-fix form also reported success; this fixture cannot tell them apart"
fi

## A FAILING build must still report ITS status, not be masked by a healthy tee.
rc=0
run_fixed "${scratch_log}" bash -c 'printf "%s\n" build-output; exit 7' >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -eq 7 ]; then
   pass "failing build reports its own status (7) through a healthy log writer"
else
   fail "failing build reported ${rc}, expected 7 -- a real failure would be mis-signalled"
fi

## --- shipped contract --------------------------------------------------------
assert_contains() {
   local file needle label
   file="$1"
   needle="$2"
   label="$3"

   if grep --quiet --fixed-strings -- "${needle}" "${file}"; then
      pass "${label}"
   else
      fail "${label} -- not found in ${file}"
   fi
}

assert_contains "${docker_start}" 'PIPESTATUS[@]' \
   "docker-start captures PIPESTATUS rather than the pipeline status"
assert_contains "${docker_start}" 'exit "${pipe_status[0]}"' \
   "docker-start exits with the BUILD's status"

## A tee failure must not vanish either: the log is then incomplete, and that is
## worth saying even though it is not the verdict.
if grep --quiet --fixed-strings -- 'WARNING' "${docker_start}"; then
   pass "docker-start warns when the build log could not be written"
else
   fail "docker-start swallows a log-write failure silently"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: docker-start exit status."

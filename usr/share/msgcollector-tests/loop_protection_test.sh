#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## msgcollector_shared's loop_protection(), exercised the way msgprogress
## exercises it.
##
## THE BUG: loop_protection lives in a SOURCED file that has no strict mode of
## its own, but every caller DOES set nounset. Reading the counter before it
## was ever set therefore aborted the CALLER with 'unbound variable' -- and
## only on the first call, which is what every --progressx update makes. The
## trap is reachable only in that shape: sourced into a nounset shell and
## called with no counter set, which is exactly what each case below builds.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v MSGCOLLECTOR_REPO ] || MSGCOLLECTOR_REPO=""

if [ -n "${MSGCOLLECTOR_REPO}" ]; then
   shared_file="${MSGCOLLECTOR_REPO}/usr/libexec/msgcollector/msgcollector_shared"
else
   shared_file='/usr/libexec/msgcollector/msgcollector_shared'
fi

if [ ! -r "${shared_file}" ]; then
   printf '%s\n' "SKIP: msgcollector_shared not found at '${shared_file}'" >&2
   printf '%s\n' "set MSGCOLLECTOR_REPO to a msgcollector checkout, or install the package" >&2
   exit 77
fi

work_dir="$(mktemp --directory -- "${TMP}/msgcollector-loop-test.XXXXXX")"

## CI-path state (see run_caller): the real absolute path may be a SYMLINK into
## a shared helper-scripts checkout, so the original is moved aside and a private
## stub dir swapped in, then restored -- never written THROUGH.
hs_real=/usr/libexec/helper-scripts
hs_backup="${work_dir}/hs-original"
hs_swapped=""

restore_hs_swap() {
   [ -n "${hs_swapped}" ] || return 0
   hs_swapped=""
   ## Retire the consumed stub dir into work_dir (safe-rm'd on exit) rather than
   ## rm-ing a /usr path, then put back whatever was there before (symlink, real
   ## dir, or nothing).
   if [ -e "${hs_real}" ] || [ -L "${hs_real}" ]; then
      mv --no-target-directory -- "${hs_real}" "${work_dir}/hs-stub-consumed"
   fi
   if [ -e "${hs_backup}" ] || [ -L "${hs_backup}" ]; then
      mv --no-target-directory -- "${hs_backup}" "${hs_real}"
   fi
}

test_cleanup_handler() {
   restore_hs_swap
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

## Stub the two helper-scripts the shared file sources, so the test does not
## depend on the host having them installed. The marker lets the regression
## guard below prove the stub never leaks to the shared real path.
stubs="${work_dir}/helper-scripts"
mkdir --parents -- "${stubs}"
printf '%s\n' 'light_sleep() { true; }' >"${stubs}/light_sleep.bsh"
{
   printf '%s\n' '## LOOP_PROTECTION_STUB_MARKER'
   printf '%s\n' 'is_whole_number() { case "${1:-}" in ""|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }'
} >"${stubs}/strings.bsh"

## Swap the private stub dir in for the real /usr/libexec/helper-scripts once,
## non-destructively. Idempotent: only the first call moves anything.
install_hs_stubs() {
   [ -z "${hs_swapped}" ] || return 0
   if [ -e "${hs_real}" ] || [ -L "${hs_real}" ]; then
      mv --no-target-directory -- "${hs_real}" "${hs_backup}"
   fi
   mkdir --parents -- "${hs_real}"
   cp --force -- "${stubs}/light_sleep.bsh" "${stubs}/strings.bsh" "${hs_real}/"
   hs_swapped=yes
}

pass_count=0
fail_count=0

## SC2016: the caller body below is LITERAL code written into a file; its
## expansions must reach the generated script unexpanded.
# shellcheck disable=SC2016
run_caller() {
   local body caller output

   body="$1"
   caller="${work_dir}/caller"

   ## Mirrors msgprogress: the R-010 preamble, then the source, then the call.
   ## That shape is what makes the trap reachable at all -- sourcing into a
   ## shell WITHOUT nounset would pass no matter what the function does.
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail' \
         'set -o errtrace' 'shopt -s inherit_errexit'
      printf '%s\n' "source ${shared_file}"
      printf '%s\n' "${body}"
   } >"${caller}"

   ## Isolate the two sourced helper-scripts so the host install is irrelevant.
   ## Locally, bwrap gives a throwaway /usr/libexec, leaving the host untouched.
   ## CI's container denies the unprivileged userns bwrap needs (pivot_root
   ## EPERM in debian:trixie-slim, same as the sibling sandbox tests -- those
   ## run only in temp-claude), but it is ephemeral and root, so there we swap
   ## the same two stubs in at the real path and run unconfined. That path may
   ## be a SYMLINK into a shared helper-scripts checkout (CI's
   ## dist-ai-tests-ci-hs-runtime.sh wires one for helper-scripts:true
   ## consumers); a plain cp would write THROUGH it and clobber the real
   ## strings.bsh for every sibling suite in the run (e.g. unit_tests_test.sh).
   ## install_hs_stubs moves the original aside instead; restore_hs_swap (below
   ## and in the EXIT trap) puts it back.
   if [ "${CI:-}" = "true" ]; then
      ## Stubs were swapped in once by the parent (install_hs_stubs, below):
      ## run_caller executes under $(...), so doing it here would be
      ## subshell-local and the restore would never fire.
      output="$(timeout 20 bash "${caller}" 2>&1)" || true
   else
      output="$(bwrap --dev-bind / / \
         --tmpfs /usr/libexec \
         --bind "${stubs}" /usr/libexec/helper-scripts \
         --ro-bind "${shared_file}" "${shared_file}" \
         -- timeout 20 bash "${caller}" 2>&1)" || true
   fi
   printf '%s' "${output}"
}

## check <description> <expected exit-status text or ''> <must-contain> <caller body>
check() {
   local description must_contain body output verdict

   description="$1"
   must_contain="$2"
   body="$3"

   output="$(run_caller "${body}")"

   verdict=PASS
   ## A bwrap that refused means the caller never ran; every assertion below
   ## would then be measuring nothing.
   if printf '%s\n' "${output}" | grep --extended-regexp -- '^bwrap:' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: the caller never ran"
   elif printf '%s\n' "${output}" | grep --fixed-strings -- 'unbound variable' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: nounset abort -- this is the bug"
   elif [ -n "${must_contain}" ] \
      && ! printf '%s\n' "${output}" | grep --fixed-strings -- "${must_contain}" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: expected '${must_contain}'"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

## In CI, swap the stub helper-scripts in at the real absolute path ONCE, in
## THIS shell -- run_caller runs under $(...), so an install there would be
## subshell-local and restore_hs_swap (regression guard + EXIT trap) would never
## fire, leaving the stub at the shared path for later suites.
if [ "${CI:-}" = "true" ]; then
   install_hs_stubs
fi

## The real first call: no counter set yet. This is what every --progressx
## update does, and the one that aborted.
## The counter's base is 0: the first call establishes it, the next increments.
## The absolute numbers are implementation detail; what the pair proves is that
## a second call does not reset.
check 'first call with no counter set' 'counter=0' \
   'loop_protection; printf "%s\n" "counter=${loop_counter_protection}"'

## The second call must INCREMENT, not reset -- a version that reset on every
## call would also survive nounset and would otherwise look fixed.
check 'a second call increments rather than resetting' 'counter=1' \
   'loop_protection; loop_protection; printf "%s\n" "counter=${loop_counter_protection}"'

## The timeout path must still fire, or the fix would have bought nounset
## safety by disabling the protection itself.
check 'a counter already at 60 still times out' '' \
   'loop_counter_protection=60; loop_protection; printf "%s\n" "NOT REACHED"'

## A non-numeric value is treated as a fresh start.
check 'a non-numeric counter resets to a fresh start' 'counter=0' \
   'loop_counter_protection=abc; loop_protection; printf "%s\n" "counter=${loop_counter_protection}"'

## Regression guard for THIS harness's own past bug: the CI stub swap must not
## leave the stub strings.bsh at the shared real path, or every sibling suite
## that sources /usr/libexec/helper-scripts/strings.bsh breaks (unit_tests_test.sh
## once went 39/5 this way). Restore now, then prove the stub marker is gone. In
## the bwrap branch nothing was swapped, so the host file is read as-is and has
## no marker -- a clean pass either way.
restore_hs_swap
if [ -e "${hs_real}/strings.bsh" ] \
   && grep --quiet --fixed-strings -- 'LOOP_PROTECTION_STUB_MARKER' "${hs_real}/strings.bsh"; then
   printf '%s\n' "FAIL: CI helper-scripts stub leaked into the shared ${hs_real}/strings.bsh" >&2
   fail_count=$(( fail_count + 1 ))
else
   printf '%s\n' "PASS: CI helper-scripts stub did not leak to the shared path"
   pass_count=$(( pass_count + 1 ))
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]

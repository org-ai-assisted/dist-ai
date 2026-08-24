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
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v MSGCOLLECTOR_REPO ] || MSGCOLLECTOR_REPO=""

if [ -n "${MSGCOLLECTOR_REPO}" ]; then
   shared_file="${MSGCOLLECTOR_REPO}/usr/libexec/msgcollector/msgcollector_shared"
else
   shared_file='/usr/libexec/msgcollector/msgcollector_shared'
fi

if [ ! -r "${shared_file}" ]; then
   printf '%s\n' "FATAL: msgcollector_shared not found at '${shared_file}'" >&2
   printf '%s\n' "set MSGCOLLECTOR_REPO to a msgcollector checkout, or install the package" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/msgcollector-loop-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

## loop_protection() calls is_whole_number and light_sleep from helper-scripts.
## Use the REAL ones the wire provides (HELPER_SCRIPTS_PATH, else the installed
## /usr/libexec) -- the same assumption every sibling suite makes -- so the test
## exercises the actual dependencies, not a reimplementation. Skip if absent.
if [ ! -r "${HELPER_SCRIPTS_PATH:-}/usr/libexec/helper-scripts/strings.bsh" ]; then
   printf '%s\n' "FATAL: helper-scripts not available at ${HELPER_SCRIPTS_PATH:-}/usr/libexec/helper-scripts" >&2
   exit 1
fi

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

   ## Run under the ambient HELPER_SCRIPTS_PATH / MSGCOLLECTOR_REPO the wire sets,
   ## so msgcollector_shared and its helper-scripts resolve from the checkouts.
   ## /usr/libexec is never written -- nothing to isolate, leak, or restore.
   ## light_sleep_skip makes the real light_sleep return without waiting where
   ## helper-scripts honors it; harmless (a 1s real sleep) where it does not yet.
   output="$(light_sleep_skip=true timeout --kill-after=20 20 bash "${caller}" 2>&1)" || true
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
   if printf '%s\n' "${output}" | grep --fixed-strings -- 'unbound variable' >/dev/null; then
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

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]

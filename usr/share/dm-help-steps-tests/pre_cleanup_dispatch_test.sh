#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for 'exception_handler_cleanup_run' in derivative-maker
## 'help-steps/pre': the single definition of which cleanup steps each error
## variant runs, shared by the ERR handlers and by exception_handler_signal.
##
## 'pre' cannot be sourced without a populated build environment, so the
## function is EXTRACTED from it and exercised against stub steps that record
## the order they ran in. That keeps the dispatch table under test even though
## its home file is not testable as a whole.
##
## Asserts:
##   - each kind runs exactly its steps, in order
##   - 'general' and an unknown kind run nothing
##   - the 'tolerate-failure' mode continues past a failing step (the signal path,
##     already exiting, must not let cleanup mask the signal)
##   - the 'abort-on-failure' mode propagates the failure (the ERR path)
##
## Needs no root and no mount capability.
##
## Subject selection (first that exists):
##   $DM_HELP_STEPS_PRE  ->  ./pre next to this test
##   ->  ~/derivative-maker/help-steps/pre

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

## Globals the extracted function closes over.
dist_source_help_steps_folder=""
args=()

extract_cleanup_run() {
   local subject extracted

   subject="$1"
   extracted="$2"
   ## The function body runs from its opening line to the first
   ## column-0 '}'.
   sed -n '/^exception_handler_cleanup_run() {$/,/^}$/p' -- "${subject}" > "${extracted}"
   if [ ! -s "${extracted}" ]; then
      printf '%s\n' "ERROR: could not extract exception_handler_cleanup_run from '${subject}'." >&2
      return 1
   fi
}

## Create a stub for each named step; each appends its own name to the log.
## '$1' is the step that should exit non-zero, or "" for none.
make_stub_steps() {
   local stub_dir failing_step log_file step_name

   stub_dir="$1"
   log_file="$2"
   failing_step="$3"

   for step_name in remove-local-temp-apt-repo unchroot-raw \
      unprevent-daemons-from-starting unmount-raw unmount-lb; do
      {
         printf '%s\n' '#!/bin/bash'
         printf '%s\n' "printf '%s\\n' '${step_name}' >> '${log_file}'"
         if [ "${step_name}" = "${failing_step}" ]; then
            printf '%s\n' 'exit 1'
         fi
      } > "${stub_dir}/${step_name}"
      chmod 0755 -- "${stub_dir}/${step_name}"
   done
}

require_steps() {
   local actual wanted description

   actual="$1"
   wanted="$2"
   description="$3"

   if [ "${actual}" = "${wanted}" ]; then
      pass "${description}"
   else
      fail "${description}: expected [${wanted}], got [${actual}]"
   fi
}

main() {
   local subject extracted scratch_base stub_dir log_file steps_ran run_rc

   subject="$(locate_help_step pre "${DM_HELP_STEPS_PRE:-}" "${test_dir}")"
   printf '%s\n' "INFO: subject: ${subject}"

   scratch_base="$(mktemp --directory)"
   stub_dir="${scratch_base}/steps"
   log_file="${scratch_base}/ran.log"
   extracted="${scratch_base}/cleanup_run.bsh"
   mkdir --parents -- "${stub_dir}"

   extract_cleanup_run "${subject}" "${extracted}"
   # shellcheck disable=SC1090
   source "${extracted}"

   dist_source_help_steps_folder="${stub_dir}"

   ## ---- each kind runs exactly its steps, in order ----

   make_stub_steps "${stub_dir}" "${log_file}" ""

   true > "${log_file}"
   exception_handler_cleanup_run unchroot_unmount "abort-on-failure"
   steps_ran="$(tr '\n' ' ' < "${log_file}")"
   require_steps "${steps_ran}" \
      "remove-local-temp-apt-repo unchroot-raw unprevent-daemons-from-starting unmount-raw " \
      "kind 'unchroot_unmount' runs its four steps in order"

   true > "${log_file}"
   exception_handler_cleanup_run unmount "abort-on-failure"
   steps_ran="$(tr '\n' ' ' < "${log_file}")"
   require_steps "${steps_ran}" "unmount-raw " "kind 'unmount' runs unmount-raw"

   true > "${log_file}"
   exception_handler_cleanup_run unmount_lb "abort-on-failure"
   steps_ran="$(tr '\n' ' ' < "${log_file}")"
   require_steps "${steps_ran}" "unmount-lb " "kind 'unmount_lb' runs unmount-lb"

   true > "${log_file}"
   exception_handler_cleanup_run general "abort-on-failure"
   steps_ran="$(tr '\n' ' ' < "${log_file}")"
   require_steps "${steps_ran}" "" "kind 'general' runs nothing"

   true > "${log_file}"
   exception_handler_cleanup_run some-unknown-kind "abort-on-failure"
   steps_ran="$(tr '\n' ' ' < "${log_file}")"
   require_steps "${steps_ran}" "" "unknown kind runs nothing"

   ## ---- failure policy ----

   ## The signal path is already exiting; a failing step must not stop the
   ## rest of the cleanup, or a leftover mount survives the abort.
   make_stub_steps "${stub_dir}" "${log_file}" "unchroot-raw"

   true > "${log_file}"
   run_rc=0
   exception_handler_cleanup_run unchroot_unmount "tolerate-failure" || run_rc="$?"
   steps_ran="$(tr '\n' ' ' < "${log_file}")"
   require_steps "${steps_ran}" \
      "remove-local-temp-apt-repo unchroot-raw unprevent-daemons-from-starting unmount-raw " \
      "the 'tolerate-failure' mode continues past a failing step"
   require_steps "${run_rc}" "0" "tolerate_failure 'true' returns success"

   ## The ERR path must see the failure instead of silently continuing.
   true > "${log_file}"
   run_rc=0
   exception_handler_cleanup_run unchroot_unmount "abort-on-failure" || run_rc="$?"
   steps_ran="$(tr '\n' ' ' < "${log_file}")"
   require_steps "${steps_ran}" "remove-local-temp-apt-repo unchroot-raw " \
      "tolerate_failure 'false' stops at the failing step"
   if [ ! "${run_rc}" = "0" ]; then
      pass "the 'abort-on-failure' mode propagates the failure (rc ${run_rc})"
   else
      fail "tolerate_failure 'false' swallowed the failure"
   fi

   safe-rm --recursive --force -- "${scratch_base}"

   if [ "${test_failures}" = "0" ]; then
      printf '%s\n' "OK: all pre cleanup-dispatch assertions passed."
      return 0
   fi
   printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
   return 1
}

main "$@"

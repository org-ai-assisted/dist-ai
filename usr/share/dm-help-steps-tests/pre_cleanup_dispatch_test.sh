#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for 'exception_handler_cleanup_run' in derivative-maker
## 'help-steps/pre': the single definition of which cleanup steps each error
## variant runs, shared by the ERR handlers and by exception_handler_signal,
## plus the step-registered cleanup callbacks it flushes.
##
## 'pre' cannot be sourced without a populated build environment, so the
## functions are EXTRACTED from it and exercised against stub steps that record
## the order they ran in. That keeps the dispatch table under test even though
## its home file is not testable as a whole.
##
## Asserts:
##   - each kind runs exactly its steps, in order
##   - 'general' and an unknown kind run no fixed steps
##   - the 'tolerate-failure' mode continues past a failing step (the signal path,
##     already exiting, must not let cleanup mask the signal)
##   - the 'abort-on-failure' mode propagates the failure (the ERR path)
##   - the step-registered cleanup callbacks run in registration order, exactly
##     once per process, and honor the failure mode (the ERR / signal / EXIT
##     paths each flush them after their fixed cleanup steps)
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

## Extract the named functions (each body from its opening line to the
## first column-0 '}') from '${subject}' into '${extracted}', so the test
## drives the REAL 'pre' code, not a reimplementation. cleanup_run is pulled
## for the fixed-dispatch assertions; the two registry functions for the
## registered-callback assertions.
extract_functions() {
   local subject extracted fn fn_body

   subject="$1"
   extracted="$2"
   shift 2
   true > "${extracted}"
   for fn in "$@"; do
      fn_body="$(sed -n "/^${fn}() {\$/,/^}\$/p" -- "${subject}")"
      if [ -z "${fn_body}" ]; then
         printf '%s\n' "ERROR: could not extract '${fn}' from '${subject}'." >&2
         return 1
      fi
      printf '%s\n' "${fn_body}" >> "${extracted}"
   done
}

## Create a stub for each named step; each appends its own name to the log.
## '$1' is the step that should exit non-zero, or "" for none.
make_stub_steps() {
   local stub_dir failing_step log_file step_name

   stub_dir="$1"
   log_file="$2"
   failing_step="$3"

   for step_name in remove-local-temp-apt-repo unchroot-raw \
      unprevent-daemons-from-starting unmount-raw; do
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

## Registered-cleanup stubs. They append to '${log_file}' (a main local,
## reached via bash dynamic scope when called from cleanup_run within main),
## so the step log shows whether -- and in what order -- a callback ran.
registered_callback_ok() {
   printf '%s\n' 'registered-callback' >> "${log_file}"
}
registered_callback_second() {
   printf '%s\n' 'second-callback' >> "${log_file}"
}
registered_callback_fail() {
   printf '%s\n' 'registered-callback' >> "${log_file}"
   return 3
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

   extract_functions "${subject}" "${extracted}" \
      exception_handler_register_cleanup \
      exception_handler_run_registered_cleanups \
      exception_handler_cleanup_run
   # shellcheck disable=SC1090
   source "${extracted}"

   ## Registry init, as 'pre' does at top level (not inside a function, so
   ## not captured by the extraction above).
   exception_handler_cleanup_functions=()

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
   ## unmount_lb was the live-build cleanup kind; the port off live-build removed
   ## it (help-steps/unmount-lb is deleted), so it must now dispatch to nothing
   ## like any other unrecognized kind -- this locks the removal against a revert.
   exception_handler_cleanup_run unmount_lb "abort-on-failure"
   steps_ran="$(tr '\n' ' ' < "${log_file}")"
   require_steps "${steps_ran}" "" "removed kind 'unmount_lb' runs nothing"

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

   ## ---- step-registered cleanup callbacks ----
   ##
   ## exception_handler_run_registered_cleanups is what lets
   ## 4350_reimage-raw-reproducible add its temp-dir teardown without hijacking
   ## the EXIT trap 'pre' owns. The ERR (exception_handler_variant), signal and
   ## normal-EXIT (exithandler) paths each flush it after the fixed steps; here
   ## the function is exercised directly.

   ## Registered callbacks run, in registration order.
   exception_handler_cleanup_functions=()
   exception_handler_cleanups_done=""
   true > "${log_file}"
   exception_handler_register_cleanup registered_callback_ok
   exception_handler_register_cleanup registered_callback_second
   exception_handler_run_registered_cleanups "tolerate-failure"
   steps_ran="$(tr '\n' ' ' < "${log_file}")"
   require_steps "${steps_ran}" "registered-callback second-callback " \
      "registered callbacks run, in registration order"

   ## Run-once guard: a second flush in the same process does not re-run them
   ## (ERR/signal then EXIT must not double-clean).
   exception_handler_run_registered_cleanups "tolerate-failure"
   steps_ran="$(tr '\n' ' ' < "${log_file}")"
   require_steps "${steps_ran}" "registered-callback second-callback " \
      "run-once guard: callbacks do not run twice"

   ## 'abort-on-failure' (the ERR path) propagates a failing callback.
   exception_handler_cleanup_functions=()
   exception_handler_cleanups_done=""
   true > "${log_file}"
   run_rc=0
   exception_handler_register_cleanup registered_callback_fail
   exception_handler_run_registered_cleanups "abort-on-failure" || run_rc="$?"
   if [ ! "${run_rc}" = "0" ]; then
      pass "the 'abort-on-failure' mode propagates a failing callback (rc ${run_rc})"
   else
      fail "abort-on-failure swallowed a failing callback"
   fi

   ## 'tolerate-failure' (the signal / EXIT path) swallows a failing callback.
   exception_handler_cleanup_functions=()
   exception_handler_cleanups_done=""
   true > "${log_file}"
   run_rc=0
   exception_handler_register_cleanup registered_callback_fail
   exception_handler_run_registered_cleanups "tolerate-failure" || run_rc="$?"
   require_steps "${run_rc}" "0" "the 'tolerate-failure' mode swallows a failing callback"

   safe-rm --recursive --force -- "${scratch_base}"

   if [ "${test_failures}" = "0" ]; then
      printf '%s\n' "OK: all pre cleanup-dispatch assertions passed."
      return 0
   fi
   printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
   return 1
}

main "$@"

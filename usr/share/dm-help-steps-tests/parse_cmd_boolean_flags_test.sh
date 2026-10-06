#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker help-steps/parse-cmd boolean flags:
##   - every boolean flag REQUIRES an explicit 'true'/'false' value and sets its
##     variable accordingly;
##   - parsing TERMINATES (the --skip-published-packages branch read its value but
##     never shifted -> infinite loop; every converted bare toggle had the same
##     latent shape);
##   - a missing/invalid value gives the actionable "supported options ... are
##     'true' or 'false'" error and exits, never a hang nor a 'shift count out of
##     range' crash;
##   - the parser advances past a valued flag to the next one.
##
## Drives the REAL parse-cmd two ways, both bounded by 'timeout' so a
## non-terminating arg loop surfaces as a FAIL instead of hanging the suite:
##   drive_var  -- SOURCE parse-cmd (via parse_cmd_source_driver.sh) and call the
##                 real function, read back one exported variable (value assertions);
##   run_err    -- EXECUTE the real parse-cmd with empty colors, capture combined
##                 output (error-message assertions).
## No parser logic is reimplemented. Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
parse_cmd="${PARSE_CMD:-${dm_checkout}/help-steps/parse-cmd}"
if [ ! -r "${parse_cmd}" ]; then
   printf '%s\n' "FATAL: parse-cmd not readable at '${parse_cmd}' (set DERIVATIVE_MAKER_DIR or PARSE_CMD)." >&2
   exit 1
fi
tests_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source_driver="${tests_dir}/parse_cmd_source_driver.sh"
if [ ! -r "${source_driver}" ]; then
   printf '%s\n' "FATAL: driver not readable at '${source_driver}'." >&2
   exit 1
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## $1 var to read back; rest = args. Prints the var value, or '__TIMEOUT__' if the
## parse hangs (the infinite-loop guard).
drive_var() {
   local var_name="$1"
   shift
   local out rc
   out="$(timeout --kill-after=5 10 bash "${source_driver}" "${parse_cmd}" "${var_name}" "" "$@")" && rc=0 || rc=$?
   ## 124 = killed by SIGTERM on timeout; 137 = killed by SIGKILL (--kill-after).
   if [ "${rc}" -eq 124 ] || [ "${rc}" -eq 137 ]; then
      printf '%s' '__TIMEOUT__'
      return 0
   fi
   printf '%s' "${out}"
}

## Execute the REAL parse-cmd; empty colors satisfy nounset, the dangerous unlock
## lets a dangerous flag reach value validation. Prints combined output, or
## '__TIMEOUT__' on a hang.
run_err() {
   local out rc
   out="$(timeout --kill-after=5 10 env -u CLAUDECODE red='' bold='' cyan='' eunder='' reset='' under='' dist_build_unlock_dangerous_options='true' "${parse_cmd}" "$@" 2>&1)" && rc=0 || rc=$?
   if [ "${rc}" -eq 124 ] || [ "${rc}" -eq 137 ]; then
      printf '%s' '__TIMEOUT__'
      return 0
   fi
   printf '%s' "${out}"
}

## $1 flag, $2 variable, $3 expected value for 'true', $4 expected value for 'false'.
check_valued_flag() {
   local flag="$1" var="$2" true_val="$3" false_val="$4" out

   out="$(drive_var "${var}" "${flag}" true)"
   if [ "${out}" = "${true_val}" ]; then
      pass "${flag} true -> ${var}='${true_val}' (terminates)"
   else
      fail "${flag} true: ${var}='${out}', expected '${true_val}'"
   fi

   out="$(drive_var "${var}" "${flag}" false)"
   if [ "${out}" = "${false_val}" ]; then
      pass "${flag} false -> ${var}='${false_val}' (terminates)"
   else
      fail "${flag} false: ${var}='${out}', expected '${false_val}'"
   fi

   out="$(run_err "${flag}" bogus)"
   case "${out}" in
      __TIMEOUT__)
         fail "${flag} bogus HANGS"
         ;;
      *"supported options for ${flag} are 'true' or 'false'"*)
         pass "${flag} bogus -> value error"
         ;;
      *)
         fail "${flag} bogus: no value error: ${out}"
         ;;
   esac

   ## flag as the LAST arg: missing value -> same actionable error, and the exit
   ## precedes 'shift 2' so there is no 'shift count out of range' crash.
   out="$(run_err "${flag}")"
   case "${out}" in
      __TIMEOUT__)
         fail "${flag} (missing value) HANGS"
         ;;
      *"supported options for ${flag} are 'true' or 'false'"*)
         pass "${flag} (missing value) -> value error, no shift crash"
         ;;
      *)
         fail "${flag} (missing value): no value error: ${out}"
         ;;
   esac
}

check_valued_flag --skip-published-packages         dist_build_skip_published_packages          true  false
check_valued_flag --skip-packages                   dist_build_skip_packages                    true  false
check_valued_flag --skip-prepare-build-machine      dist_build_skip_prepare_build_machine       true  false
check_valued_flag --skip-cowbuilder-setup           dist_build_skip_cowbuilder_setup            true  false
check_valued_flag --skip-local-dependencies         dist_build_skip_local_dependencies          true  false
check_valued_flag --reuse-cowbuilder-base           dist_build_reuse_cowbuilder_base            true  false
check_valued_flag --reproducible-dist-build-version dist_build_version_reproducible             true  false
check_valued_flag --testing-frozen-sources          dist_build_sources_list_primary             build_sources/debian_testing_frozen.sources UNSET

## --debug carries no parse-cmd variable (its xtrace effect lives in help-steps/pre,
## which runs earlier); assert the value is validated and the flag parses here.
debug_bogus="$(run_err --debug bogus)"
case "${debug_bogus}" in
   __TIMEOUT__)
      fail "--debug bogus HANGS"
      ;;
   *"supported options for --debug are 'true' or 'false'"*)
      pass "--debug bogus -> value error"
      ;;
   *)
      fail "--debug bogus: no value error: ${debug_bogus}"
      ;;
esac
debug_missing="$(run_err --debug)"
case "${debug_missing}" in
   *"supported options for --debug are 'true' or 'false'"*)
      pass "--debug (missing value) -> value error"
      ;;
   *)
      fail "--debug (missing value): no value error: ${debug_missing}"
      ;;
esac
for debug_value in true false; do
   debug_out="$(run_err --debug "${debug_value}")"
   case "${debug_out}" in
      __TIMEOUT__)
         fail "--debug ${debug_value} HANGS"
         ;;
      *"supported options for --debug"*)
         fail "--debug ${debug_value} wrongly rejected"
         ;;
      *)
         pass "--debug ${debug_value} parses (terminates past the flag)"
         ;;
   esac
done

## The parser advances past a valued flag and parses the following one: the
## preserve-following-flag check. On the pre-fix code --skip-published-packages
## true loops, so this times out (RED) instead of reaching --skip-packages.
preserve_out="$(drive_var dist_build_skip_packages --skip-published-packages true --skip-packages true)"
if [ "${preserve_out}" = "true" ]; then
   pass "--skip-published-packages true consumes its value; following --skip-packages true is parsed"
else
   fail "following flag not parsed after --skip-published-packages true: got '${preserve_out}'"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: parse-cmd boolean flags require true|false, parse without looping, preserve following flags."

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the SIMULATE-UPLOAD mode of the derivative-maker image build.
##
## WHAT IT GUARDS: a native test build (dm-image-build) has no release-server
## credentials, so dm-upload-images' rsync retries with linear backoff for ~7h and
## hangs the build. The WRONG fix (replaced) FULL-SKIPPED the upload -- it bypassed
## the whole upload code path (file-list build, target derivation, dm-prepare-release)
## instead of exercising it. The RIGHT fix runs the whole upload path but neutralizes
## only the transfer command, mirroring the existing build_dry_run mechanism:
##
##   dist_build_simulate_upload=true  ->  rsync_cmd="echo simulate-only rsync"
##
## distinct from build_dry_run (a broader dummy build that ALSO adds --dry-run to
## rsync_opts and produces empty-text images).
##
## Drives the REAL subjects, no synthetic copy:
##   - variables.d/35_rsync.bsh : the rsync_cmd selector dm-upload-images consumes
##     (sourced by it via help-steps/variables). This is where the build_dry_run
##     echo-no-op branch lives, so this is where the simulate branch is reused.
##   - help-steps/parse-cmd     : the --simulate-upload CLI option plumbing.
##   - help-steps/dm-build-official-one : the upload for-loop that the old full-skip
##     wrapped; asserted to be gate-free again (the canary that fails on the old skip).
##
## Needs no root, no network, no build.
##
## Subject selection (env override, else the checkout the dm-help-steps lane wires via
## DERIVATIVE_MAKER_DIR). A required subject absent is an environment bug (R-220) -> exit 1.

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

rsync_fragment="${DM_RSYNC_FRAGMENT:-${dm_checkout}/variables.d/35_rsync.bsh}"
parse_cmd="${DM_PARSE_CMD:-${dm_checkout}/help-steps/parse-cmd}"
build_official_one="${DM_BUILD_OFFICIAL_ONE:-${dm_checkout}/help-steps/dm-build-official-one}"

for required in "${rsync_fragment}" "${parse_cmd}" "${build_official_one}"; do
   if [ ! -r "${required}" ]; then
      printf '%s\n' "FATAL: required subject not readable: '${required}' (derivative-maker not checked out; set DERIVATIVE_MAKER_DIR)." >&2
      exit 1
   fi
done

## ---------------------------------------------------------------------------
## Part A: the REAL rsync_cmd selector (variables.d/35_rsync.bsh).
## ---------------------------------------------------------------------------

## Source the real fragment in a clean subshell under the given flags and print
## 'rsync_cmd|||rsync_opts'. The subshell isolates each run from the next.
## Args: $1 = build_dry_run value ('' leaves it unset), $2 = dist_build_simulate_upload.
rsync_select() {
   (
      unset rsync_cmd rsync_opts build_dry_run dist_build_simulate_upload
      ## Both are consumed by the sourced fragment (a non-literal path shellcheck
      ## cannot follow): SC2034 (set-but-unused), SC2030 (intended subshell-local).
      # shellcheck disable=SC2034
      [ -z "${1}" ] || build_dry_run="${1}"
      # shellcheck disable=SC2034,SC2030
      [ -z "${2}" ] || dist_build_simulate_upload="${2}"
      # shellcheck disable=SC1090
      source "${rsync_fragment}"
      ## Delimiter lives in the DATA, not the printf format (R-030).
      printf '%s\n' "${rsync_cmd:-UNSET}|||${rsync_opts:-UNSET}"
   )
}

simulate_result="$(rsync_select '' 'true')"
simulate_cmd="${simulate_result%%|||*}"
simulate_opts="${simulate_result#*|||}"

if [ "${simulate_cmd}" = "echo simulate-only rsync" ]; then
   pass "simulate-upload: rsync_cmd is the echo no-op (upload path runs, nothing transfers)"
else
   fail "simulate-upload: rsync_cmd is '${simulate_cmd}', expected 'echo simulate-only rsync'"
fi

## Distinct from build_dry_run: simulate-upload must NOT add the broad --dry-run to
## rsync_opts (that is the dummy-build behavior; simulate builds real images).
case "${simulate_opts}" in
   *--dry-run*)
      fail "simulate-upload leaked --dry-run into rsync_opts ('${simulate_opts}'); it must be distinct from build_dry_run"
      ;;
   *)
      pass "simulate-upload does not add --dry-run to rsync_opts (distinct from build_dry_run)"
      ;;
esac

## build_dry_run is the broader mode: same echo no-op, but ALSO --dry-run on rsync_opts.
dryrun_result="$(rsync_select 'true' '')"
dryrun_cmd="${dryrun_result%%|||*}"
dryrun_opts="${dryrun_result#*|||}"

if [ "${dryrun_cmd}" = "echo simulate-only rsync" ]; then
   pass "build_dry_run: rsync_cmd is the echo no-op"
else
   fail "build_dry_run: rsync_cmd is '${dryrun_cmd}', expected 'echo simulate-only rsync'"
fi
case "${dryrun_opts}" in
   *--dry-run*)
      pass "build_dry_run adds --dry-run to rsync_opts (proves the two modes differ)"
      ;;
   *)
      fail "build_dry_run did not add --dry-run to rsync_opts ('${dryrun_opts}')"
      ;;
esac

## CANARY: with neither flag the selector must choose the REAL rsync. Proves the
## echo-no-op assertions above are not vacuous (the selector CAN observe a real rsync),
## and would fail if simulate mode were ever wired as the default.
real_result="$(rsync_select '' '')"
real_cmd="${real_result%%|||*}"
if [ "${real_cmd}" = "rsync" ]; then
   pass "canary: no flag -> rsync_cmd is the real 'rsync'"
else
   fail "canary broken: no flag -> rsync_cmd is '${real_cmd}', not 'rsync'; the no-op assertions prove nothing"
fi

## ---------------------------------------------------------------------------
## Part B: the REAL --simulate-upload CLI plumbing (help-steps/parse-cmd).
## ---------------------------------------------------------------------------

## The reporting layer help-steps/pre would supply (empty colors + an aborting error())
## and the architecture list help-steps/variables would set. The subshell run of the
## parser inherits these.
export bold='' cyan='' eunder='' green='' red='' reset='' under=''
error() {
   printf '%s\n' "ERROR: $*" >&2
   exit 1
}
export -f error
# shellcheck disable=SC2034  # consumed by the sourced parse-cmd
architecture_all_list=( amd64 arm64 source )

parse_base_args=( --type host --target iso --flavor kicksecure-cli --arch amd64 --freshness current --freedom true )

## Run the REAL parser with the given extra args and print the resulting
## dist_build_simulate_upload. A parser abort (error()->exit) dies before printf, so
## the capture is empty; a nonzero return prints PARSE-FAILED. Either reads as a FAIL
## where 'true'/'false' is expected, so a bad parse never masquerades as a value.
simulate_var_after_parse() {
   (
      # shellcheck disable=SC1090
      source "${parse_cmd}"
      if dist_build_one_parse_cmd "${parse_base_args[@]}" "$@" >/dev/null 2>&1; then
         ## Set by the sourced parse-cmd inside this subshell; the SC2031 cross-subshell
         ## "might be lost" note is a false positive (the read is in the same subshell).
         # shellcheck disable=SC2031
         printf '%s' "${dist_build_simulate_upload:-UNSET}"
      else
         printf '%s' "PARSE-FAILED"
      fi
   )
}

parsed_true="$(simulate_var_after_parse --simulate-upload true)" || true
if [ "${parsed_true}" = "true" ]; then
   pass "parse-cmd: --simulate-upload true exports dist_build_simulate_upload=true"
else
   fail "parse-cmd: --simulate-upload true yielded '${parsed_true}', expected 'true'"
fi

parsed_false="$(simulate_var_after_parse --simulate-upload false)" || true
if [ "${parsed_false}" = "false" ]; then
   pass "parse-cmd: --simulate-upload false exports dist_build_simulate_upload=false"
else
   fail "parse-cmd: --simulate-upload false yielded '${parsed_false}', expected 'false'"
fi

## Omitted -> the var is left as the environment set it (unset here -> UNSET), so an
## env-provided value (dm-image-build's export) survives parse-cmd.
parsed_absent="$(simulate_var_after_parse)" || true
if [ "${parsed_absent}" = "UNSET" ]; then
   pass "parse-cmd: --simulate-upload omitted leaves dist_build_simulate_upload untouched"
else
   fail "parse-cmd: --simulate-upload omitted yielded '${parsed_absent}', expected 'UNSET'"
fi

## Bad value must be rejected (not silently accepted as a third state). parse-cmd
## rejects via 'error()'/exit, which kills the subshell before it can print -- so an
## EMPTY capture is the abort, and PARSE-FAILED the nonzero-return path; both are the
## rejection. Anything else (a 'true'/'false'/'UNSET' value) means it was accepted.
parsed_bogus="$(simulate_var_after_parse --simulate-upload bogus)" || true
case "${parsed_bogus}" in
   ''|PARSE-FAILED)
      pass "parse-cmd: --simulate-upload bogus is rejected"
      ;;
   *)
      fail "parse-cmd: --simulate-upload bogus yielded '${parsed_bogus}', expected rejection"
      ;;
esac

## ---------------------------------------------------------------------------
## Part C: the old FULL-SKIP must not return (help-steps/dm-build-official-one).
## ---------------------------------------------------------------------------

## CANARY against the replaced approach: the upload for-loop must run unconditionally,
## never be wrapped in a dist_build_skip_image_upload gate that bypasses the path.
if grep --quiet -- 'dist_build_skip_image_upload' "${build_official_one}"; then
   fail "dm-build-official-one still references dist_build_skip_image_upload (the old full-skip returned)"
else
   pass "dm-build-official-one has no dist_build_skip_image_upload full-skip gate"
fi

## ... and the upload loop it guards is actually present (so the assertion above is not
## vacuously green on an unrelated rewrite).
if grep --quiet -- 'run_cmd dm-upload-images' "${build_official_one}"; then
   pass "dm-build-official-one still invokes dm-upload-images (upload path present)"
else
   fail "dm-build-official-one no longer invokes dm-upload-images; the no-skip assertion is vacuous"
fi

## ---------------------------------------------------------------------------

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: simulate-upload runs the full upload path with the transfer neutralized."

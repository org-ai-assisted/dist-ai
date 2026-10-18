#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the UPLOAD mode of the derivative-maker image build.
##
## Upload is SIMULATED by default; a real upload is an explicit opt-in,
## '--upload true'. A test/install build with no release-server credentials must
## not attempt a real transfer (dm-upload-images' rsync would retry with linear
## backoff for ~7h). '$dist_build_upload' is the SINGLE source of truth:
##
##   dist_build_upload=true AND not CI  ->  rsync_cmd="rsync"       (real upload)
##   otherwise                          ->  rsync_cmd="echo simulate-only rsync"
##
## The full upload code path (file-list, target derivation, dm-prepare-release)
## runs in BOTH cases; only the transfer command differs. Distinct from
## build_dry_run, which ALSO adds '--dry-run' to rsync_opts and builds dummy
## images.
##
## Drives the REAL subjects, no synthetic copy:
##   - variables.d/35_rsync.bsh : the rsync_cmd selector dm-upload-images consumes.
##   - help-steps/parse-cmd     : the --upload CLI option plumbing.
##   - help-steps/dm-build-official-one : the upload for-loop must stay gate-free
##     (canary against the old full-skip).
##
## Needs no root, no network, no build. A required subject absent is an
## environment bug (R-220) -> exit 1.

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

## Source the real fragment in a clean subshell under the given inputs and print
## 'rsync_cmd|||rsync_opts'. The subshell isolates each run.
## Args: $1 dist_build_upload, $2 CI, $3 build_dry_run, $4
## build_remote_derivative_pkgs, $5 a PRE-SET rsync_cmd ('' leaves each unset).
rsync_select() {
   (
      unset rsync_cmd rsync_opts build_dry_run dist_build_upload CI build_remote_derivative_pkgs
      ## Consumed by the sourced fragment (a path shellcheck cannot follow):
      ## SC2034 (set-but-unused here), SC2030 (intended subshell-local).
      # shellcheck disable=SC2034,SC2030
      [ -z "${1}" ] || dist_build_upload="${1}"
      # shellcheck disable=SC2034,SC2030
      [ -z "${2}" ] || CI="${2}"
      # shellcheck disable=SC2034,SC2030
      [ -z "${3}" ] || build_dry_run="${3}"
      # shellcheck disable=SC2034,SC2030
      [ -z "${4:-}" ] || build_remote_derivative_pkgs="${4}"
      # shellcheck disable=SC2034,SC2030
      [ -z "${5:-}" ] || rsync_cmd="${5}"
      # shellcheck disable=SC1090
      source "${rsync_fragment}"
      ## Delimiter lives in the DATA, not the printf format (R-030).
      printf '%s\n' "${rsync_cmd:-UNSET}|||${rsync_opts:-UNSET}"
   )
}

real_result="$(rsync_select 'true' '' '')"
real_cmd="${real_result%%|||*}"
if [ "${real_cmd}" = "rsync" ]; then
   pass "--upload true (not CI): rsync_cmd is the real 'rsync'"
else
   fail "--upload true: rsync_cmd is '${real_cmd}', expected 'rsync'"
fi

## CANARY: the default MUST simulate (safe-by-default). Also proves the real-rsync
## assertion above is not vacuous.
default_result="$(rsync_select '' '' '')"
default_cmd="${default_result%%|||*}"
if [ "${default_cmd}" = "echo simulate-only rsync" ]; then
   pass "canary: default (no --upload) simulates -- rsync_cmd is the echo no-op"
else
   fail "canary broken: default rsync_cmd is '${default_cmd}', not the echo no-op (upload is not safe-by-default)"
fi

## Explicit opt-out yields the same simulate as the default (not a third state).
false_cmd="$(rsync_select 'false' '' '')"
false_cmd="${false_cmd%%|||*}"
if [ "${false_cmd}" = "echo simulate-only rsync" ]; then
   pass "--upload false: rsync_cmd is the echo no-op"
else
   fail "--upload false: rsync_cmd is '${false_cmd}', expected the echo no-op"
fi

## CI hard-block: even '--upload true' must NOT upload from CI (fail-closed).
ci_cmd="$(rsync_select 'true' 'true' '')"
ci_cmd="${ci_cmd%%|||*}"
if [ "${ci_cmd}" = "echo simulate-only rsync" ]; then
   pass "CI hard-block: --upload true + CI=true still simulates"
else
   fail "CI hard-block broken: --upload true + CI yielded '${ci_cmd}', expected the echo no-op"
fi

## Fail-closed over --upload true: a dry-run and a remote-derivative-packages build
## must NOT upload even when the operator passes --upload true.
dryrun_upload_cmd="$(rsync_select 'true' '' 'true')"
dryrun_upload_cmd="${dryrun_upload_cmd%%|||*}"
if [ "${dryrun_upload_cmd}" = "echo simulate-only rsync" ]; then
   pass "fail-closed: --upload true + build_dry_run=true still simulates"
else
   fail "fail-closed broken: --upload true + build_dry_run yielded '${dryrun_upload_cmd}' (a dry-run must not upload)"
fi
remote_upload_cmd="$(rsync_select 'true' '' '' 'true')"
remote_upload_cmd="${remote_upload_cmd%%|||*}"
if [ "${remote_upload_cmd}" = "echo simulate-only rsync" ]; then
   pass "fail-closed: --upload true + build_remote_derivative_pkgs=true still simulates"
else
   fail "fail-closed broken: --upload true + remote pkgs yielded '${remote_upload_cmd}' (opaque prebuilt must not be published)"
fi

## Fail-closed BEATS a pre-set rsync_cmd: a pre-set real 'rsync' must still be
## forced to the no-op on CI (the old unconditional CI override, preserved).
preset_ci_cmd="$(rsync_select 'true' 'true' '' '' 'rsync')"
preset_ci_cmd="${preset_ci_cmd%%|||*}"
if [ "${preset_ci_cmd}" = "echo simulate-only rsync" ]; then
   pass "fail-closed: pre-set rsync_cmd=rsync is overridden to the no-op on CI"
else
   fail "fail-closed broken: pre-set rsync_cmd survived CI ('${preset_ci_cmd}') -- CI can publish"
fi

## ... but a pre-set rsync_cmd WINS when no fail-closed mode applies (the hermetic
## localhost-sshd upload test relies on overriding rsync_cmd this way).
preset_ok_cmd="$(rsync_select '' '' '' '' 'rsync -e ssh-localhost')"
preset_ok_cmd="${preset_ok_cmd%%|||*}"
if [ "${preset_ok_cmd}" = "rsync -e ssh-localhost" ]; then
   pass "pre-set rsync_cmd wins when not CI/dry-run/remote (test-override path)"
else
   fail "pre-set rsync_cmd was clobbered ('${preset_ok_cmd}') -- the override path is broken"
fi

## build_dry_run is the broader mode: echo no-op AND --dry-run on rsync_opts.
dryrun_result="$(rsync_select '' '' 'true')"
dryrun_cmd="${dryrun_result%%|||*}"
dryrun_opts="${dryrun_result#*|||}"
if [ "${dryrun_cmd}" = "echo simulate-only rsync" ]; then
   pass "build_dry_run: rsync_cmd is the echo no-op"
else
   fail "build_dry_run: rsync_cmd is '${dryrun_cmd}', expected the echo no-op"
fi
case "${dryrun_opts}" in
   *--dry-run*)
      pass "build_dry_run adds --dry-run to rsync_opts (distinct from --upload simulate)"
      ;;
   *)
      fail "build_dry_run did not add --dry-run to rsync_opts ('${dryrun_opts}')"
      ;;
esac

## --- the simulate default must NOT add --dry-run to rsync_opts -------------
case "${default_result#*|||}" in
   *--dry-run*)
      fail "default simulate leaked --dry-run into rsync_opts; it must be distinct from build_dry_run"
      ;;
   *)
      pass "default simulate does not add --dry-run to rsync_opts (distinct from build_dry_run)"
      ;;
esac

## ---------------------------------------------------------------------------
## Part B: the REAL --upload CLI plumbing (help-steps/parse-cmd).
## ---------------------------------------------------------------------------

## The reporting layer help-steps/pre would supply (empty colors + an aborting
## error()) and the architecture list help-steps/variables would set.
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
## dist_build_upload. A parser abort (error()->exit) dies before printf, so the
## capture is empty; a nonzero return prints PARSE-FAILED. Either reads as a FAIL
## where 'true'/'false' is expected, so a bad parse never masquerades as a value.
upload_var_after_parse() {
   (
      # shellcheck disable=SC1090
      source "${parse_cmd}"
      if dist_build_one_parse_cmd "${parse_base_args[@]}" "$@" >/dev/null 2>&1; then
         # shellcheck disable=SC2031
         printf '%s' "${dist_build_upload:-UNSET}"
      else
         printf '%s' "PARSE-FAILED"
      fi
   )
}

parsed_true="$(upload_var_after_parse --upload true)" || true
if [ "${parsed_true}" = "true" ]; then
   pass "parse-cmd: --upload true exports dist_build_upload=true"
else
   fail "parse-cmd: --upload true yielded '${parsed_true}', expected 'true'"
fi

parsed_false="$(upload_var_after_parse --upload false)" || true
if [ "${parsed_false}" = "false" ]; then
   pass "parse-cmd: --upload false exports dist_build_upload=false"
else
   fail "parse-cmd: --upload false yielded '${parsed_false}', expected 'false'"
fi

## Omitted -> left as the environment set it (unset here -> UNSET): the default
## (simulate) is decided downstream by 35_rsync.bsh, not by parse-cmd.
parsed_absent="$(upload_var_after_parse)" || true
if [ "${parsed_absent}" = "UNSET" ]; then
   pass "parse-cmd: --upload omitted leaves dist_build_upload untouched"
else
   fail "parse-cmd: --upload omitted yielded '${parsed_absent}', expected 'UNSET'"
fi

## Bad value must be rejected (not silently accepted as a third state).
parsed_bogus="$(upload_var_after_parse --upload bogus)" || true
case "${parsed_bogus}" in
   ''|PARSE-FAILED)
      pass "parse-cmd: --upload bogus is rejected"
      ;;
   *)
      fail "parse-cmd: --upload bogus yielded '${parsed_bogus}', expected rejection"
      ;;
esac

## ---------------------------------------------------------------------------
## Part C: the old FULL-SKIP must not return (help-steps/dm-build-official-one).
## ---------------------------------------------------------------------------

## CANARY against the replaced approach: the upload for-loop must run
## unconditionally, never be wrapped in a dist_build_skip_image_upload gate.
if grep --quiet -- 'dist_build_skip_image_upload' "${build_official_one}"; then
   fail "dm-build-official-one still references dist_build_skip_image_upload (the old full-skip returned)"
else
   pass "dm-build-official-one has no dist_build_skip_image_upload full-skip gate"
fi

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
printf '%s\n' "OK: upload mode -- simulate by default, real upload opt-in, full upload path exercised."

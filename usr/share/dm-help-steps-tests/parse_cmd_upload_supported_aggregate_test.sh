#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/parse-cmd':
## 'dist_build_image_upload_supported' must AGGREGATE across multiple '--target'
## rather than be overwritten by the last arm.
##
## THE BUG IT GUARDS: each '--target' arm set the flag unconditionally (true for
## virtualbox/qcow2/iso/windows/source, false for utm/raw/root), so with more than
## one '--target' the LAST one won:
##   --target iso --target raw  -> false
##   --target raw --target iso  -> true
## dm-upload-images gates the WHOLE upload on this one flag, so a supported target
## silently lost its upload to a later unsupported one, purely by argument order
## (dm-build-official-one passes 'dist_build_multi_target_list' as several --target
## to one dm-upload-images). Fixed by making the flag sticky-true.
##
## Drives the REAL parse-cmd (sourced), only stubbing the color/error layer
## help-steps/pre would supply and the architecture_all_list help-steps/variables
## would set. Needs no root, no network, no build.

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
parse_cmd="${DM_PARSE_CMD:-${dm_checkout}/help-steps/parse-cmd}"
if [ ! -r "${parse_cmd}" ]; then
   printf '%s\n' "FATAL: parse-cmd not found/readable at '${parse_cmd}' (set DM_PARSE_CMD or DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

pass() { printf '%s\n' "PASS: $*"; }
test_failures=0
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## The reporting layer help-steps/pre would supply (empty colors + an error() that
## prints and aborts) and the architecture list help-steps/variables would set.
## Defined once at top level; each subshell run of the parser inherits them.
export bold='' cyan='' eunder='' green='' red='' reset='' under=''
error() {
   printf 'ERROR: %s\n' "$*" >&2
   exit 1
}
export -f error
architecture_all_list=( amd64 arm64 source )

## Run the REAL parser in a subshell with a full, valid argument set and print the
## resulting 'dist_build_image_upload_supported'. The subshell isolates parse-cmd's
## strict-mode and any error()/exit from this test and from the other runs.
##
## A FAILED parse must never read as a value: if the parser returns nonzero, emit a
## 'PARSE-FAILED' sentinel (not the possibly-half-set flag) so the assertions FAIL
## rather than pass on a bad parse; if it aborts via exit() (the real error() path),
## the subshell dies before printf and the capture is empty -- the '|| true' at each
## call site keeps the script from aborting under errexit, and empty likewise FAILs.
upload_supported_for() {
   (
      # shellcheck disable=SC1090
      source "${parse_cmd}"
      if dist_build_one_parse_cmd "$@" >/dev/null 2>&1; then
         printf '%s' "${dist_build_image_upload_supported:-UNSET}"
      else
         printf 'PARSE-FAILED'
      fi
   )
}

base_args=( --flavor kicksecure-cli --arch amd64 --freshness current --freedom true )

## --- the fix: order must NOT matter; a supported target keeps the flag true ----
iso_then_raw="$( upload_supported_for --type host --target iso --target raw "${base_args[@]}" )" || true
case "${iso_then_raw}" in
   true)
      pass "--target iso --target raw keeps upload_supported=true"
      ;;
   *)
      fail "--target iso --target raw yielded upload_supported='${iso_then_raw}' (a later unsupported target flipped it back)"
      ;;
esac

raw_then_iso="$( upload_supported_for --type host --target raw --target iso "${base_args[@]}" )" || true
case "${raw_then_iso}" in
   true)
      pass "--target raw --target iso keeps upload_supported=true"
      ;;
   *)
      fail "--target raw --target iso yielded upload_supported='${raw_then_iso}'"
      ;;
esac

## Order independence stated directly.
if [ "${iso_then_raw}" = "${raw_then_iso}" ]; then
   pass "upload_supported is argument-order-independent for iso+raw"
else
   fail "upload_supported depends on --target order: iso+raw='${iso_then_raw}' vs raw+iso='${raw_then_iso}'"
fi

## --- CANARY: a pure-unsupported target set must still read false ---------------
## Proves the probe can OBSERVE a false result, so the assertions above are not
## vacuously green; and it is the correct semantics (nothing to upload).
raw_only="$( upload_supported_for --type vm --target raw "${base_args[@]}" )" || true
case "${raw_only}" in
   false)
      pass "canary: --target raw alone reads upload_supported=false"
      ;;
   *)
      fail "canary broken: --target raw alone read '${raw_only}', not false; the true-assertions above prove nothing"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: upload_supported aggregates across --target."

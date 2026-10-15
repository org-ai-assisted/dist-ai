#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## persistence-setup is NON-INTERACTIVE: driven by mandatory flags, no prompts.
## This drives the REAL script (sourced; its main() is behind a was_executed
## guard so sourcing does not run it) and asserts the ARGUMENT-VALIDATION layer:
## --encrypt is mandatory, the --key-type combo rules, and the mutually-exclusive
## checks. Validation runs BEFORE any device is touched, and even valid args stop
## at a later safe gate (preflight / as_root / rd.live.image) on this non-live,
## non-root host -- so no case can reach systemd-repart. No root, no device, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""
if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   subject="${LIVE_CONFIG_DIST_REPO}/usr/bin/persistence-setup"
else
   subject='/usr/bin/persistence-setup'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not found: ${subject}" >&2
   printf '%s\n' "set LIVE_CONFIG_DIST_REPO to a live-config-dist checkout, or install live-config-dist" >&2
   exit 1
fi

## persistence-setup sources helper-scripts via HELPER_SCRIPTS_PATH; derive it
## from the sibling checkout when the suite did not wire it.
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -z "${HELPER_SCRIPTS_PATH}" ] && [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   HELPER_SCRIPTS_PATH="$(dirname -- "${LIVE_CONFIG_DIST_REPO}")/helper-scripts"
fi
export HELPER_SCRIPTS_PATH

# shellcheck disable=SC1090
source "${subject}"

if [ ! "$(type -t main)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' defined no 'main' function" >&2
   exit 1
fi

pass_count=0
fail_count=0

## Run main in a SUBSHELL so its globals never leak between cases and a die's
## exit ends only the subshell. Captures combined output + exit code.
run_main() {
   main_rc=0
   main_out="$( ( main "$@" ) 2>&1 )" || main_rc=$?
}

## A validation rejection: non-zero exit AND the message contains the needle.
check_rejects() {
   local desc needle
   desc="$1"
   needle="$2"
   shift 2
   run_main "$@"
   if [ "${main_rc}" -ne 0 ] && [[ "${main_out}" == *"${needle}"* ]]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${desc}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${desc} (rc=${main_rc} out='${main_out}')"
   fi
}

## Validation PASSED: the run stopped at a later, safe post-validation gate
## (missing dependency / not root / not live), never a validation message.
check_passes_validation() {
   local desc
   desc="$1"
   shift
   run_main "$@"
   if [ "${main_rc}" -ne 0 ] \
      && [[ "${main_out}" != *"mandatory"* ]] \
      && [[ "${main_out}" != *"meaningless"* ]] \
      && [[ "${main_out}" != *"unknown method"* ]] \
      && [[ "${main_out}" != *"requires"* ]] \
      && [[ "${main_out}" != *"selected no method"* ]]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${desc}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${desc} (rc=${main_rc} out='${main_out}')"
   fi
}

## --- mandatory --encrypt ---------------------------------------------------
check_rejects "missing --encrypt is rejected" "--encrypt is mandatory"
check_rejects "non-boolean --encrypt is rejected" "Option 'encrypt' cannot be 'maybe'" --encrypt maybe

## --- key-type rules (encrypt true) -----------------------------------------
check_rejects "--encrypt true without --key-type" "--key-type is mandatory" --encrypt true
check_rejects "--key-type password without --passphrase-file" "requires --passphrase-file" \
   --encrypt true --key-type password
check_rejects "--key-type keyfile without --keyfile" "requires --keyfile" \
   --encrypt true --key-type keyfile
check_rejects "unknown --key-type method" "unknown method" \
   --encrypt true --key-type bogus --passphrase-file /dev/null

## --- forbidden with encrypt false ------------------------------------------
check_rejects "--key-type with --encrypt false" "meaningless" \
   --encrypt false --key-type password
check_rejects "--passphrase-file with --encrypt false" "meaningless" \
   --encrypt false --passphrase-file /dev/null

## --- target/device ---------------------------------------------------------
check_rejects "--target disk without --device" "requires --device" \
   --encrypt false --target disk

## --- keyfile size floor (a 1-byte/newline key is trivially weak) -----------
tiny_keyfile="$(mktemp)"
printf '%s\n' "" > "${tiny_keyfile}"
check_rejects "tiny keyfile is rejected" "too small" \
   --encrypt true --key-type keyfile --keyfile "${tiny_keyfile}"
safe-rm --force -- "${tiny_keyfile}"

## --- valid combinations pass validation (stop at a later safe gate) --------
check_passes_validation "valid: --encrypt false" --encrypt false
check_passes_validation "valid: password" \
   --encrypt true --key-type password --passphrase-file /dev/null
check_passes_validation "valid: password,tpm combo" \
   --encrypt true --key-type password,tpm --passphrase-file /dev/null

printf '%s\n' ""
printf '%s\n' "===== persistence-setup arg validation: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]

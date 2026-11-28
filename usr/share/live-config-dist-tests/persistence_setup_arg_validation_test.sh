#!/bin/bash

## These globals cross the sourced-subject boundary (set here, read by the
## subject's validate_encryption_args) or come from the subject (default_luks_uuid,
## persist_type_guid_*), so shellcheck cannot see their use/assignment.
# shellcheck disable=SC2034,SC2154

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## persistence-setup validates its encryption arguments in validate_encryption_args(),
## a seam extracted from main() so the rules can be exercised without as_root /
## live-mode / a device. This sources the REAL script (its main() is behind a
## was_executed guard, so sourcing defines functions without running anything),
## sets the argument globals, and calls validate_encryption_args() in a subshell
## (a die ends only the subshell). Regressions covered:
##   * org-ai-assisted/live-config-dist#3 (h84): --passphrase-file '-' (stdin) must
##     NOT be rejected by the file-readability check.
##   * org-ai-assisted/live-config-dist#3 (h87): an omitted --luks-uuid must get the
##     default BEFORE the UUID-format validation, not die on the empty string.
## No root, no device, no network.

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

[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -z "${HELPER_SCRIPTS_PATH}" ] && [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   HELPER_SCRIPTS_PATH="$(dirname -- "${LIVE_CONFIG_DIST_REPO}")/helper-scripts"
fi
export HELPER_SCRIPTS_PATH

# shellcheck disable=SC1090
source "${subject}"

if [ ! "$(type -t validate_encryption_args)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' defined no 'validate_encryption_args'" >&2
   exit 1
fi

work="$(mktemp --directory --tmpdir persistence-setup-argval.XXXXXX)"
# shellcheck disable=SC2317  ## EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## A real, adequately-sized keyfile and passphrase file for the valid cases.
good_keyfile="${work}/keyfile"; head --bytes=64 /dev/zero | tr '\0' 'k' > "${good_keyfile}"
good_passfile="${work}/passfile"; printf '%s\n' 'swordfish' > "${good_passfile}"

pass_count=0
fail_count=0

## read_passphrase does real I/O; isolate it so the VALIDATION logic is what is
## under test. It mirrors the real behaviour: '-' reads stdin, else reads the file.
# shellcheck disable=SC2317  ## invoked by validate_encryption_args
read_passphrase() {
   if [ "${passphrase_file}" = '-' ]; then
      IFS= read -r passphrase || true
   else
      IFS= read -r passphrase < "${passphrase_file}" || true
   fi
}

## Reset all encryption-arg globals to a known base before each case.
reset_globals() {
   do_encrypt='true'; passphrase_file=''; keyfile=''; luks_uuid=''
   use_tpm='false'; passphrase=''; persist_type_guid=''
}

## Run validate_encryption_args in a subshell, capturing rc + combined output and,
## when it returns 0, the resolved luks_uuid / persist_type_guid. $1 = stdin text.
run_validate() {
   local stdin_data="${1:-}"
   rc=0
   ## '|| rc=$?' both captures a die's exit status and suppresses the test's
   ## own errexit on the assignment.
   out="$(
      ( validate_encryption_args \
         && printf '%s\n' "RESOLVED_UUID=${luks_uuid}" "RESOLVED_GUID=${persist_type_guid}" \
      ) 2>&1 <<< "${stdin_data}"
   )" || rc=$?
}

check() {
   if [ "$2" = 'true' ]; then
      pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1 (rc=${rc} out='${out}')"
   fi
}

## --- h87 REGRESSION: default luks uuid applied BEFORE validation ------------
reset_globals; passphrase_file="${good_passfile}"
run_validate
## Must NOT die on the empty uuid; must resolve to the built-in default.
check "h87: omitted --luks-uuid passes validation (not 'must be a UUID')" \
   "$( [ "${rc}" -eq 0 ] && [[ "${out}" != *'must be a UUID'* ]] && printf '%s' true || printf '%s' false )"
check "h87: omitted --luks-uuid resolves to default_luks_uuid" \
   "$( [[ "${out}" == *"RESOLVED_UUID=${default_luks_uuid}"* ]] && printf '%s' true || printf '%s' false )"

## An explicit, valid uuid still overrides the default.
reset_globals; passphrase_file="${good_passfile}"; luks_uuid='12345678-1234-1234-1234-1234567890ab'
run_validate
check "h87: explicit valid --luks-uuid overrides the default" \
   "$( [ "${rc}" -eq 0 ] && [[ "${out}" == *'RESOLVED_UUID=12345678-1234-1234-1234-1234567890ab'* ]] && printf '%s' true || printf '%s' false )"

## A malformed explicit uuid is still rejected.
reset_globals; passphrase_file="${good_passfile}"; luks_uuid='not-a-uuid'
run_validate
check "malformed explicit --luks-uuid is rejected" \
   "$( [ "${rc}" -ne 0 ] && [[ "${out}" == *'must be a UUID'* ]] && printf '%s' true || printf '%s' false )"

## --- h84 REGRESSION: --passphrase-file '-' (stdin) not rejected -------------
reset_globals; passphrase_file='-'
run_validate 'from-stdin-secret'
check "h84: --passphrase-file '-' is not rejected as unreadable" \
   "$( [ "${rc}" -eq 0 ] && [[ "${out}" != *'does not exist or cannot be read'* ]] && printf '%s' true || printf '%s' false )"

## A real but unreadable passphrase file IS still rejected.
reset_globals; passphrase_file="${work}/nope-does-not-exist"
run_validate
check "nonexistent --passphrase-file is rejected" \
   "$( [ "${rc}" -ne 0 ] && [[ "${out}" == *'does not exist or cannot be read'* ]] && printf '%s' true || printf '%s' false )"

## --- unchanged rules still hold --------------------------------------------
reset_globals; passphrase_file=''; keyfile=''
run_validate
check "encrypt true with neither passphrase nor keyfile is rejected" \
   "$( [ "${rc}" -ne 0 ] && [[ "${out}" == *'Cannot proceed'* ]] && printf '%s' true || printf '%s' false )"

## --use-tpm is not a primary unlock method: tpm alone (no passphrase/keyfile) is
## refused, and the tpm-specific hint fires. A portable overlay cannot be TPM-only.
## The hint is a 'log info', suppressed at the default notice level -- raise the
## level so the tpm-specific branch (not just the generic refusal) is observed.
reset_globals; passphrase_file=''; keyfile=''; use_tpm='true'
log_level='info'
run_validate
log_level='notice'
check "tpm-only (use-tpm without a passphrase/keyfile) is rejected with the tpm hint" \
   "$( [ "${rc}" -ne 0 ] && [[ "${out}" == *'Cannot proceed'* ]] && [[ "${out}" == *'cannot be used as an encryption method by itself'* ]] && printf '%s' true || printf '%s' false )"

reset_globals; keyfile="${good_keyfile}"
run_validate
check "valid keyfile passes and selects the LUKS type GUID" \
   "$( [ "${rc}" -eq 0 ] && [[ "${out}" == *"RESOLVED_GUID=${persist_type_guid_luks}"* ]] && printf '%s' true || printf '%s' false )"

tiny="${work}/tiny"; printf '%s' 'x' > "${tiny}"
reset_globals; keyfile="${tiny}"
run_validate
check "undersized keyfile is rejected" \
   "$( [ "${rc}" -ne 0 ] && [[ "${out}" == *'too small'* ]] && printf '%s' true || printf '%s' false )"

reset_globals; do_encrypt='false'; keyfile="${good_keyfile}"
run_validate
check "encrypt false with an encryption option is rejected" \
   "$( [ "${rc}" -ne 0 ] && [[ "${out}" == *'encryption-specific option'* ]] && printf '%s' true || printf '%s' false )"

reset_globals; do_encrypt='false'
run_validate
check "encrypt false with no encryption options selects the plain type GUID" \
   "$( [ "${rc}" -eq 0 ] && [[ "${out}" == *"RESOLVED_GUID=${persist_type_guid_plain}"* ]] && printf '%s' true || printf '%s' false )"

printf '%s\n' ""
printf '%s\n' "===== persistence-setup arg validation: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the four dist-ai GitHub-JSON readers that map an API
## response on stdin to one id (or a TSV list):
##   dm-boot-local-select-run.py, dm-boot-local-select-artifact.py,
##   dm-repro-run-id.py, dm-repro-artifact-list.py.
##
## THE CONTRACT: the stdin body is a NETWORK payload whose shape is not
## guaranteed. A GitHub error object ({"message": "rate limit ..."}), a bare
## list/null from an intercepting proxy or an error page, a truncated read, or a
## partial entry missing a field must all yield NO id and exit 0 -- the shell
## callers (dm-boot-local, dm-repro-verify-against-ci) read an empty result as
## "no run/artifact found" and print their own diagnostic. A stack-trace crash
## instead aborts the whole tool under the caller's errexit. rc is captured so a
## crash reads as a FAIL, not an errexit abort of this suite.
##
## Needs no root, no network.

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

## Resolve a reader named '$1' (first hit wins): the env override '$2', the
## in-tree copy, then the installed path.
locate_reader() {
   local reader_name="$1" env_override="$2" candidate
   for candidate in \
      "${env_override}" \
      "${test_dir}/../../libexec/dist-ai/${reader_name}" \
      "/usr/libexec/dist-ai/${reader_name}"
   do
      [ -n "${candidate}" ] || continue
      if [ -r "${candidate}" ]; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   printf '%s\n' "FATAL: ${reader_name} not found (set its env override)." >&2
   exit 1
}

select_run="$(locate_reader dm-boot-local-select-run.py "${DM_BOOT_LOCAL_SELECT_RUN:-}")"
select_artifact="$(locate_reader dm-boot-local-select-artifact.py "${DM_BOOT_LOCAL_SELECT_ARTIFACT:-}")"
repro_run_id="$(locate_reader dm-repro-run-id.py "${DM_REPRO_RUN_ID:-}")"
repro_artifact_list="$(locate_reader dm-repro-artifact-list.py "${DM_REPRO_ARTIFACT_LIST:-}")"

## $1 label, $2 want-stdout, $3 rc, $4 got-stdout.
expect() {
   local label="$1" want="$2" rc="$3" got="$4"
   if [ "${rc}" -eq 0 ] && [ "${got}" = "${want}" ]; then
      pass "${label}"
   else
      fail "${label}: rc=${rc} want=[${want}] got=[${got}]"
   fi
}

## Feed each malformed / unexpected-shape body to reader '$1' and assert no
## output and exit 0. IMAGE_TYPE is set for every reader (harmless to those that
## ignore it). '{"workflow_runs":"x"}' / '{"artifacts":"x"}' cover the
## right-key-wrong-type shape that a per-item field access crashes on.
assert_no_crash() {
   local reader="$1" bad rc got
   for bad in \
      '{"message":"API rate limit exceeded for x."}' \
      'null' \
      '[]' \
      'not json' \
      '{"workflow_runs":"x"}' \
      '{"artifacts":"x"}' \
      '{"workflow_runs":[null,3]}' \
      '{"artifacts":[null,3]}'
   do
      rc=0
      got="$(printf '%s' "${bad}" | IMAGE_TYPE=qcow2 "${reader}" 2>/dev/null)" || rc=$?
      if [ "${rc}" -eq 0 ] && [ -z "${got}" ]; then
         pass "$(basename -- "${reader}"): no crash, no output on: ${bad}"
      else
         fail "$(basename -- "${reader}"): crashed/emitted (rc=${rc} out=[${got}]) on: ${bad}"
      fi
   done
}

tab="$(printf '\t')"

## --- dm-boot-local-select-run.py ---------------------------------------------
rc=0
got="$(printf '%s' '{"workflow_runs":[{"name":"Build","conclusion":"success","id":12345}]}' \
   | "${select_run}")" || rc=$?
expect "select-run: newest successful Build run id" "12345" "${rc}" "${got}"

## Skips a non-matching name and a non-success run; picks the Boot Test success.
rc=0
got="$(printf '%s' '{"workflow_runs":[{"name":"Lint","conclusion":"success","id":1},{"name":"Boot Test","conclusion":"failure","id":2},{"name":"Boot Test","conclusion":"success","id":99}]}' \
   | "${select_run}")" || rc=$?
expect "select-run: selects the matching successful run only" "99" "${rc}" "${got}"
assert_no_crash "${select_run}"

## --- dm-boot-local-select-artifact.py ----------------------------------------
rc=0
got="$(printf '%s' '{"artifacts":[{"name":"boot-image-qcow2","expired":false,"id":7}]}' \
   | IMAGE_TYPE=qcow2 "${select_artifact}")" || rc=$?
expect "select-artifact: unexpired matching artifact id" "7" "${rc}" "${got}"

## An entry missing 'expired' (partial API response) must NOT crash; absent ->
## treated as live, like every other .get() default.
rc=0
got="$(printf '%s' '{"artifacts":[{"name":"boot-image-qcow2","id":8}]}' \
   | IMAGE_TYPE=qcow2 "${select_artifact}")" || rc=$?
expect "select-artifact: entry missing 'expired' does not crash" "8" "${rc}" "${got}"

## An expired-only match yields no id (empty stdout), exit 0.
rc=0
got="$(printf '%s' '{"artifacts":[{"name":"boot-image-qcow2","expired":true,"id":9}]}' \
   | IMAGE_TYPE=qcow2 "${select_artifact}" 2>/dev/null)" || rc=$?
expect "select-artifact: expired-only match yields no id" "" "${rc}" "${got}"
assert_no_crash "${select_artifact}"

## --- dm-repro-run-id.py ------------------------------------------------------
rc=0
got="$(printf '%s' '{"workflow_runs":[{"id":555}]}' | "${repro_run_id}")" || rc=$?
expect "repro-run-id: first run id" "555" "${rc}" "${got}"
assert_no_crash "${repro_run_id}"

## --- dm-repro-artifact-list.py -----------------------------------------------
rc=0
got="$(printf '%s' '{"artifacts":[{"name":"img.zip","id":3,"expired":false}]}' \
   | "${repro_artifact_list}")" || rc=$?
expect "repro-artifact-list: id<TAB>name line" "3${tab}img.zip" "${rc}" "${got}"

## An entry missing 'id' is skipped, not a KeyError crash.
rc=0
got="$(printf '%s' '{"artifacts":[{"name":"img.zip","expired":false}]}' \
   | "${repro_artifact_list}")" || rc=$?
expect "repro-artifact-list: entry missing 'id' is skipped" "" "${rc}" "${got}"
assert_no_crash "${repro_artifact_list}"

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "ci_json_readers_test: ${test_failures} fail" >&2
   exit 1
fi
printf '%s\n' "ci_json_readers_test: all reader contracts hold"
exit 0

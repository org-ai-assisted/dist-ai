#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## suite-exit.bash: the canonical result vocabulary + aggregator. Distinct,
## non-overloaded exit codes per outcome (0 PASS, 1 FAIL, 77 SKIP:target-absent,
## 78 SKIP:env-unmet); suite_exit precedence fail > target-absent > env-unmet >
## pass, so a skip is never folded into a passing suite. Drives the REAL helper.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
helper="${script_dir}/../dist-ai-tests-common/suite-exit.bash"
if [ ! -r "${helper}" ]; then
   helper='/usr/share/dist-ai-tests-common/suite-exit.bash'
fi
if [ ! -r "${helper}" ]; then
   printf '%s\n' "FATAL: suite-exit.bash not found (checkout or installed)" >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/suite-exit.bash
source "${helper}"

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## Emitters each exit their own distinct code (run in a subshell; they never return).
rc=0; ( result_pass ) || rc=$?; check "result_pass -> 0" "${rc}" "0"
rc=0; ( result_fail 'x' ) || rc=$?; check "result_fail -> 1" "${rc}" "1"
rc=0; ( result_skip_target_absent 'x' ) || rc=$?; check "result_skip_target_absent -> 77" "${rc}" "77"
rc=0; ( result_skip_env_unmet 'x' ) || rc=$?; check "result_skip_env_unmet -> 78" "${rc}" "78"

## result_word maps code -> label.
check "word 0"  "$(result_word 0)"  "PASS"
check "word 1"  "$(result_word 1)"  "FAIL"
check "word 77" "$(result_word 77)" "SKIP:target-absent"
check "word 78" "$(result_word 78)" "SKIP:env-unmet"
check "word other" "$(result_word 42)" "FAIL"

## suite_exit precedence: fail > target-absent > env-unmet > pass.
rc=0; ( suite_exit 0 0 0 ) || rc=$?; check "0/0/0 -> PASS(0)"                    "${rc}" "0"
rc=0; ( suite_exit 0 1 0 ) || rc=$?; check "target-absent -> 77"                "${rc}" "77"
rc=0; ( suite_exit 0 0 1 ) || rc=$?; check "env-unmet -> 78"                    "${rc}" "78"
rc=0; ( suite_exit 0 2 3 ) || rc=$?; check "target-absent outranks env-unmet -> 77" "${rc}" "77"
rc=0; ( suite_exit 1 0 0 ) || rc=$?; check "fail -> 1"                          "${rc}" "1"
rc=0; ( suite_exit 3 5 7 ) || rc=$?; check "fail dominates all -> 1"            "${rc}" "1"
rc=0; ( suite_exit '' '' '' ) || rc=$?; check "empty counts -> PASS(0)"         "${rc}" "0"
rc=0; ( suite_exit '' '' 1 ) || rc=$?; check "2-arg legacy call still skips (env) -> 78" "${rc}" "78"
rc=0; ( suite_exit 0 1 ) || rc=$?; check "2-arg call: skipped -> target-absent 77" "${rc}" "77"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"

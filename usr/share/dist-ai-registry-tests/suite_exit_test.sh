#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## suite_exit(): the canonical runner exit decision. Precedence fail > skip >
## pass, so a skip is never folded into a passing suite (the silent-skip the
## orchestrator's --allow-skip must get to govern). Drives the REAL helper.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## The helper ships in dist-ai-tests-common beside this suite's share dir.
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
      printf '%s\n' "FAIL: ${label} (rc ${got}, want ${want})"
      fail=$((fail + 1))
   fi
}

## suite_exit never returns, so run it in a subshell and read the exit code.
rc=0; ( suite_exit 0 0 ) || rc=$?; check "0 failed 0 skipped -> 0 (pass)"        "${rc}" "0"
rc=0; ( suite_exit 0 2 ) || rc=$?; check "0 failed 2 skipped -> 77 (skip)"       "${rc}" "77"
rc=0; ( suite_exit 1 0 ) || rc=$?; check "1 failed 0 skipped -> 1 (fail)"        "${rc}" "1"
rc=0; ( suite_exit 3 5 ) || rc=$?; check "fail dominates skip -> 1"              "${rc}" "1"
rc=0; ( suite_exit "" "" ) || rc=$?; check "empty counts -> 0 (pass)"           "${rc}" "0"
rc=0; ( suite_exit "" 1 ) || rc=$?; check "empty failed, 1 skipped -> 77"       "${rc}" "77"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"

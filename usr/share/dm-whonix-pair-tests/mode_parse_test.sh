#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dm-whonix-pair's --mode contract and the functional-lane wiring:
##   - --mode defaults to leak (current behavior preserved).
##   - --mode functional|leak parse; an unknown mode is REJECTED (SETUP_RC).
##   - functional mode runs the numbered battery (run_release_check_battery) via the OCR
##     real-session executor (ws_func_exec -> run_check), and is reached BEFORE the leak-only
##     anon-leak-test requirement (so functional does not need that checkout).
## Sources the REAL script define-only (EOF guard); no VM, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
tool="${here}/../../bin/dm-whonix-pair"
[ -x "${tool}" ] || { printf '%s\n' "FAIL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
## assert LABEL CMD...: run CMD; PASS iff it exits 0 (CMD carries its own rc, so no
## $?-after-test ambiguity).
assert() {
   local label="$1"
   shift
   if "$@"; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: ${label}"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: ${label}"
   fi
}

## default mode is leak, so existing callers keep the leak battery.
assert "default mode is leak" test "${mode}" = 'leak'

## --mode functional parses
mode='leak'
parse_args --mode functional
assert "--mode functional sets mode=functional" test "${mode}" = 'functional'

## --mode leak parses
mode='functional'
parse_args --mode leak
assert "--mode leak sets mode=leak" test "${mode}" = 'leak'

## an unknown mode is REJECTED (SETUP_RC=2); die exits, so run in a subshell + capture rc.
mode_rc=0
( parse_args --mode bogus ) >/dev/null 2>&1 || mode_rc=$?
assert "--mode bogus rejected (SETUP_RC)" test "${mode_rc}" -eq 2

## --shot-dir parses into shot_dir (the leak "story" sink); default is empty (storyless run).
assert "shot_dir defaults empty" test -z "${shot_dir}"
parse_args --shot-dir /shot-dir-parse-canary
assert "--shot-dir sets shot_dir" test "${shot_dir}" = '/shot-dir-parse-canary'

## functional wiring canaries (grep the SOURCE): the executor maps to run_check and
## main_functional drives the shared numbered battery with the two callbacks. The patterns
## hold literal $1/$3 which must NOT expand.
# shellcheck disable=SC2016  ## intentional literal match of the source text
assert "ws_func_exec delegates to run_check" \
   grep --quiet --fixed-strings 'run_check "$1" "$3" "$4"' "${tool}"
assert "main_functional drives the numbered battery" \
   grep --quiet --fixed-strings 'run_release_check_battery ws_func_exec ws_func_reboot_sysmaint' "${tool}"

## source-order canary: the functional branch is reached BEFORE the leak-only anon-leak-test
## requirement, so a functional run never demands that checkout.
branch_line="$(grep --line-number --fixed-strings 'main_functional' "${tool}" | head -1 | cut -d: -f1)"
require_line="$(grep --line-number --fixed-strings 'anon-leak-test checkout not found' "${tool}" | head -1 | cut -d: -f1)"
if [ -n "${branch_line}" ] && [ -n "${require_line}" ] && [ "${branch_line}" -lt "${require_line}" ]; then
   pass=$(( pass + 1 ))
   printf '%s\n' "PASS: functional branch precedes the anon-leak-test requirement"
else
   fail=$(( fail + 1 ))
   printf '%s\n' "FAIL: functional branch precedes the anon-leak-test requirement"
fi

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1

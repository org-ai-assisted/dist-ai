#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai-tests-all's effective_timeout() raises a named heavy suite's per-suite
## timeout to a FLOOR (developer-meta-files forks the style gate hundreds of times and
## can exceed the 300s core budget on a smaller / contended sandbox) without a global
## bump that would blind the hang-detector for every other suite. Extracts the REAL
## function from the shipped orchestrator and drives it.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
orch="${test_dir}/../../bin/dist-ai-tests-all"
if [ ! -r "${orch}" ]; then
   orch='/usr/bin/dist-ai-tests-all'
fi
if [ ! -r "${orch}" ]; then
   printf '%s\n' 'FATAL: effective_timeout_test: dist-ai-tests-all not found' >&2
   exit 1
fi

## Extract the real effective_timeout() -- from its header to the first column-0 '}'.
src="$(awk '
   /^effective_timeout\(\) \{/ { f = 1 }
   f { print }
   f && /^\}$/ { exit }
' "${orch}")"
if [ -z "${src}" ]; then
   printf '%s\n' 'FATAL: could not extract effective_timeout() from dist-ai-tests-all' >&2
   exit 1
fi
eval "${src}"

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

## The floored suite: the core budget (300) is raised to the 900 floor.
check "dmf: 300 core budget is floored to 900" \
   "$(effective_timeout developer-meta-files-tests 300)" '900'
## A larger operator-set budget is kept (max, not clamped down to the floor).
check "dmf: a larger operator budget (1200) is kept" \
   "$(effective_timeout developer-meta-files-tests 1200)" '1200'
## Exactly at the floor stays at the floor.
check "dmf: exactly 900 stays 900" \
   "$(effective_timeout developer-meta-files-tests 900)" '900'
## 0 would DISABLE timeout(1) -- the floor rescues the named suite from that.
check "dmf: 0 (timeout-disabling) is raised to the floor" \
   "$(effective_timeout developer-meta-files-tests 0)" '900'
## An unrelated suite has no floor: its budget passes through unchanged.
check "other suite: 300 passes through unchanged" \
   "$(effective_timeout lockfile-tests 300)" '300'
## A unit-suffixed value is operator-explicit and returned verbatim (no -ge on it).
check "dmf: a unit-suffixed value is left as-is" \
   "$(effective_timeout developer-meta-files-tests 5m)" '5m'

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"

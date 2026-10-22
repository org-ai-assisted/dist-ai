#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## No-privilege unit test for isn-nat-lib.bsh: the SYN-sequence parser and the
## verdict/expectation logic the capture engine depends on. Runs on every
## invocation of the suite (CI included), so a regression in the comparison logic
## is caught even where the privileged capture cannot run.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$( cd -- "$( dirname -- "$( readlink --canonicalize -- "$0" )" )" && pwd )"
lib="${script_dir}/isn-nat-lib.bsh"
if [ ! -r "${lib}" ]; then
   lib='/usr/share/tirdad-isn-nat-tests/isn-nat-lib.bsh'
fi
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FATAL: isn-nat-lib.bsh not found (checkout or installed)" >&2
   exit 1
fi
# shellcheck source=./isn-nat-lib.bsh
source "${lib}"

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$(( fail + 1 ))
   fi
}

## A real tcpdump '-S' pure-SYN line: the absolute ISN rides in 'seq <N>'.
syn_line='00:00:26.613376 IP 10.0.2.15.34934 > 94.16.104.174.443: Flags [S], seq 3502149445, win 64240, options [mss 1460,sackOK,nop,wscale 7], length 0'
check "parse SYN seq" "$( printf '%s\n' "${syn_line}" | isn_seq_from_text )" "3502149445"

## The first SYN wins when several lines are present.
two_lines="$( printf '%s\n' "${syn_line}" \
   '00:00:26.615423 IP 10.0.2.15.55840 > 208.38.228.104.2197: Flags [S], seq 632236576, win 64240, length 0' )"
check "parse first of many" "$( printf '%s\n' "${two_lines}" | isn_seq_from_text )" "3502149445"

## No SYN -> empty, never a spurious number.
check "parse no-seq -> empty" "$( printf '%s\n' 'no sequence here' | isn_seq_from_text )" ""

## Verdict mapping.
check "verdict equal -> preserved"       "$( isn_verdict 123 123 )"   "preserved"
check "verdict differ -> regenerated"    "$( isn_verdict 123 456 )"   "regenerated"
check "verdict empty guest -> inconclusive" "$( isn_verdict '' 456 )" "inconclusive"
check "verdict empty wire -> inconclusive"  "$( isn_verdict 123 '' )" "inconclusive"

## Expected verdict per mode.
check "expect libslirp" "$( isn_expected libslirp )" "regenerated"
check "expect passt"    "$( isn_expected passt )"    "regenerated"
check "expect routed"   "$( isn_expected routed )"   "preserved"
rc=0
isn_expected bogus >/dev/null 2>&1 || rc=$?
check "expect unknown -> non-zero" "${rc}" "1"

## isn_check end to end: a correct measurement passes, a flipped one fails.
rc=0
isn_check libslirp 111 222 >/dev/null || rc=$?
check "check libslirp regenerated -> pass" "${rc}" "0"
rc=0
isn_check libslirp 333 333 >/dev/null || rc=$?
check "check libslirp preserved -> fail" "${rc}" "1"
rc=0
isn_check routed 444 444 >/dev/null || rc=$?
check "check routed preserved -> pass" "${rc}" "0"
rc=0
isn_check routed 444 555 >/dev/null || rc=$?
check "check routed regenerated -> fail" "${rc}" "1"

printf '%s\n' "isn-nat-lib: ${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
exit 0

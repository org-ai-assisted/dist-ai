#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## leak-exit-classify is the AUTHORITATIVE leak-fail gate's core: dm-whonix-pair's probe_verdict
## classifies every leak-battery run through it (0 clear / 1 leak / else inconclusive). It MUST
## read the ONE top-level integer exit_code via a real JSON parse and fail-closed on ambiguity --
## a mis-read here is a silently-dropped leak, not a cosmetic bug. Drives the REAL classifier CLI
## (no VM/root/network); the shared leak_verdict module backs both this and battery-story-cards.
##
## PRIMARY CANARY (grok #3): the pre-fix classifier line-matched "exit_code" at any indent and
## took tail -1. Under anon-leak-test's json.dumps(indent=2, sort_keys=True) the top-level
## "exit_code" sorts FIRST and "results" LAST, so a NESTED detail exit_code (one 'returncode'->
## 'exit_code' rename away) is the last line and WON: a real leak (top-level 1) with a detail
## "exit_code": 0 classified CLEAR -> probe_verdict took the clear path for a real leak. Verified
## empirically: the old sed emits 'clear' for nested_leak below; this suite asserts 'leak'.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## LEAK_EXIT_CLASSIFY overrides the subject; default is the checkout sibling (no /usr write).
classifier="${LEAK_EXIT_CLASSIFY:-${here}/../../libexec/dm-whonix-pair/leak-exit-classify}"
[ -x "${classifier}" ] \
   || { printf '%s\n' "FATAL: leak-exit-classify not found at ${classifier}" >&2; exit 1; }

pass=0
fail=0
## Classify INPUT and assert the verdict equals WANT.
classifies() {
   local label="$1" input="$2" want="$3" got
   got="$(printf '%s' "${input}" | "${classifier}")"
   if [ "${got}" = "${want}" ]; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: ${label} (${got})"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
   fi
}

## --- the real anon-leak-test output shapes: one top-level object, integer exit_code -----------
classifies "clear run (exit_code 0)" \
   '{"results":[],"leak_detected":false,"exit_code":0}' clear
classifies "leak run (exit_code 1)" \
   '{"results":[{"probe":"icmp","status":"FAIL","message":"m","detail":{}}],"leak_detected":true,"exit_code":1}' leak
classifies "inconclusive run (exit_code 2)" \
   '{"results":[],"exit_code":2}' inconclusive

## --- PRIMARY CANARY #3: a nested detail exit_code must NOT override the top-level verdict -------
## Exactly anon-leak-test's json.dumps(indent=2, sort_keys=True): top-level "exit_code": 1 (leak),
## a probe detail carrying "exit_code": 0 on its own indented line AFTER it. The old sed read 0
## (clear); the real parse reads the top-level 1 (leak).
nested_leak='{
  "exit_code": 1,
  "leak_detected": true,
  "results": [
    {
      "detail": {
        "exit_code": 0,
        "leaked_to": "1.1.1.1"
      },
      "message": "non-Tor egress",
      "probe": "icmp-clearnet",
      "status": "FAIL"
    }
  ]
}'
classifies "nested detail exit_code 0 does NOT flip a real leak to clear (#3)" "${nested_leak}" leak

## --- fail-closed: nothing may read as a false CLEAR --------------------------------------------
## A guest-side infra failure / transport cut yields no verdict object -> inconclusive (SETUP).
classifies "no verdict object at all (infra/transport failure)" \
   'dsudo: command failed' inconclusive
classifies "empty input (transport cut)" '' inconclusive
## A truncated tail (an incomplete final object) decodes to nothing -> inconclusive, never clear.
classifies "truncated tail (incomplete object) (#5)" \
   '{"results":[],"exit_code":1' inconclusive
## A truncated REAL leak whose cut leaves a nested detail {"exit_code": 0} as the only complete
## object must NOT promote that nested 0 to the verdict (ai-review codex/grok/agy): the top-level
## object never closes -> no top-level span -> inconclusive, never a false clear.
trunc_nested_leak='{
  "exit_code": 1,
  "leak_detected": true,
  "results": [
    {
      "detail": {
        "exit_code": 0,
        "leaked_to": "1.1.1.1"
      },
      "message": "non-Tor egress"'
classifies "a truncated leak does NOT promote a nested detail exit_code (false clear)" \
   "${trunc_nested_leak}" inconclusive
## The inverse (top-level clean, nested leak, same truncation) must NOT become a false LEAK either.
trunc_nested_clean='{
  "exit_code": 0,
  "leak_detected": false,
  "results": [
    {
      "detail": {
        "exit_code": 1
      },
      "message": "x"'
classifies "a truncated clean does NOT promote a nested detail exit_code (false leak)" \
   "${trunc_nested_clean}" inconclusive
## A duplicate top-level exit_code (json keeps the LAST) must not flip a leak to clear: json.dumps
## never repeats a key, so a duplicate is crafted/garbled -> reject the object (ai-review grok).
classifies "duplicate exit_code key is rejected (not last-wins to clear)" \
   '{"exit_code": 1, "results": [{"probe":"icmp","status":"FAIL","message":"m","detail":{}}], "exit_code": 0}' inconclusive
## A key forged to collide via a unicode escape (exit_code decodes to exit_code) is the same
## duplicate once decoded -> rejected, not silently last-wins.
classifies "a unicode-escaped colliding exit_code key is rejected" \
   '{"exit_code": 1, "results": [{"probe":"icmp","status":"FAIL","message":"m","detail":{}}], "exit_code": 0}' inconclusive
## A boolean exit_code is not an integer verdict (isinstance(True,int) is True but type is not).
classifies "boolean exit_code decoy is not a verdict" \
   '{"results":[],"exit_code":true}' inconclusive
## Two top-level integer-exit_code objects are ambiguous -> never guess which is real.
classifies "two verdict objects are ambiguous (fail-closed)" \
   "$(printf '%s\n' '{"results":[],"exit_code":1}' '{"results":[],"exit_code":0}')" inconclusive

## --- transport tolerance: real output may be wrapped in noise / preceded by a warning ----------
classifies "transport noise around the one real object is tolerated" \
   "$(printf '%s\n' 'guest warning' '{"results":[{"probe":"x","status":"PASS","message":"m","detail":{}}],"exit_code":0}' 'trailing junk')" clear
classifies "an earlier object with NO exit_code does not mask the real leak" \
   "$(printf '%s\n' '{"results": []}' '{"results":[],"exit_code":1}')" leak

## --- bare decoy lines (only the old sed ever saw them) are inert to a real JSON parse ----------
## A CR/indent/leading-zero/non-ASCII "exit_code" line appended as TEXT (not a JSON object) once
## flipped the sed's tail -1; the parser ignores it and reads the real top-level leak at the gate.
leak_line='{"results":[{"probe":"icmp","status":"FAIL","message":"m","detail":{}}],"leak_detected":true,"exit_code":1}'
classifies "a CR-prefixed bare decoy line is inert (gate reads the real leak)" \
   "${leak_line}"$'\n\r''"exit_code": 0' leak
classifies "a leading-zero bare decoy line is inert (gate reads the real leak)" \
   "${leak_line}"$'\n''  "exit_code": 01' leak

printf '%s\n' "" "leak_exit_classify_test: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]

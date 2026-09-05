#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the shots driver (secure-terminal-shots-sandbox) must report HONEST, MONOTONIC
## phases, not a frozen repeated spinner.
##
## THE BUG THIS GUARDS: the driver reprinted "<lane> capturing -- N shot(s) rendered ..." every
## poll on a timer. Once the shot count froze in the compress+pull TAIL, that line kept printing
## -- a FABRICATED progress signal that (a) masked a real wedge from byte-growth supervision and
## (b) read as a stall to distinct-content readers. A 40-min run that SUCCEEDED read as a wedge.
##
## The fix (phase-progress.sh) prints a line only when the phase truly changes: capturing (N,
## distinct) -> compressing (once) -> pulling -> done, never an identical repeat.
##
## This drives the REAL emitter (sourced from the checkout, no synthetic copy) over a scripted
## capture-then-freeze-then-pull scenario and asserts:
##   1. the DISTINCT phase sequence capturing -> compressing -> pulling -> done, in order;
##   2. NO line is ever printed identically more than once.
## CANARY (proves the assertions catch the bug): the SAME two checks are run against a captured
## sample of the OLD frozen-spinner output; the no-repeat check MUST fail on it and the phase
## sequence MUST be absent. It also asserts the real driver no longer carries the fabricated line
## and does wire the emitter, so reverting the driver re-fails this test.
##
## No display, no sandbox. Exit: 0 pass | 1 fail.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
lib="${script_dir}/../secure-terminal-shots/phase-progress.sh"
driver="${script_dir}/../../bin/secure-terminal-shots-sandbox"

if [ ! -f "${lib}" ]; then
   printf '%s\n' "FATAL: phase-progress.sh not found at ${lib}" >&2
   exit 1
fi
if [ ! -x "${driver}" ]; then
   printf '%s\n' "FATAL: secure-terminal-shots-sandbox not found at ${driver}" >&2
   exit 1
fi

pass=0
fail=0
pass() { pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; }
fail() { fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; }

## in_order LOG NEEDLE... -- true iff each NEEDLE appears, in the given order, as a line substring.
in_order() {
   local log="$1"; shift
   local rest="${log}" needle idx
   for needle in "$@"; do
      case "${rest}" in
         *"${needle}"*)
            rest="${rest#*"${needle}"}"
            ;;
         *)
            return 1
            ;;
      esac
   done
   return 0
}

## has_repeat LOG -- true (rc 0) iff SOME non-empty line appears more than once in LOG. This is
## the property the frozen spinner violates and the honest emitter must satisfy (no repeat).
has_repeat() {
   local dup
   dup="$(printf '%s\n' "$1" | grep -v '^$' | LC_ALL=C sort | LC_ALL=C uniq -d)"
   [ -n "${dup}" ]
}

## --- Scenario 1: the REAL emitter over capture -> freeze(tail) -> pull -> done ---------------
## Threshold 2 frozen polls -> compressing (matches the shipped default; set explicitly so the
## test does not silently drift if the default changes).
new_log="$(
   export PP_FREEZE_POLLS=2
   # shellcheck source=../secure-terminal-shots/phase-progress.sh
   source "${lib}"
   pp_begin comparison
   pp_capture_tick 0     # first poll: no shots yet
   pp_capture_tick 12    # capturing advances
   pp_capture_tick 89
   pp_capture_tick 147
   pp_capture_tick 147   # frozen poll 1 (below threshold) -> silent
   pp_capture_tick 147   # frozen poll 2 -> compressing (147 captured), ONCE
   pp_capture_tick 147   # still frozen -> silent (no repeat)
   pp_capture_tick '?'   # unreadable count -> treated as frozen -> silent
   pp_pull_begin
   pp_done 'pulled 147 shot(s) into /site/comparison/shots/'
)"

printf '%s\n' '---- new emitter output ----' "${new_log}" '----------------------------'

if in_order "${new_log}" \
   'phase: capturing' 'phase: compressing' 'phase: pulling' 'phase: done'; then
   pass 'honest emitter prints the distinct phase sequence capturing -> compressing -> pulling -> done'
else
   fail 'honest emitter did NOT print capturing -> compressing -> pulling -> done in order'
fi

## The count must advance in the capturing lines (monotonic, distinct), not a single frozen value.
if in_order "${new_log}" '(12 shot(s))' '(89 shot(s))' '(147 shot(s))'; then
   pass 'capturing lines carry an advancing, distinct shot count'
else
   fail 'capturing lines did not carry an advancing distinct count'
fi

## compressing must be announced EXACTLY once despite 3 frozen polls + an unreadable poll.
compress_n="$(printf '%s\n' "${new_log}" | grep --count --fixed-strings 'phase: compressing' || true)"
if [ "${compress_n}" = '1' ]; then
   pass 'compressing announced exactly once across the frozen tail (no reprint)'
else
   fail "compressing announced ${compress_n} times (want 1) -- a reprint is the fabricated-progress bug"
fi

if has_repeat "${new_log}"; then
   fail 'honest emitter repeated an identical line -- that is the frozen-spinner bug'
else
   pass 'honest emitter never repeats an identical line'
fi

## --- Scenario 2 (CANARY): the OLD frozen-spinner output must FAIL both properties -------------
## A faithful sample of what the pre-fix driver printed: one line per poll, frozen at 147 in the
## tail. This is DATA (a captured log), not a re-implemented script, so it is not a synthetic
## copy of the subject -- it exists only to prove the checks above actually detect the bug.
old_log="$(printf '%s\n' \
   'secure-terminal-shots-sandbox: comparison capturing -- 12 shot(s) rendered ...' \
   'secure-terminal-shots-sandbox: comparison capturing -- 89 shot(s) rendered ...' \
   'secure-terminal-shots-sandbox: comparison capturing -- 147 shot(s) rendered ...' \
   'secure-terminal-shots-sandbox: comparison capturing -- 147 shot(s) rendered ...' \
   'secure-terminal-shots-sandbox: comparison capturing -- 147 shot(s) rendered ...' \
   'secure-terminal-shots-sandbox: comparison capturing -- 147 shot(s) rendered ...')"

if has_repeat "${old_log}"; then
   pass 'CANARY: the no-repeat check detects the old frozen spinner (it repeats a line)'
else
   fail 'CANARY BROKEN: no-repeat check did not flag the old frozen spinner -- the check proves nothing'
fi

if in_order "${old_log}" 'phase: compressing' 'phase: pulling' 'phase: done'; then
   fail 'CANARY BROKEN: the old spinner somehow satisfied the phase sequence -- the check proves nothing'
else
   pass 'CANARY: the old spinner lacks the labeled phase sequence (sequence check would fail on it)'
fi

## --- Scenario 3: guard the DRIVER wiring (a revert re-fails this test) ------------------------
## Structural, reads the real driver text (no synthetic copy). The fabricated per-poll line must
## be GONE and the emitter must be wired in.
if grep --quiet --fixed-strings 'shot(s) rendered ...' -- "${driver}"; then
   fail 'the driver still contains the fabricated "N shot(s) rendered ..." reprint'
else
   pass 'the driver no longer contains the fabricated per-poll reprint'
fi
if grep --quiet --fixed-strings 'phase-progress.sh' -- "${driver}" \
   && grep --quiet --fixed-strings 'pp_capture_tick' -- "${driver}"; then
   pass 'the driver sources phase-progress.sh and calls pp_capture_tick'
else
   fail 'the driver does not wire the phase-progress emitter (source + pp_capture_tick)'
fi

printf '%s\n' "---- ${pass} passed, ${fail} failed ----"
[ "${fail}" -eq 0 ]

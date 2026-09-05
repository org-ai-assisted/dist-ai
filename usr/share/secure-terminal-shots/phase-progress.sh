#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Honest, monotonic phase reporting for the host-side shots driver
## (secure-terminal-shots-sandbox). Sourced, never executed.
##
## WHY: a timer-reprinted progress line ("<lane> capturing -- N shot(s) rendered
## ...") is a FABRICATED signal once the shot count freezes in the compress+pull
## TAIL -- the line keeps printing while N stands still, advancing the progress
## file whether or not any work happens. That defeats stall detection in BOTH
## directions:
##   - byte-growth supervision reads the reprints as progress, so a REAL wedge
##     (the count stopped, but the line still prints) is HIDDEN;
##   - distinct-content reading sees the frozen count as a stall, so a legit
##     final phase reads as wedged.
##
## FIX: emit LABELED, MONOTONIC phase transitions, and print a line ONLY when
## something real changes:
##   - the observed shot count changed        -> "phase: capturing (N)"  (distinct N)
##   - the count has been frozen while the run is still live -> "phase: compressing
##     (N captured)" ONCE (the final composite build + webp optimization emit no
##     per-shot signal, so silence -- not a fabricated heartbeat -- is the honest
##     signal that the host cannot see inside this phase);
##   - the capture process exited, host pulls -> "phase: pulling (N)"  ONCE
##   - the pull succeeded                      -> "phase: done: ..."     ONCE
## No line is ever reprinted identically. A frozen last line therefore reads as a
## self-evident phase ("phase: compressing (147 captured)"), never as a hang, and
## the progress file stops growing exactly when the host has no real signal -- so
## a genuine wedge in the tail is no longer masked by fake growth.
##
## State is kept in this module's globals (one driver process = one reporter).

## Carried for R-010 / standalone-lint cleanliness; a NO-OP for the sole caller
## (secure-terminal-shots-sandbox), which enables the same options before sourcing.
# shellcheck shell=bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Polls with an unchanged count before the run is declared to have left the
## capturing phase. >1 so a single slow shot (one poll longer than the capture
## interval) does not flip the label to "compressing" prematurely; kept small so
## the honest "compressing" label appears promptly once capture truly stops.
[ -v PP_FREEZE_POLLS ] || PP_FREEZE_POLLS=2
case "${PP_FREEZE_POLLS}" in
   '' | *[!0-9]* | 0 )
      PP_FREEZE_POLLS=2
      ;;
esac

_pp_prefix='secure-terminal-shots-sandbox'
_pp_lane=''
_pp_last=''       ## last observed count ('' = nothing observed yet)
_pp_phase=''      ## capturing | compressing | pulling | done
_pp_frozen=0      ## consecutive polls with an unchanged count

_pp_line() {
   ## Progress lines go to STDOUT: that is the stream the durable-bg progress file
   ## captures. Diagnostics in the driver use >&2.
   printf '%s\n' "${_pp_prefix}: phase: $*"
}

## pp_begin LANE -- reset state for a fresh run and announce the capturing phase.
## The start marker carries NO count (nothing observed yet); per-poll ticks carry
## the count, so a first poll of 0 shots does not reprint this exact line.
pp_begin() {
   _pp_lane="$1"
   _pp_last=''
   _pp_phase='capturing'
   _pp_frozen=0
   _pp_line "capturing ${_pp_lane} ..."
}

## pp_capture_tick COUNT -- feed one observed shot count while the capture is
## still running. Prints at most one line, and never an identical repeat.
pp_capture_tick() {
   local count="$1"

   ## A non-numeric reading (the count probe failed / returned '?') is NOT a real
   ## count: treat it like a frozen poll rather than printing it as the shot total.
   case "${count}" in
      '' | *[!0-9]* )
         count="${_pp_last}"
         ;;
   esac

   if [ -n "${count}" ] && [ "${count}" != "${_pp_last}" ]; then
      ## The count changed -> capture is actively producing shots. Print the new
      ## count (distinct line) and reset the frozen run. If we had transitioned to
      ## "compressing" on a transient freeze, capture resuming flips it back --
      ## honest: it labels what is actually happening.
      _pp_last="${count}"
      _pp_frozen=0
      _pp_phase='capturing'
      _pp_line "capturing ${_pp_lane} (${count} shot(s))"
      return 0
   fi

   ## Count unchanged (or unreadable) this poll. Only a run that has ALREADY
   ## captured shots (a positive count) can be in its compress tail; a freeze at 0
   ## / nothing-yet is a slow start, not compression, so it stays in "capturing".
   _pp_frozen=$(( _pp_frozen + 1 ))
   if [ "${_pp_phase}" = 'capturing' ] && [ "${_pp_frozen}" -ge "${PP_FREEZE_POLLS}" ] \
      && [ -n "${_pp_last}" ] && [ "${_pp_last}" -gt 0 ]; then
      ## Capture has stopped producing new shots: the run is in its tail phase
      ## (final composite build + webp optimization), which emits no per-shot
      ## signal. Announce it ONCE; do NOT keep printing -- a repeated line would be
      ## the fabricated-progress bug this file exists to remove.
      _pp_phase='compressing'
      _pp_line "compressing (${_pp_last:-0} captured)"
   fi
   ## Already compressing, or not yet at the freeze threshold: print nothing.
   return 0
}

## pp_pull_begin -- the capture process has exited; the host is pulling the shots
## back. A distinct, self-evident phase.
pp_pull_begin() {
   _pp_phase='pulling'
   _pp_line "pulling (${_pp_last:-0} shot(s))"
}

## pp_done DETAIL... -- terminal success line.
pp_done() {
   _pp_phase='done'
   _pp_line "done: $*"
}

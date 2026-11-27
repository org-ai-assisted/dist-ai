#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sourced-only fragment; a top-level strict-mode block would leak
## set -o errexit/nounset into the consumer (every caller already sets it).

## Shared process-lifecycle helpers for dist-ai test suites. SOURCE this, do not execute.
## A liveness check written ONCE, correctly -- a hand-rolled `kill -0` poll is the recurring bug
## this closes: `kill -0` reports a ZOMBIE (killed but not yet reaped) as ALIVE, and an orphan
## reparented to a slow-reaping PID 1 (common in a CI container) lingers as a zombie, so a
## correctly-killed process reads as a false "survivor" intermittently. Any test that decides
## whether a process is dead MUST use proc_dead rather than a bare `kill -0`.

## proc_dead PID -- true (0) when PID is gone OR a zombie (state Z); false (1) while still running.
proc_dead() {
   local stat
   kill -0 "$1" 2>/dev/null || return 0
   stat="$(cat -- "/proc/$1/stat" 2>/dev/null)" || return 0
   ## comm (field 2) is parenthesized and may hold spaces/parens, so key off the LAST ')';
   ## the single-char state code is the first field after it.
   stat="${stat##*') '}"
   case "${stat}" in
      Z*)
         return 0
         ;;
   esac
   return 1
}

## proc_diag LABEL PID -- on a SURVIVOR, print its state/ppid/comm to stderr (nothing if gone),
## so a single red CI log tells a real leak (state R/S/D) from a timing/zombie artifact without
## a local reproduction.
proc_diag() {
   local raw rest state ppid comm
   kill -0 "$2" 2>/dev/null || return 0
   raw="$(cat -- "/proc/$2/stat" 2>/dev/null)" || return 0
   comm="${raw#*(}"
   comm="${comm%)*}"
   rest="${raw##*') '}"          # "state ppid pgrp ..." -- no parens past here
   state="${rest%% *}"
   rest="${rest#* }"
   ppid="${rest%% *}"
   printf '%s\n' \
      "DIAG: ${1} pid ${2} SURVIVED: state=${state} ppid=${ppid} comm=${comm}" >&2
}

## proc_wait_cmdline PATTERN [TRIES] -- wait (bounded, default ~30s = TRIES x 0.1s) until a
## process whose FULL command line matches PATTERN is visible to pgrep, i.e. a just-backgrounded
## marker has actually exec'd and become schedulable. Returns 0 when visible, 1 on timeout.
## PATTERN MUST be unique (not a generic name) so it cannot self-match the waiting shell. Gate a
## marker-dependent assertion on this instead of a fixed settle: under load a bare sleep lets the
## pgrep/pkill probe run before the marker is visible, and the subject is then blamed for an
## un-ready fixture (a flake that reads as a safe-pgrep/pkill defect).
proc_wait_cmdline() {
   local pattern="$1" tries="${2:-300}" i
   for (( i = 0; i < tries; i++ )); do
      if pgrep --full -- "${pattern}" >/dev/null 2>&1; then
         return 0
      fi
      sleep 0.1
   done
   return 1
}

## proc_wait_dead PID [TRIES] -- wait (bounded, default ~5s = TRIES x 0.05s) until PID is dead or
## a zombie (proc_dead), then return 0; 1 on timeout. Use after SENDING a kill signal: delivery
## is ASYNChronous, so an immediate proc_dead races it under load and reads a correctly-signalled
## process as still alive. This waits for the signal to actually take effect.
proc_wait_dead() {
   local pid="$1" tries="${2:-100}" i
   for (( i = 0; i < tries; i++ )); do
      proc_dead "${pid}" && return 0
      sleep 0.05
   done
   return 1
}

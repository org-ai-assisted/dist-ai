#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NON-strict: sourcing SUBJECT must NOT turn
## strict-mode ON in the sourcing shell (a 'set -o' / 'shopt' leak) and must NOT
## auto-run torbrowser (the was_executed guard). Run by check_noexec_do_test.sh
## under a timeout, which asserts on BOTH this exit code AND the final
## 'PROBE-COMPLETE' line: a SUBJECT that 'exit's while being sourced (e.g. a
## footer that auto-runs, or a stray top-level 'exit 0') kills this shell early,
## so exit 0 alone would pass vacuously -- the sentinel proves every check ran.
## SUBJECT and HELPER_SCRIPTS_PATH come from the env.
## Exit: 0 AND 'PROBE-COMPLETE' printed = clean; 1 a strict-mode option leaked;
## 3 a required function is undefined; no 'PROBE-COMPLETE' (any exit) = sourcing
## ran the tool / exited early. A leaked pre.bsh ERR trap exits via its own
## handler before the sentinel, so it reads as the early-exit case too.

# shellcheck disable=SC1090,SC1091,SC2154
source "${SUBJECT}"

## Reaching here at all proves sourcing did NOT auto-run torbrowser (main_function
## would have launched the browser / exited).
if [ ! "$(type -t check_noexec_do)" = "function" ]; then
  exit 3
fi
if [ ! "$(type -t main_function)" = "function" ]; then
  exit 3
fi

## Strict-mode leak check. Inspect the ACTUAL option state, not just the letters
## in $-: 'pipefail' and the 'inherit_errexit' / 'shift_verbose' shopts have no
## $- letter, so a partial leak (e.g. a 'set -o pipefail' moved above the
## was_executed guard) would be missed. A bare 'false' probe is unusable here --
## it trips the ERR trap torbrowser's pre.bsh installs when executed.
leaked=""
while read -r opt_name opt_state; do
  case "${opt_name}" in
  errexit | nounset | pipefail | errtrace)
    if [ "${opt_state}" = "on" ]; then
      leaked="${leaked} ${opt_name}"
    fi
    ;;
  esac
done < <(set -o)
for shopt_name in inherit_errexit shift_verbose; do
  if shopt -q "${shopt_name}" 2>/dev/null; then
    leaked="${leaked} ${shopt_name}"
  fi
done
if [ -n "${leaked}" ]; then
  printf '%s\n' "STRICT-LEAK:${leaked}" >&2
  exit 1
fi

## ERR-trap leak check: a sourced consumer calling check_noexec_do DIRECTLY (not
## in an 'if'/'||') must observe its non-zero return, not be killed by pre.bsh's
## ERR handler leaking into this shell (pre.bsh must be sourced only when torbrowser
## is EXECUTED). Drive a noexec verdict (-> return 1) as a BARE statement: if the
## trap leaked, its handler exits here before the sentinel. findmnt is the test's
## stub on PATH; '/' exists so the ancestor walk resolves immediately.
export FINDMNT_STUB_OPTIONS="rw,noexec"
export FINDMNT_STUB_RC="0"
# shellcheck disable=SC2034
tb_home_folder="/"
check_noexec_do

## Sentinel: printed only when every check above ran to completion. The test
## requires it in the probe's OUTPUT, so an early exit (auto-run, sourced 'exit',
## ERR-trap kill) cannot read as a clean pass.
printf '%s\n' "PROBE-COMPLETE"
exit 0

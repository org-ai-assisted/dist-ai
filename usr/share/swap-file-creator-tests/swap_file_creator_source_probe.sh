#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NON-strict: this probe must start with
## errexit OFF to observe whether sourcing SUBJECT (or calling the pure function)
## turns it ON. Run by select_swap_backend_test.sh, which asserts on its stdout
## and exit code. arg1: 'source' (just source) or 'call' (source, then call
## select_swap_backend once).
##
## The subject sources check_runtime.bsh at source time via HELPER_SCRIPTS_PATH
## (inherited from the parent test env), and does NOT auto-run main() when
## sourced (its was_executed guard is false).
##
## Exit: 0 no leak and select_swap_backend is defined; 1 sourcing or the call
## enabled errexit (leak); 3 select_swap_backend is undefined.

## Clear positional args BEFORE sourcing, exactly as the caller test does, so the
## subject sees the same ${#} here as in the real source (a subject gated on $#, e.g.
## 'exit 0 when no args', must behave identically under the probe and the real path).
mode="${1:-}"
set --
# shellcheck disable=SC1090,SC1091,SC2154  # SUBJECT: the swap-file-creator path, from the env
source "${SUBJECT}"

if ! declare -F select_swap_backend >/dev/null ; then
   exit 3
fi

if [ "${mode}" = "call" ]; then
   select_swap_backend no '' '' >/dev/null 2>&1 || true
fi

## Positive sentinel: main() must NOT have auto-run on source. main()'s first act
## is to source live-mode.sh, which sets live_status_detected; a plain source
## never does. So a set live_status_detected means the was_executed gate failed.
if [ -n "${live_status_detected+x}" ]; then
   printf '%s\n' "LEAK: main() auto-ran on source (live_status_detected is set)" >&2
   exit 1
fi

## No strict-mode option may have leaked from the subject into this shell
## (errexit is covered by the false/true oracle below too; pipefail/nounset/
## errtrace are NOT visible in $- so check each explicitly).
for __opt in errexit nounset pipefail errtrace; do
   if [[ -o "${__opt}" ]]; then
      printf '%s\n' "LEAK: shell option ${__opt} enabled on source" >&2
      exit 1
   fi
done

## No ERR/EXIT (or other) trap may have leaked -- a top-level 'trap ... EXIT'
## would hijack the caller's exit.
if [ -n "$(trap -p)" ]; then
   printf '%s\n' "LEAK: a trap is installed after source" >&2
   exit 1
fi

## If sourcing (or the call) enabled errexit, this 'false' aborts (exit 1);
## otherwise 'true' yields exit 0.
false
true

## Positive completion marker: written ONLY after sourcing (and the optional call) ran
## to the end with no early exit. Its ABSENCE lets the caller tell a clean source from
## a subject that 'exit 0's mid-source -- both give rc 0 and empty stdout, so rc/stdout
## alone cannot distinguish them.
if [ -n "${SOURCE_COMPLETE_MARKER:-}" ]; then
   true > "${SOURCE_COMPLETE_MARKER}"
fi

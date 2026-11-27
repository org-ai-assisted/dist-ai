#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NON-strict: sourcing SUBJECT must NOT turn
## strict-mode ON in the sourcing shell (a 'set -o' leak) and must NOT auto-run
## torbrowser (the was_executed guard). Run by check_noexec_do_test.sh, which
## asserts on this exit code. SUBJECT and HELPER_SCRIPTS_PATH come from the env.
## Exit: 0 clean (no auto-run, no strict leak, check_noexec_do + main_function
## defined); 1 strict-mode (errexit/nounset) leaked into the sourcing shell;
## 3 a required function is undefined.

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

## Strict-mode leak check: inspect $- directly. A bare 'false' would instead trip
## the ERR trap that torbrowser's sourced pre.bsh installs (not errexit), so it is
## not a reliable leak probe here; $- reflects only the actual 'set -o' state.
case "$-" in
*e* | *u*)
  exit 1
  ;;
esac

exit 0

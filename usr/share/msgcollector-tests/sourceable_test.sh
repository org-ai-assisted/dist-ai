#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## msgcollector must be SOURCE-ABLE: sourcing it defines its functions WITHOUT
## running main() -- no arg parsing, no folder_init, no dispatch, no exit. That
## is what lets unit tests drive its functions directly instead of shelling out.
## Guards against reverting to top-level execution (the version that ran the
## whole pipeline the moment the file was sourced).
##
## Sources the REAL shipped script in a clean subshell and asserts: main() is
## defined, and main's first side effect (msgcollector_run_dir, set by the
## folder_init main calls) did NOT happen. Self-contained; no root, no network.
## style-ok: no-has

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

rel='usr/libexec/msgcollector/msgcollector'
candidates=()
[ -z "${MSGCOLLECTOR_REPO:-}" ] || candidates+=( "${MSGCOLLECTOR_REPO}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/msgcollector/${rel}" )
candidates+=( "/${rel}" )
subject=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: msgcollector not found (set MSGCOLLECTOR_REPO)." >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

## Source in a clean child shell with NO arguments and strict mode OFF (the
## file sets its own once main runs, which it must NOT here). Report three
## facts: did sourcing return cleanly, is main() defined, did main run (detected
## by msgcollector_run_dir, which only folder_init -- called inside main --
## sets).
## style-ok: allow-inline-interpreter -- fresh isolation shell must inherit
## errexit ONLY from the sourced subject; a strict-mode preamble or an extracted
## script would pre-set it and defeat the test.
report="$(
   MSGCOLLECTOR_SUBJECT="${subject}" bash -c '
      ## The file sets "set -e" at the top; capture the source rc via "|| rc" so
      ## it cannot abort us, and use if-conditions below (errexit-exempt) so a
      ## failed "declare -F" for an absent function does not abort either.
      src_rc=0
      source "${MSGCOLLECTOR_SUBJECT}" </dev/null >/dev/null 2>&1 || src_rc="$?"
      printf "src_rc=%s\n" "${src_rc}"
      if declare -F main >/dev/null 2>&1; then printf "MAIN_DEFINED\n"; fi
      if declare -F collector >/dev/null 2>&1; then printf "COLLECTOR_DEFINED\n"; fi
      if [ -n "${msgcollector_run_dir:-}" ]; then printf "MAIN_RAN\n"; fi
   ' 2>/dev/null
)"

if grep --quiet --fixed-strings 'src_rc=0' <<< "${report}"; then
   pass "sourcing returns cleanly (no dispatch, no exit)"
else
   fail "sourcing did not return 0: $(printf '%s' "${report}" | tr '\n' ' ')"
fi

if grep --quiet --fixed-strings 'MAIN_DEFINED' <<< "${report}"; then
   pass "main() is defined on source"
else
   fail "main() is not defined -- msgcollector is not in source-able (main + guard) form"
fi

if grep --quiet --fixed-strings 'COLLECTOR_DEFINED' <<< "${report}"; then
   pass "collector() (and the other functions) are available to a unit test"
else
   fail "collector() not defined after sourcing"
fi

if grep --quiet --fixed-strings 'MAIN_RAN' <<< "${report}"; then
   fail "main ran on source (msgcollector_run_dir got set) -- execution is not guarded"
else
   pass "main did NOT run on source (no folder_init side effect)"
fi

if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${fail_count} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: msgcollector is source-able -- functions defined, main() guarded (${pass_count} assertions)."

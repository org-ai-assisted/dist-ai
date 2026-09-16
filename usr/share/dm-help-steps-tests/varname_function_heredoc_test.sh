#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the function-body capture in varname_snapshot_lib.bsh.
##
## 'declare -f' pretty-prints a function with its closing '}' at column 0 and all
## nested braces INDENTED -- EXCEPT a heredoc body, which bash emits verbatim, so a
## heredoc line that is just '}' also lands at column 0. Keying the block end off
## the FIRST bare '}' therefore truncates any function whose heredoc body contains
## such a line. vs_filter_functions + vs_extract_consumed_bodies instead emit
## through the LAST bare '}' (the real closer). This test feeds a crafted 'declare
## -f' dump with exactly that shape and asserts the body AFTER the heredoc's '}' is
## kept; the CANARY confirms the naive first-'}' rule would have dropped it.
##
## No checkout, no root, no network -- a pure unit test of the library.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./varname_snapshot_lib.bsh
source "${test_dir}/varname_snapshot_lib.bsh"

failures=0

## check <desc> <haystack> <needle> present|absent
check() {
   local desc="$1" hay="$2" needle="$3" want="$4" found="no" expect
   case "${hay}" in
      *"${needle}"*)
         found="yes"
         ;;
   esac
   if [ "${want}" = "present" ]; then
      expect="yes"
   else
      expect="no"
   fi
   if [ "${found}" = "${expect}" ]; then
      printf 'PASS: %s\n' "${desc}"
   else
      printf 'FAIL: %s (wanted %s: %s)\n' "${desc}" "${want}" "${needle}" >&2
      failures=$((failures + 1))
   fi
}

## Build the dump from REAL 'declare -f' output, so the header spacing and the
## verbatim (un-indented) heredoc body -- the exact shape the library parses -- come
## from bash's own pretty-printer, not a hand-mock. The heredoc body deliberately
## contains a bare '}' at column 0, with real body after the heredoc terminator.
# shellcheck disable=SC2317  # bodies are inspected via 'declare -f', not executed
heredoc_fn() {
   cat <<'EOF'
before
}
after
EOF
   printf '%s\n' tail_marker
}
# shellcheck disable=SC2317
plain_fn() {
   printf '%s\n' plain_marker
}
dump="$(declare -f heredoc_fn plain_fn)"

## Empty baseline so nothing is subtracted; vs_normalize is a passthrough here (no
## checkout path or $HOME substring appears in the crafted dump).
vs_baseline_func_file="$(mktemp)"
printf '' > "${vs_baseline_func_file}"
cleanup() {
   safe-rm --force -- "${vs_baseline_func_file}"
}
trap cleanup EXIT

filtered="$(printf '%s\n' "${dump}" | vs_filter_functions "/nonexistent-dm")"

check "vs_filter_functions keeps the heredoc body's bare '}'" "${filtered}" $'\nbefore\n}\nafter\n' present
check "vs_filter_functions keeps the body AFTER the heredoc (not truncated)" "${filtered}" "tail_marker" present
check "vs_filter_functions still captures the following function" "${filtered}" "plain_marker" present

## CANARY: the naive first-'}' rule (what this test guards against) would stop at
## the heredoc's '}', dropping 'tail_marker'. Prove that rule really would fail, so
## a green result above means something.
naive="$(printf '%s\n' "${dump}" | awk '
   /^[A-Za-z_][A-Za-z0-9_]* \(\) ?$/ { inblock = 1 }
   { if (inblock) print }
   /^}$/ { inblock = 0 }
')"
check "canary: naive first-'}' rule DROPS the post-heredoc body" "${naive}" "tail_marker" absent

## vs_extract_consumed_bodies must also keep the full heredoc body.
snapshot_file="$(mktemp)"
printf '%s\n' "${dump}" > "${snapshot_file}"
vs_consumed_funcs=( heredoc_fn )
extracted="$(vs_extract_consumed_bodies "${snapshot_file}")"
safe-rm --force -- "${snapshot_file}"
check "vs_extract_consumed_bodies keeps the post-heredoc body" "${extracted}" "tail_marker" present
check "vs_extract_consumed_bodies stops before the next function" "${extracted}" "plain_marker" absent

if [ "${failures}" -ne 0 ]; then
   printf 'FAILED: %s assertion(s).\n' "${failures}" >&2
   exit 1
fi
printf 'OK: function-body capture survives a heredoc with a column-0 brace.\n'

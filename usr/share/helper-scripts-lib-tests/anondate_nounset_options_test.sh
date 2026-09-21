#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for anondate's option parsing + dispatch under 'set -o nounset'.
##
## anondate enables 'set -o nounset'. parse_cmd_options must stay bound when a
## caller passes options only (no trailing positional, no '--') -- which is how
## every real caller invokes it. Two ways it can trip:
##   1. the BashFAQ/035 loop re-enters 'case' after the last option is shifted
##      away, so it must guard the empty argument ('${1:-}').
##   2. the post-loop dispatch reads the option flags, so they must be
##      initialized before the loop.
##
## Drives the REAL parse_cmd_options: extracts it from the shipped anondate
## (current text, no drift) and runs it under nounset with the options-only
## argvs the real callers use. The dispatch action functions (root / file / Tor
## work) are stubbed no-ops -- the test targets the argument handling, not the
## Tor queries. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/sbin/anondate"
else
   subject='/usr/sbin/anondate'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: anondate not readable at '${subject}'; set HELPER_SCRIPTS_REPO or install helper-scripts." >&2
   exit 1
fi

## Extract parse_cmd_options() verbatim from the shipped script (top-level
## definition, closing brace in column 0). Reading the current text keeps the
## test from drifting away from the code it guards.
func_body="$(awk '/^parse_cmd_options\(\) \{$/ {f=1} f {print} f && /^\}$/ {exit}' "${subject}")"
if [ -z "${func_body}" ]; then
   printf '%s\n' "FATAL: could not extract parse_cmd_options() from '${subject}'." >&2
   exit 1
fi
## A truncated extraction (e.g. an in-body here-document with a bare '}' line
## ending the awk capture early) would parse-error in the harness and could let
## a '*unbound variable*' check pass vacuously; reject invalid bash up front.
if ! bash -n <<<"${func_body}" 2>/dev/null; then
   printf '%s\n' "FATAL: extracted parse_cmd_options() is not valid bash (truncated extraction?)." >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/anondate-options-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap test_cleanup_handler EXIT

test_failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## Assemble a harness that stubs the dispatch action functions (they do
## root/file/Tor work) and sets the only globals parse_cmd_options reads before
## dispatch, then runs the extracted function under nounset with a given
## options-only argv. Captures rc and stdout+stderr.
run_parse() {
   local harness="${work_dir}/harness.bash"
   {
      cat <<'PREAMBLE'
set -o errexit -o nounset -o pipefail
TOR_CONSENSUS=/nonexistent-consensus
TOR_UNVERIFIED_CONSENSUS=/nonexistent-unverified
has_consensus() { return 0; }
current_time_is_in_valid_range() { return 0; }
show-valid-after() { return 0; }
show-valid-until() { return 0; }
show-middle-range() { return 0; }
tor_cert_lifetime_valid() { return 0; }
tor_cert_valid_after() { return 0; }
user_permission() { return 0; }
group_permission() { return 0; }
PREAMBLE
      printf '%s\n' "${func_body}"
      printf '%s\n' 'parse_cmd_options "$@"'
   } >"${harness}"
   run_rc=0
   run_output="$(bash "${harness}" "$@" 2>&1)" || run_rc=$?
}

## A single option: the loop shifts it away, then must survive re-entering
## 'case' with no arguments left, and dispatch on the initialized flag.
run_parse --has-consensus
case "${run_output}" in
   *"unbound variable"*)
      fail "--has-consensus tripped nounset: ${run_output}"
      ;;
   *)
      pass "--has-consensus: no unbound variable"
      ;;
esac
if [ "${run_rc}" -eq 0 ]; then
   pass "--has-consensus: dispatched cleanly (rc=0)"
else
   fail "--has-consensus: rc=${run_rc} -- output: ${run_output}"
fi

## systemcheck's real call: two options, no positional. Exercises both the
## shift-past-last-arg path and the flag read at post-loop dispatch.
run_parse --verified-only --has-consensus
case "${run_output}" in
   *"unbound variable"*)
      fail "--verified-only --has-consensus tripped nounset: ${run_output}"
      ;;
   *)
      pass "--verified-only --has-consensus: no unbound variable"
      ;;
esac
if [ "${run_rc}" -eq 0 ]; then
   pass "--verified-only --has-consensus: dispatched cleanly (rc=0)"
else
   fail "--verified-only --has-consensus: rc=${run_rc} -- output: ${run_output}"
fi

## No args at all: option parsing must fall through to the 'No option chosen'
## dispatch (rc 1) rather than abort on an unbound argument.
run_parse
case "${run_output}" in
   *"unbound variable"*)
      fail "no-args tripped nounset: ${run_output}"
      ;;
   *)
      pass "no-args: no unbound variable"
      ;;
esac
case "${run_output}" in
   *"No option chosen"*)
      pass "no-args: reached dispatch (No option chosen)"
      ;;
   *)
      fail "no-args: did not reach dispatch -- output: ${run_output}"
      ;;
esac
if [ "${run_rc}" -eq 1 ]; then
   pass "no-args: exited 1 as the 'No option chosen' branch requires"
else
   fail "no-args: expected rc 1, got ${run_rc} -- output: ${run_output}"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: anondate parse_cmd_options is nounset-safe for options-only argvs."

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The parts of tor-ctrl's command-line surface that never reach a controller:
## version output, usage, missing option arguments, and onion-address validation.
##
## Worth pinning because every one of these paths runs under 'set -o errexit
## -o nounset -o pipefail' with 'inherit_errexit'. Under strict mode a diagnostic
## path is the FIRST thing to break: an unset variable or a no-match grep aborts
## before the message it exists to print, and the user sees silence and a bare
## non-zero instead of the reason. So each case asserts BOTH the exit status and
## that the intended message actually appeared.
##
## No tor, no network, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TOR_CTRL_REPO ] || TOR_CTRL_REPO=""
if [ -n "${TOR_CTRL_REPO}" ]; then
   bin_dir="${TOR_CTRL_REPO}/usr/bin"
else
   bin_dir="/usr/bin"
fi

for subject in tor-ctrl tor-ctrl-onion tor-ctrl-circuit tor-ctrl-stream tor-ctrl-observer; do
   if [ ! -x "${bin_dir}/${subject}" ]; then
      printf '%s\n' "SKIP: subject not found at '${bin_dir}/${subject}'" >&2
      printf '%s\n' "set TOR_CTRL_REPO to a complete tor-ctrl checkout, or install the package" >&2
      exit 77
   fi
done

## The companions shell out to 'tor-ctrl' through PATH; keep both halves from the
## same tree so an installed copy cannot stand in for the checkout under test.
PATH="${bin_dir}:${PATH}"
export PATH

failures=0
checks=0

check() {
   local label="${1}"
   local expected="${2}"
   local actual="${3}"
   checks=$(( checks + 1 ))
   if [ "${expected}" = "${actual}" ]; then
      printf '%s\n' "PASS  ${label} (${actual})"
   else
      failures=$(( failures + 1 ))
      printf '%s\n' "FAIL  ${label}: expected '${expected}', got '${actual}'"
   fi
}

## Runs a subject and asserts its exit status AND that its output contains the
## expected text. Status alone is not enough: an errexit abort and a deliberate
## error_msg both exit 1, and only the message distinguishes "it explained the
## problem" from "it died before it could".
## Both results are set in THIS shell, not returned through a command
## substitution: '$( run_subject ... )' would run it in a subshell, where the
## captured output is discarded on return and every text assertion silently
## compares against an empty string.
last_output=""
last_status=0
run_subject() {
   last_status=0
   last_output="$( "$@" 2>&1 )" || last_status=$?
}

expect() {
   local label="${1}"
   local want_status="${2}"
   local want_text="${3}"
   shift 3
   run_subject "$@"
   check "${label}: exit status" "${want_status}" "${last_status}"
   if printf '%s' "${last_output}" | grep -qF -- "${want_text}"; then
      check "${label}: reports the reason" "found" "found"
   else
      check "${label}: reports the reason" "found" "missing: ${last_output:0:60}"
   fi
}

## '-V' is the one success path here: it prints and exits 0.
expect "tor-ctrl -V" 0 "tor-ctrl" "${bin_dir}/tor-ctrl" -V

## Usage exits 1 by design.
for subject in tor-ctrl tor-ctrl-onion tor-ctrl-observer; do
   expect "${subject} -h" 1 "usage:" "${bin_dir}/${subject}" -h
done

## tor-ctrl-circuit and tor-ctrl-stream source /usr/libexec/tor-ctrl/pad.bsh by
## ABSOLUTE path, so running them from a checkout alone cannot work -- the path
## is not relative to the script and cannot be redirected. Rather than skip them,
## assert whichever contract actually applies:
##   library installed -> they start and print usage;
##   library absent    -> they say WHICH file is missing.
## The second half is the one that matters: sourcing happens under errexit, so
## the failure mode to guard against is a bare non-zero with no explanation.
if [ -r /usr/libexec/tor-ctrl/pad.bsh ]; then
   for subject in tor-ctrl-circuit tor-ctrl-stream; do
      expect "${subject} -h (pad.bsh installed)" 1 "usage:" "${bin_dir}/${subject}" -h
   done
else
   for subject in tor-ctrl-circuit tor-ctrl-stream; do
      expect "${subject} -h (pad.bsh absent) names the missing library" 1 \
         "/usr/libexec/tor-ctrl/pad.bsh" "${bin_dir}/${subject}" -h
   done
fi

## A missing option argument must be reported, not swallowed. get_arg rejects an
## empty or '-'-prefixed argument.
expect "tor-ctrl-onion -o with no value" 1 "requires an argument" \
   "${bin_dir}/tor-ctrl-onion" -o
expect "tor-ctrl-onion -o followed by an option" 1 "requires an argument" \
   "${bin_dir}/tor-ctrl-onion" -o -D

## validate_onion runs before any controller contact, so these are offline.
## Wrong LENGTH.
expect "onion address too short" 1 "is invalid" \
   "${bin_dir}/tor-ctrl-onion" -D -o notavalidonionaddress

## Right length, but a character outside the base32 lower-case alphabet. '1' and
## '8' are not in [a-z2-7], and an upper-case letter is not either -- a check that
## only counted characters would pass all three.
expect "onion address with a non-base32 digit" 1 "is invalid" \
   "${bin_dir}/tor-ctrl-onion" -D -o "1111111111111111111111111111111111111111111111111111111a"
expect "onion address with an upper-case letter" 1 "is invalid" \
   "${bin_dir}/tor-ctrl-onion" -D -o "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA"

printf '%s\n' "" "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]

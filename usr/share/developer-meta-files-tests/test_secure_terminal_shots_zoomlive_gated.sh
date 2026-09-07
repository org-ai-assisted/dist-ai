#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Pins a false-green regression in usr/bin/secure-terminal-shots (zoom-live mode):
## the capture runs as `... comparison-capture.sh --zoom-live "$@" || run_rc="$?"`
## (|| so errexit does not stop us), then it must exit "${run_rc}". The
## "wrote real-GUI zoom-live shots" success line must be gated on run_rc == 0: an
## UNGATED print (the regression this guards) claims success on stdout for a failed
## sweep (run_rc!=0) while exiting non-zero -- misleading a stdout-scraping caller.
##
## Asserted STRUCTURALLY on the shipped runner text (driving zoom-live needs
## xvfb-run + a real/stubbed capture chain; disproportionate for a one-line guard).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
runner="${test_dir}/../../bin/secure-terminal-shots"
[ -r "${runner}" ] || runner='/usr/bin/secure-terminal-shots'
if [ ! -r "${runner}" ]; then
   printf '%s\n' "FATAL: secure-terminal-shots not found" >&2
   exit 1
fi

## Extract the zoom-live mode block: from `if [ "${mode}" = 'zoom-live' ]; then` to its
## matching top-level `fi`.
block="$(awk '
   /if \[ "\$\{mode\}" = .zoom-live. \]; then/ { grab=1 }
   grab { print }
   grab && /^fi$/ { grab=0 }
' "${runner}")"

if [ -z "${block}" ]; then
   fail 'could not locate the zoom-live mode block in secure-terminal-shots'
   printf '%s\n' "===== ${pass_count} passed, ${fail_count} failed =====" >&2
   exit 1
fi

## The success line must exist AND be gated on run_rc == 0.
if ! grep --quiet --fixed-strings 'wrote real-GUI zoom-live shots' <<< "${block}"; then
   fail 'zoom-live success line not found (test is stale -- update the pattern)'
elif grep --quiet --extended-regexp 'if \[ "\$\{run_rc\}" = .0. \]; then' <<< "${block}"; then
   pass 'the zoom-live success line is gated on run_rc == 0 (no false-green on a failed sweep)'
else
   fail 'the zoom-live success line is NOT gated on run_rc == 0 -> a failed sweep still prints "wrote ... shots" (false green)'
fi

printf '%s\n' "" "test_secure_terminal_shots_zoomlive_gated: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]

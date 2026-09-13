#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dist-ai-tests-all's inline echo of a failing suite's captured log: it must
## reproduce the WHOLE log, including a final line with no trailing newline.
##
## THE BUG IT GUARDS: 'while IFS= read -r log_line; do ... done < file' drops the
## file's last line when that line lacks a trailing newline -- which a suite that
## dies mid-write (or a tool that prints a bare final token) produces. The last
## line is often the most actionable part of a failure, so silently dropping it
## hides the reason. The fix is the house idiom '|| [ -n "${log_line}" ]'.
##
## Two checks: (1) STATIC -- no bare loop variant remains anywhere in the script
## (covers both occurrences, on FAIL and on SKIP-UNAUTHORIZED); (2) BEHAVIORAL --
## the SHIPPED loop, extracted and run against a newline-less fixture, emits the
## last line.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_script="$(readlink --canonicalize -- "${BASH_SOURCE[0]}")"
test_dir="${test_script%/*}"

orch="${test_dir}/../../bin/dist-ai-tests-all"
[ -r "${orch}" ] || orch='/usr/bin/dist-ai-tests-all'
if [ ! -r "${orch}" ]; then
   printf '%s\n' 'FATAL: log_capture_trailing_line_test: dist-ai-tests-all not found' >&2
   exit 1
fi

failures=0

## (1) Static: a bare 'while IFS= read -r log_line; do' (no continuation guard)
## must not exist. Match the loop header WITHOUT the '|| [ -n' guard.
if grep -nE 'while IFS= read -r log_line;[[:space:]]*do' -- "${orch}" >/dev/null 2>&1; then
   printf 'FAIL: a bare newline-dropping read loop remains in dist-ai-tests-all:\n' >&2
   grep -nE 'while IFS= read -r log_line;[[:space:]]*do' -- "${orch}" >&2
   failures=$((failures + 1))
else
   printf 'PASS: no bare newline-dropping read loop remains\n'
fi

## (2) Behavioral: extract the FIRST log-echo loop (from its 'while' header through
## the first 'done < ' line) and drive it against a fixture whose last line has NO
## trailing newline. Runs the SHIPPED code, so a regression fails here too.
workdir="$(mktemp -d)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${workdir}"; }
trap cleanup EXIT

slice_file="${workdir}/loop.bash"
awk '/while IFS= read -r log_line/ { f = 1 } f { print } /done < / { if (f) exit }' \
   "${orch}" > "${slice_file}"
if ! grep --quiet 'while IFS= read -r log_line' -- "${slice_file}"; then
   printf 'FAIL: could not extract the log-echo loop; the slice is wrong, not the code\n' >&2
   exit 1
fi

suite="fixture"
log_dir="${workdir}"
## printf with no trailing '\n' -> the last line has no terminator.
printf 'alpha\nbravo\nlast-line-no-newline' > "${log_dir}/dist-ai-tests-all.${suite}.log"
emit() { printf '%s\n' "$1"; }

# shellcheck disable=SC1090  # sourcing an extracted slice by design
captured="$(source "${slice_file}")"
last_emitted="$(printf '%s\n' "${captured}" | tail -n1)"
if [ "${last_emitted}" = "last-line-no-newline" ]; then
   printf 'PASS: the shipped loop emits a newline-less final line\n'
else
   printf 'FAIL: newline-less final line dropped; last emitted was %q\n' "${last_emitted}" >&2
   failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
   printf 'log_capture_trailing_line_test: %s assertion(s) FAILED.\n' "${failures}" >&2
   exit 1
fi
printf 'log_capture_trailing_line_test: OK\n'

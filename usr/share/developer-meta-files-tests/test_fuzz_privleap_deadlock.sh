#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: fuzz_privleap._drive must not DEADLOCK on a payload larger than the
## socket buffer (the server never drains a huge send, so an unbounded blocking
## sendall waits forever -- masked in normal fuzzing only by libFuzzer's max_len).
## Drives the REAL _drive through fuzz_privleap_deadlock_probe.py (in privleap-tests,
## next to the harness), which shims only the atheris fuzzing framework and bounds the
## run so a genuine hang reads as a FAIL. FAILS CLOSED on an absent prerequisite
## (python3, privleap) -- a required dep that vanished must fail loudly, not skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.bsh ; then
   printf '%s\n' "FATAL: helper-scripts has.bsh is not installed (/usr/libexec/helper-scripts/has.bsh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source /usr/libexec/helper-scripts/has.bsh

if ! has python3 ; then
   printf '%s\n' "FATAL: python3 not on PATH" >&2
   exit 1
fi
## The probe itself fails loudly (FATAL, exit 1) if the real privleap module is
## missing -- checked there rather than via an inline 'python3 -c' (R-193).

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe=''
for candidate in \
   "${test_dir}/../privleap-tests/fuzz_privleap_deadlock_probe.py" \
   "/usr/share/privleap-tests/fuzz_privleap_deadlock_probe.py"; do
   if [ -r "${candidate}" ]; then
      probe="${candidate}"
      break
   fi
done
if [ -z "${probe}" ]; then
   printf '%s\n' "FATAL: fuzz_privleap_deadlock_probe.py not found under privleap-tests" >&2
   exit 1
fi

## Call the +x probe via its own '-Bsu' shebang (it puts its own dir on sys.path so
## fuzz_privleap.py + pl_testlib resolve).
"${probe}"

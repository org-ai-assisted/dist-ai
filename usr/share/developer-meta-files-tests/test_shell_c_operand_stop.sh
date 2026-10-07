#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Direct unit test for the shell '-c' wrapper scans in dist_ai.rules._helpers
## (shell_c_programs / _c_behind_wrapper and the separate-'-c' sibling
## shell_c_program_words): a script operand, a bare '-', or '--' must STOP the
## scan, so the script's own '-c' is not misread as the shell's (a false positive
## R-191/R-192/R-101). Drives the REAL shipped module through
## shell_c_operand_stop_probe.py -- no copy of the code under test. FAILS CLOSED
## on an absent prerequisite (python3, shfmt): a required tool that vanished must
## fail loudly, not silently stop gating.

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
# shellcheck source=../../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source /usr/libexec/helper-scripts/has.bsh

if ! has python3 ; then
   printf '%s\n' "FATAL: python3 not on PATH" >&2
   exit 1
fi
if ! has shfmt ; then
   printf '%s\n' "FATAL: shfmt not on PATH (bash_ast requires it)" >&2
   exit 1
fi

script_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe="${script_dir}/shell_c_operand_stop_probe.py"
if [ ! -r "${probe}" ]; then
   printf '%s\n' "FATAL: probe not found: ${probe}" >&2
   exit 1
fi

## Call the +x probe via its own '-Bsu' shebang (no stray .pyc, no user site).
"${probe}"

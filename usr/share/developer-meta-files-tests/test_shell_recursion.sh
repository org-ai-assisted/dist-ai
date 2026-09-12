#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit test: the R-153 pipeline-flatten and R-220 arithmetic evaluator in
## dist_ai.rules.shell must handle a deeply-nested but VALID script without an
## uncaught RecursionError (which would abort every rule on that file). Drives
## the REAL shipped engine through shell_recursion_probe.py -- no copy. FAILS
## CLOSED on an absent prerequisite (python3, shfmt).

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
if ! has shfmt ; then
   printf '%s\n' "FATAL: shfmt not on PATH (bash_ast requires it)" >&2
   exit 1
fi

script_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe="${script_dir}/shell_recursion_probe.py"
if [ ! -r "${probe}" ]; then
   printf '%s\n' "FATAL: probe not found: ${probe}" >&2
   exit 1
fi

## Call the +x probe via its own '-Bsu' shebang (no stray .pyc, no user site).
"${probe}"

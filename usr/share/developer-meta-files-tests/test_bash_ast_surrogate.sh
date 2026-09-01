#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Direct unit test for dist_ai.bash_ast.parse on a lone surrogate: it must fail
## CLOSED (BashParseError), not let UnicodeEncodeError escape (fail-OPEN for a
## PreToolUse guard). Drives the REAL shipped module through
## bash_ast_surrogate_probe.py -- no copy of the code under test. FAILS CLOSED on
## an absent prerequisite (python3, shfmt): a required tool that vanished must
## fail loudly, not silently stop gating.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.sh ; then
   printf '%s\n' "FATAL: helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source /usr/libexec/helper-scripts/has.sh

if ! has python3 ; then
   printf '%s\n' "FATAL: python3 not on PATH" >&2
   exit 1
fi
if ! has shfmt ; then
   printf '%s\n' "FATAL: shfmt not on PATH (bash_ast requires it)" >&2
   exit 1
fi

script_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe="${script_dir}/bash_ast_surrogate_probe.py"
if [ ! -r "${probe}" ]; then
   printf '%s\n' "FATAL: probe not found: ${probe}" >&2
   exit 1
fi

## Call the +x probe via its own '-Bsu' shebang (no stray .pyc, no user site).
"${probe}"

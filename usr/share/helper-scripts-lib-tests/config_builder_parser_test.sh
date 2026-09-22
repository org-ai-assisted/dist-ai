#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for helper-scripts config_builder parser (issue #85):
##   - whitespace around '=' is stripped ('key = value' == 'key=value'), so a
##     later file's override actually overrides instead of emitting both keys;
##   - a header may carry an optional trailing '#' comment without crashing, and
##     only a comment may follow ']' (any other trailing content is rejected).
## Drives the REAL module by importing it off the checkout (no copy). No root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   py_path="${HELPER_SCRIPTS_REPO}/usr/lib/python3/dist-packages"
else
   py_path='/usr/lib/python3/dist-packages'
fi

if [ ! -d "${py_path}/config_builder" ] || [ ! -d "${py_path}/append_shared" ]; then
   printf '%s\n' "FATAL: config_builder/append_shared not found under '${py_path}' (set HELPER_SCRIPTS_REPO)." >&2
   exit 1
fi

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

rc=0
PYTHONPATH="${py_path}" "${test_dir}/config_builder_parser.py" || rc="$?"

if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "FAILED: config_builder parser assertions did not all pass." >&2
   exit 1
fi
printf '%s\n' "OK: config_builder parser strips '=' whitespace and tolerates header comments."

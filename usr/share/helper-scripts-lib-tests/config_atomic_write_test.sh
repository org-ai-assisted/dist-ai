#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for atomic config writes in helper-scripts:
##   - config_builder.write_config_file() wrote directly to the target with open("w"),
##     truncating it in place; an interrupted/failed write left a truncated config.
##   - append_shared (append/append-once/overwrite) used a default-TMPDIR temp file +
##     shutil.move, which falls back to a NON-atomic cross-filesystem copy onto the
##     live target when TMPDIR is on a different filesystem.
## Both now write to a same-directory temp file and os.replace (atomic rename), so a
## crash/failure leaves the previous file intact and a reader never sees a half-write.
##
## Drives the REAL modules by importing them off the checkout (no copy). No root.

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
PYTHONPATH="${py_path}" "${test_dir}/config_atomic_write.py" || rc="$?"

if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "FAILED: atomic-write assertions did not all pass." >&2
   exit 1
fi
printf '%s\n' "OK: config_builder + append_shared write atomically."

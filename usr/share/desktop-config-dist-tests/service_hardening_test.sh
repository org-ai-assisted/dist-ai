#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## W^X/NNP directive-lint lane for livecheck.service: a thin wrapper so the
## suite's *_test.sh glob runs the shared-engine Python lint. Forwards the lint's
## exit code (0 pass / 1 fail / 77 skip) to the suite runner's accounting.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

rc=0
"${script_dir}/service_hardening_lint.py" "$@" || rc=$?
exit "${rc}"

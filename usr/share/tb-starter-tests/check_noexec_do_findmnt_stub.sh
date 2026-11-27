#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Stub 'findmnt' for check_noexec_do_test.sh. Ignores its arguments and returns
## the scenario's controlled mount OPTIONS (FINDMNT_STUB_OPTIONS) with exit
## FINDMNT_STUB_RC, so the test drives check_noexec_do's view of the covering
## mount hermetically -- no real mounts, no root. A non-zero rc models "no mount
## resolved".

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

rc="${FINDMNT_STUB_RC:-0}"
if [ "${rc}" != "0" ]; then
  exit "${rc}"
fi
printf '%s\n' "${FINDMNT_STUB_OPTIONS:-}"

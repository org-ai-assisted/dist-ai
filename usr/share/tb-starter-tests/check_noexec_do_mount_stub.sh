#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Stub 'mount' for check_noexec_do_test.sh. The FIXED check_noexec_do uses
## findmnt and never calls mount; this stub exists only to make the CANARY run
## (the old 'mount | grep ~/.tb' code) deterministic instead of reading the test
## host's real mount table. Emits MOUNT_STUB_OUTPUT, ignoring arguments.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

printf '%s\n' "${MOUNT_STUB_OUTPUT:-}"

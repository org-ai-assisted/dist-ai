#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Helper for concurrency_guard_test.sh (NOT a '*_test.sh', so the runner does
## not execute it directly). Run UNDER the dist-installer-cli lock via lockfile.sh
## wrap mode: 'lockfile.sh dist-installer-cli -- concurrency_guard_holder.sh
## <ready-marker> <hold-seconds>'. It touches the ready marker (so the test knows
## the lock is held WITHOUT itself trying to acquire it -- an acquiring probe would
## race this holder), then holds the lock by sleeping for <hold-seconds>.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

ready_marker="${1}"
hold_seconds="${2}"

touch -- "${ready_marker}"
sleep "${hold_seconds}"

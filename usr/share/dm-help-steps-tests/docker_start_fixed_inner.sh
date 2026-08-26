#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The FIXED tee idiom from derivative-maker 'docker/derivative-maker-docker-start',
## standalone, so the assertion is about behaviour rather than about reading the
## shipped file.
##
## Runs "$@" with its output tee'd to $LOG_TARGET and exits with the COMMAND's
## status, not the pipeline's -- so a log write that fails (ENOSPC, /dev/full)
## cannot invert a passing build into a failure.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

declare -a pipe_status
if "$@" 2>&1 | tee -a -- "${LOG_TARGET}" ; then
   pipe_status=( "${PIPESTATUS[@]}" )
else
   pipe_status=( "${PIPESTATUS[@]}" )
fi
exit "${pipe_status[0]}"

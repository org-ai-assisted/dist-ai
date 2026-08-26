#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The PRE-FIX tee idiom, kept as the canary counterpart of
## 'docker_start_fixed_inner.sh': the bare pipeline under errexit + pipefail, whose
## status is the pipeline's, so a failing tee masks the command's own result.
##
## It MUST get the /dev/full case wrong. If it ever stops doing so, the fixed
## script's assertions are proving nothing and the test says so.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

"$@" 2>&1 | tee -a -- "${LOG_TARGET}"

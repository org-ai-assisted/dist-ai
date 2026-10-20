#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Helper for create_teardown_shim_test.sh: source the REAL swap-file-creator
## subject (SUBJECT) and drive its do_start / do_stop directly, with the knobs
## supplied via DRIVE_* env, so the test can observe the command trace left by
## the PATH-shimmed external commands. Not a *_test.sh, so the suite runner does
## not execute it as a case. arg1: 'start' | 'stop'.

## The config knobs below are consumed by the sourced subject's do_start /
## do_stop (shellcheck cannot see that), and SUBJECT / DRIVE_* arrive from the
## environment -- so SC2034 (unused) and SC2154 (unassigned) are false here.
## These directives precede the first command, so they apply file-wide.
# shellcheck disable=SC2034,SC2154
# shellcheck disable=SC1090,SC1091

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

source "${SUBJECT}"
set_defaults
SWAPFILE="${DRIVE_SWAPFILE}"
SWAP_FILE_SIZE_CUSTOM_MB="${DRIVE_SIZE_MB:-1024}"
DO_PRE_CHECK="${DRIVE_DO_PRE_CHECK:-no}"
HIBERNATION='no'
VERBOSE='yes'
SHRED_ON_STOP="${DRIVE_SHRED_ON_STOP:-no}"

case "${1:-}" in
   start)
      do_start
      ;;
   stop)
      do_stop
      ;;
   *)
      printf '%s\n' "drive: expected 'start' or 'stop', got '${1:-}'" >&2
      exit 2
      ;;
esac

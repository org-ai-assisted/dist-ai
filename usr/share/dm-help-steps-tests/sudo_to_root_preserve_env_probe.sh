#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Companion probe for sudo_to_root_preserve_env_leak_test.sh. Run from a
## derivative-maker checkout (cwd), with the build command as arguments.
##
## Sources help-steps/pre + help-steps/variables as a PARENT (finalizing
## SUDO_TO_ROOT), then re-execs itself as a CHILD (--child) that sources them
## again and prints whether the child's SUDO_TO_ROOT kept '--preserve-env'. A
## child inherits only EXPORTED state, so this reproduces the production shape (a
## build step under a variables-sourcing ancestor): the leak appears iff
## 'variables' exports its re-entrance guard flag.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ "${1:-}" = "--child" ]; then
   shift
   source help-steps/pre >/dev/null 2>&1
   source help-steps/variables "$@" >/dev/null 2>&1
   case "${SUDO_TO_ROOT}" in
      *--preserve-env=*)
         printf '%s\n' "CHILD_HAS_PRESERVE_ENV"
         ;;
      *)
         printf '%s\n' "CHILD_MISSING_PRESERVE_ENV"
         ;;
   esac
   exit 0
fi

source help-steps/pre >/dev/null 2>&1
source help-steps/variables "$@" >/dev/null 2>&1
bash "$0" --child "$@"

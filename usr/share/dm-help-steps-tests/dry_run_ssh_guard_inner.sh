#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive the argv-scan + '~/.ssh' guard sliced out of
## derivative-maker 'help-steps/dm-build-official-one' (argv 1), with the build
## arguments following it.
##
## 'run_cmd' is defined to EXECUTE, which is what the shipped one does at
## TESTING_MODE=0 -- the default, and the only mode in which the guard actually
## tests anything. $HOME and $CI are set by the caller; they are the inputs.
##
## Exits 0 only if control reaches past the guard.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

body="$1"
shift

run_cmd() {
   "$@"
}

eval "${body}"
printf '%s\n' "reached-past-ssh-guard"

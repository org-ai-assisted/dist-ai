#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Inner runner for variables_precedence_test.sh: source help-steps/pre +
## help-steps/variables for one build command and print the resolved value of a
## single variable as 'RESULT=<value>'. Run with CWD = the derivative-maker
## checkout (the caller cd's there) so 'source help-steps/...' resolves. Args:
##   $1 = variable name to report; the rest = the build command (passed through
##   to variables). Layer inputs the caller controls: an env var it exports
##   before invoking this, and a --conffile it passes in the build command.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Real derivative-maker builds start NON-ROOT and sudo internally; the dist-ai CI
## container runs as root. Re-exec as a non-root build user FIRST, before consuming
## args, so the resolver runs faithfully (no root-check / empty-user_name gymnastics).
prec_inner_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./help_steps_test_lib.bsh
source "${prec_inner_dir}/help_steps_test_lib.bsh"
reexec_as_build_user "$0" "$@"

prec_var_name="$1"
shift

source help-steps/pre
source help-steps/variables "$@"

printf 'RESULT=%s\n' "${!prec_var_name:-<unset>}"

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Inner runner for variables_reload_idempotent_test.sh: source help-steps/pre +
## help-steps/variables, snapshot 'declare -p', source variables AGAIN in this
## same shell, snapshot again. Run with CWD = the derivative-maker checkout (the
## caller cd's there) so 'source help-steps/...' resolves. Args:
##   $1 = first-snapshot path, $2 = second-snapshot path, rest = the build
##   command passed through to variables (--flavor ... --target ...).

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
reload_inner_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./help_steps_test_lib.bsh
source "${reload_inner_dir}/help_steps_test_lib.bsh"
reexec_as_build_user "$0" "$@"

reload_first_snapshot="$1"
reload_second_snapshot="$2"
shift 2

source help-steps/pre
source help-steps/variables "$@"
declare -p | LC_ALL=C sort > "${reload_first_snapshot}"

source help-steps/variables "$@"
declare -p | LC_ALL=C sort > "${reload_second_snapshot}"

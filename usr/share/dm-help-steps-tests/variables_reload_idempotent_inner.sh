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

reload_first_snapshot="$1"
reload_second_snapshot="$2"
shift 2

## CI/suite runs as root; the resolver's pre root-check refuses that without
## this documented override (help-steps/pre). No-op when not root.
export dist_build_allow_root=true

source help-steps/pre
source help-steps/variables "$@"
declare -p | LC_ALL=C sort > "${reload_first_snapshot}"

source help-steps/variables "$@"
declare -p | LC_ALL=C sort > "${reload_second_snapshot}"

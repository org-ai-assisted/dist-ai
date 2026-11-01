#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- fixture driver; does not source helper-scripts.

## Fixture driver for test_website_tests_required_unit_test_red_diagnostics.sh. Run as a SEPARATE
## process so run_required_unit_test executes under the runner's OWN errexit, uncontaminated by the
## test's result-catch: errexit is IGNORED throughout a function/subshell in a caught context, which
## would mask the silent-abort bug under test. Mirrors website-tests calling the function as a bare
## simple command. Args: <runner-path> <tests_dir> <unit-test-name>. The runner's source-able guard
## makes `source` return before the suite body, so only the function is defined, then driven.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck disable=SC1090
source "$1"
## Sets the global that the sourced run_required_unit_test reads (cross-file; not seen by shellcheck).
# shellcheck disable=SC2034
tests_dir="$2"
run_required_unit_test "$3"

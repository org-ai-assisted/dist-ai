#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins sdwdate-gui-tests-mutation's HELPER_SCRIPTS_PATH resolution: the dist-ai wire
## convention passes HELPER_SCRIPTS_PATH as the checkout ROOT, so the runner must put
## the dist-packages dir UNDER it on PYTHONPATH -- NOT the bare root. With the bare
## root, the staged suites fail with ModuleNotFoundError (strict_config_parser /
## sanitize_string) whenever helper-scripts is not also installed system-wide (every
## clean CI runner / source checkout). Canary: RED on the pre-fix runner (which set
## hs_pkg="${HELPER_SCRIPTS_PATH}" directly), GREEN once it appends the package subpath.
##
## Uses the runner's DIST_AI_MUTATION_PRINT_PYTHONPATH seam to read the derived
## PYTHONPATH without staging or running any mutant.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_script="$(readlink --canonicalize -- "${BASH_SOURCE[0]}")"
test_dir="${test_script%/*}"

## Installed layout is /usr/share/...; from a checkout the entrypoints sit at ../../bin.
runner="${test_dir}/../../bin/sdwdate-gui-tests-mutation"
[ -x "${runner}" ] || runner='/usr/bin/sdwdate-gui-tests-mutation'

if [ ! -x "${runner}" ]; then
   printf '%s\n' 'FATAL: sdwdate_gui_tests_mutation_helper_scripts_path_test: sdwdate-gui-tests-mutation not found' >&2
   exit 1
fi

pkg_rel='usr/lib/python3/dist-packages'

work="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## A minimal fake sdwdate_gui checkout: only the package DIR must exist for the runner's
## absent-target guard to pass; the print seam exits before anything is staged or run.
fake_repo="${work}/sdwdate-gui"
mkdir --parents -- "${fake_repo}/${pkg_rel}/sdwdate_gui"

## A fake helper-scripts checkout ROOT (what the wire convention passes as
## HELPER_SCRIPTS_PATH). Only its dist-packages dir needs to exist.
fake_hs="${work}/helper-scripts"
mkdir --parents -- "${fake_hs}/${pkg_rel}"
expected="$(readlink --canonicalize -- "${fake_hs}/${pkg_rel}")"

failures=0

derived="$(
   env "SDWDATE_GUI_REPO=${fake_repo}" "HELPER_SCRIPTS_PATH=${fake_hs}" \
      "DIST_AI_MUTATION_PRINT_PYTHONPATH=1" --unset=PYTHONPATH \
      "${runner}" 2>/dev/null
)"
first_entry="${derived%%:*}"

if [ "${first_entry}" = "${expected}" ]; then
   printf '%s\n' "PASS: HELPER_SCRIPTS_PATH root resolves to its dist-packages dir on PYTHONPATH"
else
   printf '%s\n' "FAIL: PYTHONPATH head is '${first_entry}', expected '${expected}' (the runner put the bare HELPER_SCRIPTS_PATH root on PYTHONPATH -- ModuleNotFoundError when helper-scripts is not installed system-wide)" >&2
   failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
   printf '%s\n' "sdwdate_gui_tests_mutation_helper_scripts_path_test: ${failures} assertion(s) FAILED." >&2
   exit 1
fi
printf '%s\n' "sdwdate_gui_tests_mutation_helper_scripts_path_test: OK"

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The dm-help-steps-tests runner and its host-only marker. A case whose header
## carries '## dm-help-steps-tests: host-only: <reason>' cannot verify anything
## in CI. Under CI it must be listed by name and NOT run: running it there exits
## 77, which turns the whole suite into SKIP -- an unauthorized skip, so dm CI
## could never be green. Off CI it runs like any other case.
## Drives the REAL runner on a fixture tests dir (DM_HELP_STEPS_TESTS_DIR):
##   - CI: suite exits 0, host-only case listed and not run, normal case runs;
##   - not CI: the host-only case runs (its 77 surfaces as the suite's SKIP);
##   - an UNMARKED case exiting 77 under CI still makes the suite SKIP.
## Canary: fails on the runner that ran every case under CI.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

runner="${test_dir}/../../bin/dm-help-steps-tests"
if [ ! -x "${runner}" ]; then
   runner="$(type -P dm-help-steps-tests || true)"
fi
if [ -z "${runner}" ] || [ ! -x "${runner}" ]; then
   printf '%s\n' "FATAL: dm-help-steps-tests runner not found." >&2
   exit 1
fi

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

fixture="${work_dir}/tests"
mkdir -- "${fixture}"
ran_log="${work_dir}/ran.log"
touch -- "${ran_log}"

## Fixture cases record that they ran; the host-only one would SKIP if run.
## Stub bodies are literal text, expanded when the case runs.
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash' \
      '## dm-help-steps-tests: host-only: fixture' \
      'printf "%s\n" host >> "${RAN_LOG}"' 'exit 77' > "${fixture}/a_host_only_test.sh"
   printf '%s\n' '#!/bin/bash' \
      'printf "%s\n" normal >> "${RAN_LOG}"' 'exit 0' > "${fixture}/b_normal_test.sh"
}

## run_runner <ci:true|false>: suite rc -> runner_rc, output -> runner_out.
run_runner() {
   runner_rc=0
   truncate --size=0 -- "${ran_log}"
   runner_out="$(env --unset=GITHUB_ACTIONS CI="$1" RAN_LOG="${ran_log}" \
      DM_HELP_STEPS_TESTS_DIR="${fixture}" DM_HELP_STEPS_TESTS_NO_ELEVATE=true \
      DERIVATIVE_MAKER_DIR="${dm_checkout}" "${runner}" 2>&1)" || runner_rc="$?"
}

run_runner true
if [ "${runner_rc}" -eq 0 ] && ! grep --quiet -- '^host$' "${ran_log}" \
   && grep --quiet -- '^normal$' "${ran_log}" \
   && [[ "${runner_out}" == *"host-only, not run under CI (1): a_host_only_test.sh"* ]]; then
   pass "CI: host-only case listed by name and not run; suite passes"
else
   fail "CI: rc=${runner_rc} ran='$(cat -- "${ran_log}")' output: ${runner_out}"
fi

run_runner false
if [ "${runner_rc}" -eq 77 ] && grep --quiet -- '^host$' "${ran_log}"; then
   pass "off CI: host-only case runs (its skip surfaces as the suite SKIP)"
else
   fail "off CI: rc=${runner_rc} ran='$(cat -- "${ran_log}")' output: ${runner_out}"
fi

## Only the marker exempts: an unmarked skip under CI still surfaces.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/bash' 'exit 77' > "${fixture}/c_unmarked_skip_test.sh"
run_runner true
if [ "${runner_rc}" -eq 77 ]; then
   pass "CI: an unmarked skip still makes the suite SKIP"
else
   fail "CI: unmarked skip did not surface; rc=${runner_rc} output: ${runner_out}"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: host-only cases are listed, not run, under CI."

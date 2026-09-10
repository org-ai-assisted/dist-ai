#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/buildconfig.d/05_lib.bsh'
## derive_unified_image_paths(): the 'none' sentinel must leave the unified-image
## path variables UNSET.
##
## THE BUG IT GUARDS: help-steps/variables sets vm_names_to_be_exported='none' for
## a non-unified build (e.g. --flavor source). The path-derivation loop iterated
## '${vm_names_to_be_exported}' and, because "none" does not contain the source
## build's dist_build_type_long ("source"), did NOT 'continue' -- so it derived a
## bogus '.../none-<ver>.<arch>.raw' path into binary_image_raw_file_for_unified /
## _qcow2_ instead of leaving them unset (the state a kicksecure single build has).
##
## Drives the REAL function by SOURCING it (no code extraction), plus the REAL
## helper-scripts strings.bsh for its check_variable_name dependency. Needs no
## root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
## variables-lib.bsh was folded into the top-level buildconfig.d/ module dir as
## 05_lib.bsh (loaded first by help-steps/variables). Still a separate
## sourced-only file so this test can source the helpers directly.
variables_lib="${DM_VARIABLES_LIB:-${dm_checkout}/buildconfig.d/05_lib.bsh}"
if [ ! -r "${variables_lib}" ]; then
   printf '%s\n' "FATAL: variables-lib.bsh not found/readable at '${variables_lib}' (set DM_VARIABLES_LIB or DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi
: "${HELPER_SCRIPTS_PATH:=${dm_checkout}/packages/kicksecure/helper-scripts}"
export HELPER_SCRIPTS_PATH
strings_bsh="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh"
if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not found at '${strings_bsh}' (needed for check_variable_name)." >&2
   exit 1
fi

pass() { printf '%s\n' "PASS: $*"; }
test_failures=0
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

# shellcheck disable=SC1090
source "${strings_bsh}"
# shellcheck disable=SC1090
source "${variables_lib}"

if [ "$(type -t derive_unified_image_paths)" != "function" ]; then
   printf '%s\n' "FATAL: derive_unified_image_paths not defined after sourcing '${variables_lib}'." >&2
   exit 1
fi

## Common inputs a real build has set by the time the derivation runs.
dist_binary_build_folder=/build/out
dist_build_version=1.2.3
target_architecture_pretty_name=amd64

## Run the REAL function against a fresh set of the two output variables. The
## '|| true' keeps a nonzero return (e.g. from a dependency the derivation calls)
## from aborting the whole script under errexit with no PASS/FAIL output -- the
## assertions on the resulting variable state are the real check.
run_derivation() {
   unset binary_image_raw_file_for_unified binary_image_qcow2_file_for_unified 2>/dev/null || true
   derive_unified_image_paths || true
}

## --- the fix: the 'none' sentinel leaves both vars UNSET ----------------------
vm_names_to_be_exported="none"
dist_build_type_long="source"
run_derivation
if [ -n "${binary_image_raw_file_for_unified+x}" ]; then
   fail "'none' sentinel set binary_image_raw_file_for_unified='${binary_image_raw_file_for_unified}' (bogus path; must stay unset)"
else
   pass "'none' sentinel leaves binary_image_raw_file_for_unified unset"
fi
if [ -n "${binary_image_qcow2_file_for_unified+x}" ]; then
   fail "'none' sentinel set binary_image_qcow2_file_for_unified='${binary_image_qcow2_file_for_unified}' (bogus path; must stay unset)"
else
   pass "'none' sentinel leaves binary_image_qcow2_file_for_unified unset"
fi

## --- CANARY: a real unified (workstation) build DOES derive one path ----------
## Proves the function actually runs and its dependencies are wired, so the
## unset-assertions above are meaningful (not green because the function no-oped).
## A workstation build exports two VMs; the derivation keeps the one that is NOT
## the current build type, so the Gateway path is what must appear here.
vm_names_to_be_exported="Whonix-Gateway-CLI Whonix-Workstation-CLI"
dist_build_type_long="workstation"
run_derivation
expected_raw="/build/out/Whonix-Gateway-CLI-1.2.3.amd64.raw"
if [ "${binary_image_raw_file_for_unified:-}" = "${expected_raw}" ]; then
   pass "real two-VM list derives the other VM's raw path"
else
   fail "real two-VM list derived '${binary_image_raw_file_for_unified:-<UNSET>}', expected '${expected_raw}'"
fi

## The canary must NOT itself trip the 'none' bug (it never uses the sentinel).
case "${binary_image_raw_file_for_unified:-}" in
   */none-*)
      fail "canary path contains '/none-', the very bug under test"
      ;;
   *)
      pass "canary path carries a real VM name, not the 'none' sentinel"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: unified-image 'none' sentinel leaves paths unset."

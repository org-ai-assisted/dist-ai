#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/dm-build-official-one': the
## VM-target sets it computes.
##
## dm-build-official-one computes TWO target sets:
##   - multi_target_args: the ARCHITECTURE default (amd64 -> VirtualBox + qcow2;
##     arm64/other -> qcow2). Passed to the SHARED PREP steps (prepare-build-machine,
##     cowbuilder-setup, local-dependencies) and the sanity/create-raw steps.
##   - flavor_multi_target_args: 'dist_build_multi_target_list' when set (the
##     override, even to empty), else the arch default. Passed to the per-flavor
##     BUILD and UPLOAD steps.
##
## So the override is honored for the build/upload set, while the prep set stays the
## arch default. This guard extracts the real computation from the shipped script
## (no drift) and evaluates it per request, so a silent drop of the override-aware
## build set is caught. Behavioral: no root, no network, no build.

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

subject="$(locate_help_step dm-build-official-one "${DM_BUILD_OFFICIAL_ONE:-}" "${test_dir}")" \
   || exit 1

## The VM-target computation is a self-contained block: from the top-level
## 'multi_target_args=()' (arch case) through the 'fi' that closes the
## flavor_multi_target_args override conditional.
block="$(sed -n '/^multi_target_args=()$/,/^fi$/p' -- "${subject}")"
if [ -z "${block}" ]; then
   fail "could not extract the multi_target_args block; the assertions below would prove nothing"
   printf '%s\n' "FAILED: extraction" >&2
   exit 1
fi

## Guard the guard: the build set must remain OVERRIDE-AWARE -- it consults
## 'dist_build_multi_target_list'. A silent revert that dropped the override (e.g.
## hard-wiring the build set to the arch default) would remove this line.
case "${block}" in
   *'dist_build_multi_target_list+x'*)
      true
      ;;
   *)
      fail "the build set is no longer override-aware -- dm-build-official-one dropped the dist_build_multi_target_list override"
      ;;
esac

work="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup_handler EXIT

printf '%s\n' "${block}" > "${work}/block.bash"
## HERMETIC driver: it sets BOTH inputs the block reads -- architecture and
## dist_build_multi_target_list -- EXPLICITLY from its args, and UNSETS the override
## when the case does not provide one. The build/CI environment exports
## dist_build_multi_target_list, and an extracted block run with that ambient value
## present skews the result (an empty exported value makes the override branch fire
## with zero targets), so the block must never see an inherited value.
cat > "${work}/driver.bash" <<'DRIVER'
set -o nounset
block="$1"
architecture="$2"
if [ "$3" = "__UNSET__" ]; then
   unset dist_build_multi_target_list 2>/dev/null || true
else
   dist_build_multi_target_list="$3"
fi
# shellcheck disable=SC1090
source "${block}"
printf '%s|%s\n' "${multi_target_args[*]}" "${flavor_multi_target_args[*]}"
DRIVER

## $1 label, $2 expected "prep|build", $3 architecture, $4 override list (omit -> unset).
check_case() {
   local label="$1" want="$2" arch="$3" mtl="${4:-__UNSET__}"
   local got
   got="$(bash "${work}/driver.bash" "${work}/block.bash" "${arch}" "${mtl}")"
   if [ "${got}" = "${want}" ]; then
      pass "${label}: ${got}"
   else
      fail "${label}: got '${got}', want '${want}'"
   fi
}

## amd64, no override -> arch default for BOTH prep and build.
check_case 'amd64 default: prep and build both VirtualBox + qcow2' \
   '--target virtualbox --target qcow2|--target virtualbox --target qcow2' \
   amd64

## amd64, qcow2-only override -> prep keeps the arch default; the BUILD set honors
## the override (qcow2 only).
check_case 'amd64 qcow2-only override: prep arch default, build qcow2 only' \
   '--target virtualbox --target qcow2|--target qcow2' \
   amd64 qcow2

## amd64, explicit virtualbox+qcow2 override -> both sets carry both targets.
check_case 'amd64 explicit virtualbox+qcow2: prep and build both' \
   '--target virtualbox --target qcow2|--target virtualbox --target qcow2' \
   amd64 'virtualbox qcow2'

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-build-official-one prep uses the arch default; the build set honors the multi-target override."

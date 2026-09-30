#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/dm-build-official-one': the
## per-flavor BUILD/UPLOAD VM-target set (flavor_multi_target_args) must honor
## 'dist_build_multi_target_list'.
##
## dm-build-official-one derives an arch-default VM-target set (amd64 -> VirtualBox +
## qcow2; arm64/other -> qcow2) and then applies the 'dist_build_multi_target_list'
## override. The BUILD/UPLOAD set (flavor_multi_target_args) reflects that override:
## a qcow2-only request builds/uploads qcow2 only; an unset request keeps the arch
## default; an explicit list is honored verbatim. This is the user-facing contract.
##
## dm now derives a single multi_target_args array (the earlier separate
## flavor_multi_target_args set was removed); the expected sets below hold under
## both the master and variables.d 'ai' forms of the override handling.
##
## Behavioral: extracts the real VM-target computation from the shipped script (no
## drift) and evaluates it per request. No root, no network, no build.

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

## The whole VM-target computation: from the top-level 'multi_target_args=()' (the
## arch case) through the multi_target_args derivation, up to the next
## section separator ('####...'). Captures both the arch default and the override
## handling regardless of which of the two dm forms is present.
block="$(sed -n '/^multi_target_args=()$/,/^####/p' -- "${subject}")"
if [ -z "${block}" ] || [[ "${block}" != *dist_build_multi_target_list* ]]; then
   fail "could not extract the multi_target_args computation; the assertions below would prove nothing"
   printf '%s\n' "FAILED: extraction" >&2
   exit 1
fi

## Guard the guard: the computation must consult 'dist_build_multi_target_list'. A
## silent revert that hard-wired the target set to the arch default would drop it.
case "${block}" in
   *'dist_build_multi_target_list+x'*)
      true
      ;;
   *)
      fail "the VM-target set is no longer override-aware -- dm-build-official-one dropped the dist_build_multi_target_list override"
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
## present skews the result, so the block must never see an inherited value. Prints
## only the BUILD/UPLOAD set (flavor_multi_target_args), the divergence-invariant.
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
printf '%s\n' "${multi_target_args[*]}"
DRIVER

## $1 label, $2 expected build set, $3 architecture, $4 override list (omit -> unset).
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

## amd64, no override -> arch default (VirtualBox + qcow2).
check_case 'amd64 default: build set is VirtualBox + qcow2' \
   '--target virtualbox --target qcow2' \
   amd64

## amd64, qcow2-only override -> build/upload qcow2 only.
check_case 'amd64 qcow2-only override: build set is qcow2 only' \
   '--target qcow2' \
   amd64 qcow2

## amd64, explicit virtualbox+qcow2 override -> both targets.
check_case 'amd64 explicit virtualbox+qcow2: build set carries both' \
   '--target virtualbox --target qcow2' \
   amd64 'virtualbox qcow2'

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-build-official-one build/upload set honors the multi-target override."

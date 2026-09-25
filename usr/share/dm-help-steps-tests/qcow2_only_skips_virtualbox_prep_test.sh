#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/dm-build-official-one': the
## shared-prep VM-target set must honor 'dist_build_multi_target_list'.
##
## The amd64 default is 'virtualbox + qcow2'. dm-build-official-one passes
## 'multi_target_args' to the shared PREP steps (prepare-build-machine,
## cowbuilder-setup, local-dependencies). If that set ignores the requested
## 'dist_build_multi_target_list', a qcow2-only build still preps VirtualBox: the
## cowbuilder chroot runs the VirtualBox installer (dist-installer-cli, pulling from
## Oracle) even though no VirtualBox image is being built -- the CI '--dry-run'
## VirtualBox failure. So a qcow2-only request must yield NO '--target virtualbox'
## in the prep set, while an unset request keeps the arch default and an explicit
## 'virtualbox qcow2' still preps VirtualBox.
##
## Behavioral: extracts the real 'multi_target_args' computation from the shipped
## script (no drift) and evaluates it per request. No root, no network, no build.

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
## 'multi_target_args=()' (arch case) through 'flavor_multi_target_args=(...)'.
block="$(sed -n '/^multi_target_args=()$/,/^flavor_multi_target_args=/p' -- "${subject}")"
if [ -z "${block}" ]; then
   fail "could not extract the multi_target_args block; the assertions below would prove nothing"
   printf '%s\n' "FAILED: extraction" >&2
   exit 1
fi

## Guard the guard: the prep set must be UNIFIED with the build set (flavor derived
## from the override-aware multi_target_args). The old arch-only form assigned
## 'flavor_multi_target_args=()' first, so extraction stopped before this line and
## the block never contains it -- catching a silent revert to the split form.
# shellcheck disable=SC2016  # the pattern is matched LITERALLY against ${block}
case "${block}" in
   *'flavor_multi_target_args=("${multi_target_args[@]}")'*)
      true
      ;;
   *)
      fail "prep set not unified with the build set -- dm-build-official-one reverted to the arch-only split"
      ;;
esac

work="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup_handler EXIT

printf '%s\n' "${block}" > "${work}/block.bash"
cat > "${work}/driver.bash" <<'DRIVER'
set -o nounset
## architecture and (optionally) dist_build_multi_target_list arrive via the env.
source "$1"
printf '%s|%s\n' "${multi_target_args[*]}" "${flavor_multi_target_args[*]}"
DRIVER

## $1 label, $2 expected "multi|flavor", rest: env assignments for the driver.
check_case() {
   local label="$1" want="$2"
   shift 2
   local got
   got="$(env -u dist_build_multi_target_list "$@" bash "${work}/driver.bash" "${work}/block.bash")"
   if [ "${got}" = "${want}" ]; then
      pass "${label}: ${got}"
   else
      fail "${label}: got '${got}', want '${want}'"
   fi
}

## amd64, no override -> arch default (VirtualBox + qcow2); prep == build set.
check_case 'amd64 default preps VirtualBox + qcow2' \
   '--target virtualbox --target qcow2|--target virtualbox --target qcow2' \
   architecture=amd64

## amd64, qcow2-only -> NO VirtualBox in the prep set (the regression / CI fix).
check_case 'amd64 qcow2-only skips VirtualBox prep' \
   '--target qcow2|--target qcow2' \
   architecture=amd64 dist_build_multi_target_list=qcow2

## amd64, explicit virtualbox+qcow2 -> VirtualBox still prepped when requested.
check_case 'amd64 explicit virtualbox+qcow2 still preps VirtualBox' \
   '--target virtualbox --target qcow2|--target virtualbox --target qcow2' \
   architecture=amd64 'dist_build_multi_target_list=virtualbox qcow2'

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: qcow2-only build does not prep VirtualBox; the override is honored in the shared prep."

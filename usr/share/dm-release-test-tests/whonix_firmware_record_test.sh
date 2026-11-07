#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for #28: firmware is now part of the whonix result identity. rt_publish_result must
## fold -${firmware} into the published lane key for BOTH whonix lanes (whonix-func = inst,
## whonix-pair = leak), so a bios and an efi run of the same pair land in DISTINCT result cells
## and cannot clobber each other. Drives the REAL rt_publish_result (sourced define-only) with a
## stub image_test_results_publish that records the --lane it is handed. Canary: the pre-fix gate
## folded firmware for calamares-install ONLY, so a whonix lane key carried no -${firmware}.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_RELEASE_TEST_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-release-test" ]; then
      subject="${test_dir}/../../bin/dm-release-test"
   else
      subject='/usr/bin/dm-release-test'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-release-test not found at ${subject}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${subject}"

work="$(mktemp --directory --tmpdir dm-release-test-fwrec.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

lane_log="${work}/lane"

## Override the sourced publisher: record the --lane value, print a fake outdir so the caller's
## command substitution succeeds.
# shellcheck disable=SC2317  ## invoked indirectly by rt_publish_result
image_test_results_publish() {
   local prev=""
   local a
   for a in "$@"; do
      [ "${prev}" = "--lane" ] && printf '%s\n' "${a}" >> "${lane_log}"
      prev="${a}"
   done
   printf '%s\n' "${work}/fake-outdir"
}

pass=0
fail=0
check() {
   if [ "$2" = "true" ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1 (got '${3:-}')"; fi
}

# shellcheck disable=SC2034  ## read by rt_publish_result
firmware="bios"
# shellcheck disable=SC2034
interface="lxqt"
# shellcheck disable=SC2034
rt_origin="downloaded"

## --- whonix-func (inst lane) ---
true > "${lane_log}"
# shellcheck disable=SC2034
rt_lane_key="inst"
rt_publish_result whonix 18.2.3.0 someacct whonix-func 0 "" release-checks >/dev/null
func_lane="$(cat -- "${lane_log}")"
case "${func_lane}" in
   whonix-lxqt-inst-bios)
      check "whonix-func lane key folds in -bios" true
      ;;
   *)
      check "whonix-func lane key folds in -bios" false "${func_lane}"
      ;;
esac

## --- whonix-pair (leak lane) ---
true > "${lane_log}"
# shellcheck disable=SC2034
rt_lane_key="leak"
rt_publish_result whonix 18.2.3.0 someacct whonix-pair 0 "" tor-confirm >/dev/null
leak_lane="$(cat -- "${lane_log}")"
case "${leak_lane}" in
   whonix-lxqt-leak-bios)
      check "whonix-pair lane key folds in -bios" true
      ;;
   *)
      check "whonix-pair lane key folds in -bios" false "${leak_lane}"
      ;;
esac

## --- calamares-install still carries its firmware axis (unchanged) ---
true > "${lane_log}"
# shellcheck disable=SC2034
rt_lane_key=""
rt_publish_result kicksecure 18.2.3.0 someacct calamares-install 0 "" Kicksecure >/dev/null
ks_lane="$(cat -- "${lane_log}")"
case "${ks_lane}" in
   kicksecure-lxqt-bios)
      check "calamares-install lane key keeps -bios" true
      ;;
   *)
      check "calamares-install lane key keeps -bios" false "${ks_lane}"
      ;;
esac

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0

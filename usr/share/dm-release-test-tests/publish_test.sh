#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests the shared results-plane publisher (results-publish.bsh), used by
## both image-test-run and dm-release-test. Runs as a normal user into a temp
## results root (owner = the running user, so the chown is a no-op), no network.
## Canary: a result.json that dropped a field or a 'latest' link that did not
## point at the run would fail the assertions below.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib="${RESULTS_PUBLISH_LIB:-}"
if [ -z "${lib}" ]; then
   if [ -f "${test_dir}/../../libexec/image-test/results-publish.bsh" ]; then
      lib="${test_dir}/../../libexec/image-test/results-publish.bsh"
   else
      lib='/usr/libexec/image-test/results-publish.bsh'
   fi
fi
[ -r "${lib}" ] || { printf 'FATAL: results-publish.bsh not found at %s\n' "${lib}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${lib}"

failures=0
work=""

publish_test_cleanup() {
   [ -n "${work}" ] || return 0
   safe-rm --recursive --force -- "${work}"
}

work="$(mktemp --directory --tmpdir dm-release-test-publish.XXXXXX)"
trap publish_test_cleanup EXIT

shot="${work}/shot.png"
printf 'PNGDATA\n' > "${shot}"
results_root="${work}/results"
owner="$(id --user --name)"

outdir="$(image_test_results_publish "${results_root}" "${owner}" \
   "kicksecure-18-2-3-5" "eph-run-kicksecure-18-2-3-5" "calamares-install" \
   0 "true" "${shot}" "Kicksecure")"

check() {
   local label cond
   label="$1"
   cond="$2"
   if [ "${cond}" = 'true' ]; then
      printf 'ok: %s\n' "${label}"
   else
      printf 'FAIL: %s\n' "${label}" >&2
      failures=$((failures + 1))
   fi
}

json="${outdir}/result.json"
check "outdir created" "$([ -d "${outdir}" ] && printf true || printf false)"
check "result.json written" "$([ -f "${json}" ] && printf true || printf false)"
check "screenshot copied" "$([ -f "${outdir}/screenshot.png" ] && printf true || printf false)"
check "json has name" "$(grep --quiet '"name": "kicksecure-18-2-3-5"' -- "${json}" && printf true || printf false)"
check "json has test_user" "$(grep --quiet '"test_user": "eph-run-kicksecure-18-2-3-5"' -- "${json}" && printf true || printf false)"
check "json has mode" "$(grep --quiet '"mode": "calamares-install"' -- "${json}" && printf true || printf false)"
check "json has rc" "$(grep --quiet '"rc": 0' -- "${json}" && printf true || printf false)"
check "json has pass" "$(grep --quiet '"pass": true' -- "${json}" && printf true || printf false)"
check "json has verdict PASS" "$(grep --quiet '"verdict": "PASS"' -- "${json}" && printf true || printf false)"
check "json has expect" "$(grep --quiet '"expect": \["Kicksecure"\]' -- "${json}" && printf true || printf false)"

## latest must point at the run's timestamp dir (basename of outdir).
latest="${results_root}/kicksecure-18-2-3-5/latest"
link_target="$(readlink -- "${latest}" 2>/dev/null || true)"
check "latest symlink points at run" "$([ "${link_target}" = "$(basename -- "${outdir}")" ] && printf true || printf false)"

## verdict mapping (canary: the old binary pass/fail schema published rc 2 as FAIL).
## SETUP_RC(2) -> INCONCLUSIVE (pass=false but NOT a leak); any other non-zero -> FAIL.
inc_out="$(image_test_results_publish "${results_root}" "${owner}" \
   "whonix-18-2-3-5" "persist-leak-whonix" "whonix-pair" \
   2 "false" "" "tor-confirm")"
inc_json="${inc_out}/result.json"
check "rc 2 verdict INCONCLUSIVE" "$(grep --quiet '"verdict": "INCONCLUSIVE"' -- "${inc_json}" && printf true || printf false)"
check "rc 2 pass false" "$(grep --quiet '"pass": false' -- "${inc_json}" && printf true || printf false)"

fail_out="$(image_test_results_publish "${results_root}" "${owner}" \
   "whonix-18-2-3-6" "persist-leak-whonix" "whonix-pair" \
   5 "false" "" "tor-confirm")"
check "rc 5 verdict FAIL" "$(grep --quiet '"verdict": "FAIL"' -- "${fail_out}/result.json" && printf true || printf false)"

if [ "${failures}" -ne 0 ]; then
   printf '\n%s publish assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall publish assertions passed\n'

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: rt_publish_result must FORWARD its shot arg (6th positional) to
## image_test_results_publish's shot_src (7th arg), and forward an empty shot as
## empty. A reverted change that hardcoded "" would silently drop every screenshot
## from the results plane. Sources the REAL dm-release-test (guarded main) and
## stubs image_test_results_publish to capture the forwarded shot_src.

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
[ -r "${subject}" ] || { printf 'FATAL: dm-release-test not found at %s\n' "${subject}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${subject}"

failures=0
## rt_publish_result calls the publisher inside a command substitution (a subshell), so
## a global set by the stub would not escape -- capture via a FILE instead.
capture_file="$(mktemp --tmpdir dm-release-test-shotcap.XXXXXX)"
argv_file="$(mktemp --tmpdir dm-release-test-argvcap.XXXXXX)"
shot_cap_cleanup() { safe-rm --force -- "${capture_file}" "${argv_file}"; }
trap shot_cap_cleanup EXIT
captured_shot='UNSET'

## Stub the publisher: record the 7th positional (shot_src) the lane forwards AND the
## whole argv (to assert option passthrough), and print an outdir so rt_publish_result's
## summary line does not choke.
# shellcheck disable=SC2329  ## invoked indirectly by rt_publish_result
image_test_results_publish() {
   printf '%s' "$7" > "${capture_file}"
   printf '%s\n' "$*" > "${argv_file}"
   printf '%s' "/nonexistent/outdir"
}

## Globals rt_publish_result reads (interface is part of the results subtree name).
# shellcheck disable=SC2034
RESULTS_ROOT='/nonexistent/results'
# shellcheck disable=SC2034
RESULTS_OWNER='nobody'
# shellcheck disable=SC2034
interface='lxqt'
## Firmware axis: rt_publish_result reads it to disambiguate the Calamares-install lane
## (bios vs efi are separate goldens). Non-install lanes ignore it.
# shellcheck disable=SC2034
firmware='efi'

assert_shot() {
   local label="$1" expected="$2"
   if [ "${captured_shot}" = "${expected}" ]; then
      printf 'ok: %s\n' "${label}"
   else
      printf 'FAIL: %s: got %s, expected %s\n' "${label}" "'${captured_shot}'" "'${expected}'" >&2
      failures=$((failures + 1))
   fi
}

## A real shot path must reach shot_src.
rt_publish_result kicksecure 18.2.3.5 acct calamares-install 0 /nonexistent/shot.png Kicksecure >/dev/null
captured_shot="$(cat -- "${capture_file}")"
assert_shot "rt_publish_result forwards a shot path" '/nonexistent/shot.png'

## An empty shot (download failure / packet-based lane) must forward as empty.
rt_publish_result whonix 18.2.3.5 acct whonix-pair 0 '' tor-confirm >/dev/null
captured_shot="$(cat -- "${capture_file}")"
assert_shot "rt_publish_result forwards an empty shot" ''

## A non-empty rt_check_log (a FAILED check's output) threads as --step-stderr-file,
## so the run record explains WHY it failed.
clog="$(mktemp --tmpdir dm-release-test-clog.XXXXXX)"
printf 'check 8 (systemcheck) FAILED:\nsystemcheck unknown option: --ci\n' > "${clog}"
# shellcheck disable=SC2034  ## read by the sourced rt_publish_result (dynamic scope)
rt_check_log="${clog}"
rt_publish_result kicksecure 18.2.3.5 acct calamares-install 5 '' Kicksecure >/dev/null
if grep --quiet -- "--step-stderr-file ${clog}" "${argv_file}"; then
   printf 'ok: rt_publish_result threads rt_check_log as --step-stderr-file\n'
else
   printf 'FAIL: --step-stderr-file not forwarded: %s\n' "$(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi

## Canary: rt_check_log is consumed ONCE -- the next publish (no failed check) must
## NOT re-forward the stale path.
rt_publish_result kicksecure 18.2.3.5 acct calamares-install 0 '' Kicksecure >/dev/null
if grep --quiet -- '--step-stderr-file' "${argv_file}"; then
   printf 'FAIL: rt_check_log leaked to the next publish\n' >&2
   failures=$((failures + 1))
else
   printf 'ok: rt_check_log consumed once (reset after use)\n'
fi
safe-rm --force -- "${clog}"

## Firmware is part of the Calamares-install lane identity: bios and efi installs produce
## DIFFERENT screenshots (firmware menu, boot chrome), so they must land in separate
## subtrees / sids / goldens and separate overview rows -- never collide. Assert the
## firmware suffix reaches BOTH the results subtree name (3rd positional) and --lane.
# shellcheck disable=SC2034  ## read by the sourced rt_publish_result (dynamic scope)
firmware='bios'
rt_publish_result kicksecure 18.2.3.6 acct calamares-install 0 '' Kicksecure >/dev/null
if grep --quiet -- '--lane kicksecure-lxqt-bios ' "${argv_file}"; then
   printf 'ok: calamares-install --lane carries firmware (kicksecure-lxqt-bios)\n'
else
   printf 'FAIL: calamares-install --lane missing firmware: %s\n' "$(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi
if grep --quiet -- 'kicksecure-lxqt-bios-18-2-3-6' "${argv_file}"; then
   printf 'ok: calamares-install subtree name carries firmware\n'
else
   printf 'FAIL: calamares-install subtree name missing firmware: %s\n' "$(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi

## A non-install lane (whonix-pair) has NO firmware axis -- its lane must stay bare even
## when firmware is set, or EFI/BIOS would wrongly fork packet-based runs.
rt_publish_result whonix 18.2.3.6 acct whonix-pair 0 '' tor-confirm >/dev/null
if grep --quiet -- '--lane whonix-lxqt ' "${argv_file}" \
   && ! grep --quiet -- 'whonix-lxqt-bios' "${argv_file}"; then
   printf 'ok: whonix-pair lane carries no firmware suffix\n'
else
   printf 'FAIL: whonix-pair lane wrongly forked by firmware: %s\n' "$(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi

if [ "${failures}" -ne 0 ]; then
   printf '\n%s shot-publish assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall shot-publish assertions passed\n'

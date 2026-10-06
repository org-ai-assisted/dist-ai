#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: rt_publish_result must FORWARD its shot arg (6th positional) to
## image_test_results_publish's shot_src (8th arg), and forward an empty shot as
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
shot_cap_cleanup() { safe-rm --force -- "${capture_file}"; }
trap shot_cap_cleanup EXIT
captured_shot='UNSET'

## Stub the publisher: record the 8th positional (shot_src) the lane forwards, and
## print an outdir so rt_publish_result's summary line does not choke.
# shellcheck disable=SC2329  ## invoked indirectly by rt_publish_result
image_test_results_publish() {
   printf '%s' "$8" > "${capture_file}"
   printf '%s' "/nonexistent/outdir"
}

## Globals rt_publish_result reads (interface is part of the results subtree name).
# shellcheck disable=SC2034
RESULTS_ROOT='/nonexistent/results'
# shellcheck disable=SC2034
RESULTS_OWNER='nobody'
# shellcheck disable=SC2034
interface='lxqt'

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

if [ "${failures}" -ne 0 ]; then
   printf '\n%s shot-publish assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall shot-publish assertions passed\n'

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The CLI whonix lane's Workstation milestone frames (booted / tor-confirmed / final) are the
## SAME static getty login console: a CLI edition has NO graphical WS session, so the
## release-check battery logs in programmatically over guestcontrol and the on-screen console
## never advances. image-dup-check's 3-cluster gate would then FALSE-FAIL an otherwise-passing
## run (seen live: the CLI lane published FAIL rc=5 on 3 byte-identical console frames), so
## rt_dup_allow_tokens emits the WS-milestone --allow tokens for interface=cli and NOTHING for
## lxqt (whose desktop genuinely advances and must keep the full gate).
##
## Drives the REAL dm-release-test helper (sourced, no VM/root) AND the REAL image-dup-check, so
## the test proves the emitted tokens actually exempt those frame STEMS (a name drift in either
## place breaks it) and -- the canary -- that WITHOUT the tokens (the lxqt path) the same three
## identical frames still FAIL the 3-cluster gate.

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

checker="${IMAGE_DUP_CHECK_BIN:-}"
if [ -z "${checker}" ]; then
   if [ -f "${test_dir}/../../bin/image-dup-check" ]; then
      checker="${test_dir}/../../bin/image-dup-check"
   else
      checker='/usr/bin/image-dup-check'
   fi
fi
[ -r "${checker}" ] || { printf '%s\n' "FATAL: image-dup-check not found at ${checker}" >&2; exit 1; }

magick_bin='convert'
if type -P magick >/dev/null 2>&1; then
   magick_bin='magick'
fi

# shellcheck source=../../bin/dm-release-test
source "${subject}"

pass=0
fail=0
assert() {
   local label="$1"
   shift
   if "$@"; then
      pass=$((pass + 1))
      printf '%s\n' "PASS: ${label}"
   else
      fail=$((fail + 1))
      printf '%s\n' "FAIL: ${label}" >&2
   fi
}

workdir="$(mktemp --directory --tmpdir cli-milestone-dup-allow-test.XXXXXX)"
# shellcheck disable=SC2317  ## invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${workdir}"; }
trap cleanup EXIT

## --- the pure helper emits the right tokens, by interface -------------------------------------
assert "cli emits the three WS milestone --allow tokens" \
   test "$(rt_dup_allow_tokens cli)" = "$(printf '%s\n' workstation-booted workstation-tor-confirmed workstation-final)"
assert "lxqt emits NO tokens (keeps the full gate)" \
   test -z "$(rt_dup_allow_tokens lxqt)"

## --- the tokens actually exempt those frame stems in the REAL image-dup-check -----------------
## Three byte-identical WS console frames (named as the whonix lane publishes them) + one
## distinct gateway frame -> a 3-cluster that trips --min-cluster 3.
shot="${workdir}/shot"
mkdir -- "${shot}"
"${magick_bin}" -size 128x96 xc:'#101418' "${shot}/whonix-func-25-workstation-booted.png"
cp -- "${shot}/whonix-func-25-workstation-booted.png" "${shot}/whonix-func-50-workstation-tor-confirmed.png"
cp -- "${shot}/whonix-func-25-workstation-booted.png" "${shot}/whonix-func-95-workstation-final.png"
"${magick_bin}" -size 128x96 xc:'#3a2e14' "${shot}/whonix-func-20-gateway-booted.png"

## Build the --allow args the gate builds, from the REAL helper, for each interface.
cli_allow=()
tok=''
while IFS= read -r tok; do
   [ -n "${tok}" ] && cli_allow+=( --allow "${tok}" )
done < <(rt_dup_allow_tokens cli)

cli_rc=0
"${checker}" --min-cluster 3 "${cli_allow[@]}" -- "${shot}" >/dev/null 2>&1 || cli_rc=$?
assert "cli allow set exempts the static WS console milestones (no false FAIL)" \
   test "${cli_rc}" -eq 0

## CANARY: the lxqt path emits no tokens, so the SAME three identical frames must still FAIL --
## otherwise the test would pass even if the helper emitted nothing and the fix were a no-op.
gui_rc=0
"${checker}" --min-cluster 3 -- "${shot}" >/dev/null 2>&1 || gui_rc=$?
assert "lxqt (no allow set) still FAILS the 3-identical-frame cluster" \
   test "${gui_rc}" -eq 1

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1

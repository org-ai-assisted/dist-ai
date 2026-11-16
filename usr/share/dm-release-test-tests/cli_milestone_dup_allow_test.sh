#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The milestone-screenshot integrity gate, by lane (dm-release-test rt_cluster_gate_enabled +
## the exact image-dup-check command each branch runs):
##  - GUI: the CLUSTER gate. A desktop visibly advances, so N byte-identical milestone frames ==
##    a stuck capture published under many names (image-dup-check --min-cluster 3).
##  - CLI: NOT the cluster gate -- a CLI edition has no graphical session, so every idle milestone
##    is the SAME static getty console by design and the cluster gate can only FALSE-FAIL. But a
##    CLI capture can still FREEZE, and the check-8 verdict is driven over guestcontrol (blind of
##    the screen), so a frozen grab would pass undetected. The console-login frame is DRIVEN to a
##    logged-in shell, so on any live run it must differ from the idle workstation-booted frame;
##    identical == a frozen capture. So the CLI branch runs a capture-LIVENESS assertion
##    (image-dup-check --no-cluster --require-distinct console-login workstation-booted) in place
##    of the cluster gate -- NOT a per-name --allow, which can drop a genuine stuck cluster below
##    --min-cluster and silently weaken a GUI lane.
##
## Drives the REAL dm-release-test helper (sourced, no VM/root) AND the REAL image-dup-check with
## the EXACT arguments each branch passes: the CLI liveness gate PASSES a live run whose idle frames
## legitimately repeat, FAILS a four-frame frozen capture (console-login frozen onto the idle
## frames), and the GUI cluster gate still FIRES -- so neither gate is a vacuous pass.

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
## $2 = expected rc of the REAL image-dup-check invoked with $3.. (the exact gate argv).
expect_gate() {
   local label="$1" want="$2"
   shift 2
   local got=0
   "${checker}" "$@" >/dev/null 2>&1 || got=$?
   if [ "${got}" -eq "${want}" ]; then
      pass=$((pass + 1)); printf '%s\n' "PASS: ${label}"
   else
      fail=$((fail + 1)); printf '%s\n' "FAIL: ${label} (rc=${got}, want ${want})" >&2
   fi
}

workdir="$(mktemp --directory --tmpdir cli-milestone-dup-test.XXXXXX)"
# shellcheck disable=SC2317  ## invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${workdir}"; }
trap cleanup EXIT

## --- the gate decision, by interface ----------------------------------------------------------
## assert checks for SUCCESS, so the negative (cli must return non-zero) is an explicit if/else.
if rt_cluster_gate_enabled cli; then
   fail=$((fail + 1)); printf '%s\n' "FAIL: cli must NOT get the cluster gate" >&2
else
   pass=$((pass + 1)); printf '%s\n' "PASS: cli does NOT get the cluster gate (static console; liveness instead)"
fi
assert "lxqt GETS the cluster gate" rt_cluster_gate_enabled lxqt

## --- CLI liveness gate: the EXACT argv the CLI branch runs ------------------------------------
## A live func-CLI run: 3 idle frames legitimately identical (booted/tor-confirmed/final) + a
## DISTINCT driven console-login + a distinct gateway. The liveness gate must PASS it (the cluster
## gate would FALSE-FAIL on the 3 identical idle frames -- see the GUI canary below).
live="${workdir}/cli-live"
mkdir -- "${live}"
"${magick_bin}" -size 128x96 xc:'#101418' "${live}/25-workstation-booted.png"
cp -- "${live}/25-workstation-booted.png" "${live}/50-workstation-tor-confirmed.png"
cp -- "${live}/25-workstation-booted.png" "${live}/95-workstation-final.png"
"${magick_bin}" -size 128x96 xc:'#2a3340' "${live}/58-console-login.png"       ## logged-in shell
"${magick_bin}" -size 128x96 xc:'#181c10' "${live}/20-gateway-booted.png"
expect_gate "CLI liveness PASSES a live run (idle frames legitimately repeat)" 0 \
   --no-cluster --require-distinct console-login workstation-booted -- "${live}"

## FROZEN capture: the grab stuck, so console-login is byte-identical to the idle frames (four
## identical frames). The verdict is guestcontrol-driven and would pass; the liveness gate FAILS it.
frozen="${workdir}/cli-frozen"
mkdir -- "${frozen}"
"${magick_bin}" -size 128x96 xc:'#101418' "${frozen}/25-workstation-booted.png"
cp -- "${frozen}/25-workstation-booted.png" "${frozen}/50-workstation-tor-confirmed.png"
cp -- "${frozen}/25-workstation-booted.png" "${frozen}/58-console-login.png"    ## frozen onto idle
cp -- "${frozen}/25-workstation-booted.png" "${frozen}/95-workstation-final.png"
expect_gate "CLI liveness FAILS a four-frame frozen capture (console-login == booted)" 1 \
   --no-cluster --require-distinct console-login workstation-booted -- "${frozen}"

## --- GUI CANARY: the cluster gate the GUI branch runs still FIRES -----------------------------
## Proves "CLI uses liveness instead of cluster" is a real behavior difference, not a gate that
## never fired anyway: the SAME 3 identical idle frames FAIL the GUI cluster gate.
expect_gate "GUI cluster gate FAILS 3 identical frames (--min-cluster 3)" 1 \
   --min-cluster 3 -- "${live}"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1

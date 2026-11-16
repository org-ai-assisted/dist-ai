#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## image-dup-check FAILs a run when >= 3 milestone frames are byte-identical (a capture that did
## not advance, published under many names). That premise -- frames SHOULD advance -- holds only
## for a GUI lane whose desktop visibly changes. A CLI edition has NO graphical session: every
## milestone is the SAME static getty console by design (func: workstation-booted/-tor-confirmed/
## -final; leak: workstation-desktop/-tor-confirmed), so the gate can only FALSE-FAIL it (seen
## live: a CLI inst lane published FAIL rc=5 on 3 byte-identical console frames). So
## rt_dup_check_enabled SKIPS the gate for interface=cli and keeps it for the GUI lanes -- not a
## per-name --allow, which can drop a GENUINE stuck cluster below --min-cluster and silently weaken
## the gate on a different lane.
##
## Drives the REAL dm-release-test helper (sourced, no VM/root) AND the REAL image-dup-check: the
## gate is proven to still FIRE when enabled (the GUI canary), so "skip for cli" is not a vacuous
## pass.

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

workdir="$(mktemp --directory --tmpdir cli-milestone-dup-test.XXXXXX)"
# shellcheck disable=SC2317  ## invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${workdir}"; }
trap cleanup EXIT

## --- the gate decision, by interface ----------------------------------------------------------
## assert checks for SUCCESS, so the negative (cli must return non-zero) is an explicit if/else.
if rt_dup_check_enabled cli; then
   fail=$((fail + 1)); printf '%s\n' "FAIL: cli must SKIP the milestone dup gate" >&2
else
   pass=$((pass + 1)); printf '%s\n' "PASS: cli SKIPS the milestone dup gate (static console, no advance)"
fi
assert "lxqt KEEPS the milestone dup gate" rt_dup_check_enabled lxqt

## --- CANARY: when enabled (GUI), the REAL gate still FAILS 3 identical frames ------------------
## Proves "skip for cli" is a real behavior difference, not a gate that never fired anyway.
shot="${workdir}/shot"
mkdir -- "${shot}"
"${magick_bin}" -size 128x96 xc:'#101418' "${shot}/25-workstation-booted.png"
cp -- "${shot}/25-workstation-booted.png" "${shot}/50-workstation-tor-confirmed.png"
cp -- "${shot}/25-workstation-booted.png" "${shot}/95-workstation-final.png"
gui_rc=0
"${checker}" --min-cluster 3 -- "${shot}" >/dev/null 2>&1 || gui_rc=$?
assert "the enabled gate FAILS a 3-identical-frame cluster (GUI canary)" \
   test "${gui_rc}" -eq 1

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1

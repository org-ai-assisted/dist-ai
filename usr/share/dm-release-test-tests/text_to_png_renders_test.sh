#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-text-to-png renders the state-card text to a PNG. It MUST produce a frame with
## actual text, not a blank rectangle: a near-black hex fill ('#111111') renders the
## label BLANK on ImageMagick 7 (no text, no error), which is how the vm-defined /
## firmware-state cards came out all-white. Drives the REAL tool; asserts non-blank.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

resolve() {
   ## $1 env-var-name, $2 basename
   local v="${!1:-}"
   if [ -n "${v}" ]; then
      printf '%s' "${v}"
      return
   fi
   if [ -f "${test_dir}/../../bin/$2" ]; then
      printf '%s' "${test_dir}/../../bin/$2"
      return
   fi
   printf '%s' "/usr/bin/$2"
}
text_to_png="$(resolve DM_TEXT_TO_PNG_BIN dm-text-to-png)"
blank_check="$(resolve IMAGE_BLANK_CHECK_BIN image-blank-check)"
[ -r "${text_to_png}" ] || { printf '%s\n' "FATAL: dm-text-to-png not found at ${text_to_png}" >&2; exit 1; }
[ -r "${blank_check}" ] || { printf '%s\n' "FATAL: image-blank-check not found at ${blank_check}" >&2; exit 1; }

workdir="$(mktemp --directory --tmpdir text-to-png-test.XXXXXX)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

pass=0
fail=0

## Render a representative multi-line state card.
card="${workdir}/card.png"
printf '%s\n' \
   "[state card -- rendered from VBoxManage showvminfo, not a screenshot]" \
   "VM defined (pre-boot)" \
   "" \
   'VMState="poweroff"' \
   'firmware="EFI"' \
   "memory=2048" \
   'SecureBoot="1"' \
   | bash -- "${text_to_png}" "${card}"

if [ -s "${card}" ]; then
   printf '%s\n' "PASS: dm-text-to-png produced a non-empty PNG"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: dm-text-to-png produced no/empty PNG" >&2
   fail=$((fail + 1))
fi

## The rendered card must NOT be degenerate (this is the regression: the old '#111111'
## fill made it uniform white, which image-blank-check flags).
if "${blank_check}" "${card}" >/dev/null 2>&1; then
   printf '%s\n' "PASS: rendered card carries content (not all-white/all-black)"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: rendered card is degenerate (blank) -- the text did not render" >&2
   fail=$((fail + 1))
fi

## Empty stdin must be rejected, not emit a blank card.
rc=0
bash -- "${text_to_png}" "${workdir}/empty.png" </dev/null >/dev/null 2>&1 || rc=$?
if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "PASS: empty input is rejected (rc=${rc})"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: empty input was accepted" >&2
   fail=$((fail + 1))
fi

printf '%s\n' "===== text_to_png_renders_test: ${pass} pass, ${fail} fail ====="
[ "${fail}" -eq 0 ]

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## image-text-assert gates a milestone screenshot on CONTENT: its OCR text must contain the
## stage's EXPECTED tokens, so a non-blank but WRONG frame (the expected words absent) fails the
## run instead of publishing a mislabeled shot. image-ocr-sidecar writes the OCR text beside the
## shot. Drives the REAL tools + REAL tesseract against a rendered fixture (shared with the
## redact test); no root, no VM.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

resolve_bin() {
   ## $1 = tool basename, $2 = override env value
   local tool="$1" override="$2"
   if [ -n "${override}" ]; then
      printf '%s\n' "${override}"
   elif [ -f "${test_dir}/../../bin/${tool}" ]; then
      printf '%s\n' "${test_dir}/../../bin/${tool}"
   else
      printf '%s\n' "/usr/bin/${tool}"
   fi
}

assert_bin="$(resolve_bin image-text-assert "${IMAGE_TEXT_ASSERT_BIN:-}")"
sidecar_bin="$(resolve_bin image-ocr-sidecar "${IMAGE_OCR_SIDECAR_BIN:-}")"
[ -r "${assert_bin}" ] || { printf '%s\n' "FATAL: image-text-assert not found at ${assert_bin}" >&2; exit 1; }
[ -r "${sidecar_bin}" ] || { printf '%s\n' "FATAL: image-ocr-sidecar not found at ${sidecar_bin}" >&2; exit 1; }

fixture_gen="${test_dir}/make-redact-fixture.py"
[ -x "${fixture_gen}" ] || { printf '%s\n' "FATAL: make-redact-fixture.py not found/executable at ${fixture_gen}" >&2; exit 1; }

## tesseract drives the OCR these tools read by. It is an OVH e2e-lane dependency (the content
## gate + sidecar run only inside the install lane, which already uses tesseract), not a unit-CI
## tool, so its absence is a SKIP, never a silent pass.
if ! tesseract --version >/dev/null 2>&1; then
   printf '%s\n' "SKIP: tesseract not available (e2e-lane OCR dependency)" >&2
   ## style-ok: allow-skip: tesseract is an e2e-lane OCR dependency, absent in the unit-CI env
   exit 77
fi

work="$(mktemp --directory --tmpdir image-text-assert-test.XXXXXX)"
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## The shared fixture renders OCR-friendly markers: 'ALPHA 12.345678 BRAVO' and
## 'CHARLIE luks-... DELTA'. ALPHA/BRAVO/CHARLIE/DELTA are the stable present-tokens; ZULU is absent.
img="${work}/frame.png"
"${fixture_gen}" "${img}"

pass=0
fail=0
expect_rc() {
   ## $1 description, $2 expected-rc, $3.. args
   local desc="$1" want="$2"
   shift 2
   local got=0
   "$@" >/dev/null 2>&1 || got=$?
   if [ "${got}" -eq "${want}" ]; then
      printf '%s\n' "PASS: ${desc}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${desc} (rc=${got}, want ${want})" >&2
      fail=$((fail + 1))
   fi
}

## Present tokens pass; an absent token fails.
expect_rc "all expected tokens present -> pass"      0 "${assert_bin}" --expect ALPHA --expect BRAVO -- "${img}"
expect_rc "an absent token -> fail"                  1 "${assert_bin}" --expect ZULU -- "${img}"
expect_rc "present + absent mix -> fail"             1 "${assert_bin}" --expect ALPHA --expect ZULU -- "${img}"
## Case- and whitespace-insensitive matching.
expect_rc "case-insensitive match -> pass"           0 "${assert_bin}" --expect alpha --expect bravo -- "${img}"

## FAIL-CLOSED: no expectation, or an only-empty expectation, asserts nothing -> usage error.
expect_rc "no --expect is a usage error"             2 "${assert_bin}" -- "${img}"
expect_rc "empty --expect asserts nothing (usage)"   2 "${assert_bin}" --expect '' -- "${img}"
## OCR read failure (missing image) -> exit 3 (transient, distinct from a config error), never a pass.
expect_rc "missing image -> OCR-read error (not pass)" 3 "${assert_bin}" --expect ALPHA -- "${work}/nope.png"

## --spec FILE: expected tokens from a repo golden ('#' comments + blank lines ignored).
printf '%s\n' '# stage golden' 'ALPHA' '' 'CHARLIE' > "${work}/spec_ok.txt"
printf '%s\n' 'ZULU' > "${work}/spec_bad.txt"
expect_rc "--spec with present tokens -> pass"       0 "${assert_bin}" --spec "${work}/spec_ok.txt" -- "${img}"
expect_rc "--spec with an absent token -> fail"      1 "${assert_bin}" --spec "${work}/spec_bad.txt" -- "${img}"
## --spec that yields only comments/blanks asserts nothing -> usage error.
printf '%s\n' '# only a comment' '' > "${work}/spec_empty.txt"
expect_rc "--spec of only comments asserts nothing (usage)" 2 "${assert_bin}" --spec "${work}/spec_empty.txt" -- "${img}"
## A non-UTF-8 golden is a BROKEN golden -> exit 2 (not an uncaught UnicodeDecodeError traceback + exit 1).
## A rendered PNG's bytes are not valid UTF-8 (its header is not), so reuse it as a binary spec.
cp -- "${img}" "${work}/spec_binary.txt"
expect_rc "non-UTF-8 --spec is a broken golden (exit 2)" 2 "${assert_bin}" --spec "${work}/spec_binary.txt" -- "${img}"

## image-ocr-sidecar writes <image>.ocr.txt carrying the OCR text.
"${sidecar_bin}" -- "${img}" >/dev/null 2>&1
if [ -f "${img}.ocr.txt" ] && grep --quiet --ignore-case ALPHA "${img}.ocr.txt"; then
   printf '%s\n' "PASS: ocr-sidecar writes a sidecar carrying the frame text"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: ocr-sidecar did not write a sidecar with the frame text" >&2
   fail=$((fail + 1))
fi

## Every SHIPPED golden must assert SOMETHING: an empty/all-comment golden exits 2 (config) on
## any image and would, in the lane, silently disable that stage's validation. A well-formed
## golden returns 0/1/3 on the fixture (present/absent/ocr), never 2.
golden_dir="${test_dir}/../dm-calamares-install-golden"
if [ -d "${golden_dir}" ]; then
   for golden in "${golden_dir}"/*.tokens; do
      [ -f "${golden}" ] || continue
      got=0
      "${assert_bin}" --spec "${golden}" -- "${img}" >/dev/null 2>&1 || got=$?
      if [ "${got}" -ne 2 ]; then
         printf '%s\n' "PASS: shipped golden ${golden##*/} asserts something (rc=${got})"
         pass=$((pass + 1))
      else
         printf '%s\n' "FAIL: shipped golden ${golden##*/} asserts NOTHING (rc=2)" >&2
         fail=$((fail + 1))
      fi
   done
fi

## CANARY: a tool that always passed would fail every '1'/'2'/'3' case above; one that always
## failed would fail every '0' case. Both directions are asserted, so the suite is non-vacuous.

printf '%s\n' "===== image_text_assert_test: ${pass} pass, ${fail} fail ====="
[ "${fail}" -eq 0 ]

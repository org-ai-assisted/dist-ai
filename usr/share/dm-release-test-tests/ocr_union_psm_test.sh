#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The content gate OCRs varied layouts: a multi-region GUI installer page (a full-width row
## separated by whitespace -- the "Encrypt system" checkbox) AND a simple centered menu (GRUB
## "Choose boot mode"). NO single tesseract page-segmentation mode reads both: psm 6 (uniform
## block) drops the separated GUI row; psm 3 (auto layout) mis-segments the centered menu. So
## image-text-assert / image-ocr-sidecar default to the UNION of psm 3 + psm 6. This guards that
## union: a token present under ONLY one mode is still matched, while either mode ALONE misses the
## other's token (the real wedge -- partitions-luks-filled failed because psm 6 dropped "Encrypt
## system" though it was on screen).
##
## Deterministic + version-independent: tesseract is STUBBED to return a different token per --psm
## (mirroring the real per-mode difference), so this runs in unit CI without real tesseract and
## cannot flake on a tesseract version that segments differently. The REAL per-frame behavior is
## verified on the e2e lane (image_text_assert_test.sh drives real tesseract on a rendered frame).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

resolve_bin() {
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

work="$(mktemp --directory --tmpdir ocr-union-psm-test.XXXXXX)"
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## Stub tesseract on PATH: GUIROW reads ONLY under psm 3 (auto layout), MENUTOKEN ONLY under psm 6
## (uniform block). argv is `tesseract <img> stdout --psm N [tsv]`; emit plain text (no tsv path
## exercised here). Mirrors the real split that no single mode reads both tokens.
stub="${work}/bin"
mkdir --parents -- "${stub}"
cat > "${stub}/tesseract" <<'STUB'
#!/bin/bash
psm=""
while [ "$#" -gt 0 ]; do
   case "$1" in
      --psm) psm="$2"; shift 2 ;;
      *) shift ;;
   esac
done
case "${psm}" in
   3) printf '%s\n' "GUIROW read only by auto layout" ;;
   6) printf '%s\n' "MENUTOKEN read only by uniform block" ;;
   *) printf '%s\n' "fallback text" ;;
esac
exit 0
STUB
chmod +x -- "${stub}/tesseract"
export PATH="${stub}:${PATH}"

img="${work}/frame.png"
true > "${img}"   ## the stub ignores the path; a real file keeps the tools' own checks happy.

pass=0
fail=0
expect_rc() {
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

## DEFAULT (union 3+6) reads BOTH tokens -> pass. This is the fix.
expect_rc "union (default) matches a token each single mode misses" \
   0 "${assert_bin}" --expect GUIROW --expect MENUTOKEN -- "${img}"
## Each single mode ALONE misses the OTHER mode's token -> fail. Proves the union is doing the work
## (non-vacuous: without the union, the default would behave like one of these).
expect_rc "psm 6 alone MISSES the auto-layout token (the real bug)" \
   1 "${assert_bin}" --psm 6 --expect GUIROW -- "${img}"
expect_rc "psm 3 alone MISSES the uniform-block token" \
   1 "${assert_bin}" --psm 3 --expect MENUTOKEN -- "${img}"
## Control: each single mode DOES read its own token (the stub is not just failing everything).
expect_rc "psm 6 alone reads its uniform-block token (control)" \
   0 "${assert_bin}" --psm 6 --expect MENUTOKEN -- "${img}"
expect_rc "psm 3 alone reads its auto-layout token (control)" \
   0 "${assert_bin}" --psm 3 --expect GUIROW -- "${img}"

## image-ocr-sidecar default (union) publishes text carrying BOTH tokens, so a golden is
## approvable from the sidecar regardless of which mode read a given row.
"${sidecar_bin}" -- "${img}" >/dev/null 2>&1
if [ -f "${img}.ocr.txt" ] \
   && grep --quiet GUIROW "${img}.ocr.txt" && grep --quiet MENUTOKEN "${img}.ocr.txt"; then
   printf '%s\n' "PASS: ocr-sidecar default (union) carries both single-mode tokens"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: ocr-sidecar default did not carry both tokens" >&2
   fail=$((fail + 1))
fi
## A single-mode sidecar carries only that mode's token (canary: the default above is the union).
"${sidecar_bin}" --psm 6 --suffix .psm6.txt -- "${img}" >/dev/null 2>&1
if [ -f "${img}.psm6.txt" ] \
   && grep --quiet MENUTOKEN "${img}.psm6.txt" && ! grep --quiet GUIROW "${img}.psm6.txt"; then
   printf '%s\n' "PASS: ocr-sidecar --psm 6 carries only the uniform-block token (non-vacuous)"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: ocr-sidecar --psm 6 did not isolate the single-mode token" >&2
   fail=$((fail + 1))
fi

printf '%s\n' "===== ocr_union_psm_test: ${pass} pass, ${fail} fail ====="
[ "${fail}" -eq 0 ]

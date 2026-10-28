#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The content gate OCRs varied layouts: a multi-region GUI installer page (a full-width row
## separated by whitespace -- the "Encrypt system" checkbox) AND a simple centered menu (GRUB
## "Choose boot mode"). NO single tesseract page-segmentation mode reads both: psm 6 (uniform
## block) drops the separated GUI row; psm 3 (auto layout) mis-segments the centered menu. So
## image-text-assert / image-ocr-sidecar OCR under BOTH psm 3 and psm 6 by default and a token is
## present if it appears in EITHER transcript.
##
## This guards three properties the design must hold:
##   (1) a token present under ONLY one mode is still matched (the fix: partitions-luks-filled
##       failed because psm 6 dropped "Encrypt system" though it was on screen);
##   (2) NO SEAM: the transcripts are matched INDEPENDENTLY, never concatenated, so a multi-word
##       golden cannot be matched across the boundary between two transcripts (end of one + start
##       of the other). Every shipped golden is a multi-word phrase, so this is reachable;
##   (3) a per-mode OCR FAILURE does not hide a real mismatch: if one mode errors but the other
##       reads, the read decides (mismatch stays a mismatch); only when ALL modes fail is it an
##       ocr-error.
##
## Deterministic + version-independent: tesseract is STUBBED (output + exit per --psm, via env), so
## this runs in unit CI without real tesseract and cannot flake on a tesseract version that
## segments differently. The REAL per-frame behavior is on the e2e lane (image_text_assert_test.sh
## drives real tesseract on a rendered frame).

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

## Stub tesseract on PATH. Default: GUIROW reads ONLY under psm 3 (auto layout), MENUTOKEN ONLY
## under psm 6 (uniform block) -- the real split that no single mode reads both. A case overrides
## the per-psm output/exit via env (TESS_P3_OUT / TESS_P3_RC / TESS_P6_OUT / TESS_P6_RC) to drive
## the seam and per-mode-failure paths. argv is `tesseract <img> stdout --psm N [tsv]`.
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
bin=""
case "${psm}" in
   3) out="${TESS_P3_OUT-GUIROW read only by auto layout}"; rc="${TESS_P3_RC:-0}"; bin="${TESS_P3_BIN:-}" ;;
   6) out="${TESS_P6_OUT-MENUTOKEN read only by uniform block}"; rc="${TESS_P6_RC:-0}"; bin="${TESS_P6_BIN:-}" ;;
   *) out="fallback text"; rc=0 ;;
esac
if [ -n "${bin}" ]; then
   ## non-UTF-8 output for this mode (tesseract emitting invalid bytes) -- exercises the decode-error path.
   printf 'ok \xff\xfe tail\n'
else
   printf '%s\n' "${out}"
fi
exit "${rc}"
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

## (1) DEFAULT matches a token each single mode misses; each single mode ALONE misses the other's.
expect_rc "default matches a token each single mode misses" \
   0 "${assert_bin}" --expect GUIROW --expect MENUTOKEN -- "${img}"
expect_rc "psm 6 alone MISSES the auto-layout token (the real bug)" \
   1 "${assert_bin}" --psm 6 --expect GUIROW -- "${img}"
expect_rc "psm 3 alone MISSES the uniform-block token" \
   1 "${assert_bin}" --psm 3 --expect MENUTOKEN -- "${img}"
expect_rc "psm 6 alone reads its own token (control)" \
   0 "${assert_bin}" --psm 6 --expect MENUTOKEN -- "${img}"
expect_rc "psm 3 alone reads its own token (control)" \
   0 "${assert_bin}" --psm 3 --expect GUIROW -- "${img}"

## (2) NO SEAM: psm3="alpha beta", psm6="gamma delta". The multi-word token "beta gamma" is in
## NEITHER transcript -- it only forms at the join of the two. It must be reported MISSING (rc 1).
## A joined-blob union would normalize "alpha beta\ngamma delta" to "alpha beta gamma delta" and
## FALSELY match it (rc 0) -- the canary for the seam bug.
expect_rc "a cross-transcript seam phrase is NOT matched (no false pass)" \
   1 env TESS_P3_OUT='alpha beta' TESS_P6_OUT='gamma delta' "${assert_bin}" --expect 'beta gamma' -- "${img}"
## Positive controls: each real per-transcript token IS matched.
expect_rc "a token really in the psm3 transcript is matched" \
   0 env TESS_P3_OUT='alpha beta' TESS_P6_OUT='gamma delta' "${assert_bin}" --expect 'alpha beta' -- "${img}"
expect_rc "a token really in the psm6 transcript is matched" \
   0 env TESS_P3_OUT='alpha beta' TESS_P6_OUT='gamma delta' "${assert_bin}" --expect 'gamma delta' -- "${img}"

## (3) A per-mode OCR FAILURE must not hide a real mismatch. psm3 errors (rc 1), psm6 reads but
## LACKS the expected token: the default must report MISMATCH (rc 1), NOT ocr-error (rc 3). A
## join-generator that aborts on the first (psm3) failure would wrongly return ocr-error -> the
## content gate ignores it -> false green. This is the canary for that.
expect_rc "psm3 failure + psm6 mismatch -> MISMATCH, not ocr-error (no false green)" \
   1 env TESS_P3_RC=1 TESS_P6_OUT='only the menu token' "${assert_bin}" --expect GUIROW -- "${img}"
## psm3 fails but psm6 DOES read the token -> pass (the surviving mode decides).
expect_rc "psm3 failure + psm6 reads the token -> pass" \
   0 env TESS_P3_RC=1 TESS_P6_OUT='GUIROW is here' "${assert_bin}" --expect GUIROW -- "${img}"
## ALL modes fail -> a genuine OCR read error (exit 3), never a pass.
expect_rc "ALL modes fail -> OCR-read error (exit 3)" \
   3 env TESS_P3_RC=1 TESS_P6_RC=1 "${assert_bin}" --expect GUIROW -- "${img}"

## (4) The MISMATCH DIAGNOSTIC path must not crash. On a real miss the tool prints the missing
## token(s) AND an "OCR saw:" excerpt, then returns 1 -- an rc-only check cannot tell a clean
## mismatch (exit 1) from a crash in the diagnostic (also exit 1), so assert the stderr content.
err_file="${work}/mismatch.err"
mm_rc=0
"${assert_bin}" --expect ZZZDEFINITELYABSENT -- "${img}" >/dev/null 2>"${err_file}" || mm_rc=$?
saw=0
if grep --quiet 'OCR saw:' "${err_file}"; then saw=1; fi
crash=0
if grep --quiet --extended-regexp 'Traceback|NameError' "${err_file}"; then crash=1; fi
if [ "${mm_rc}" -eq 1 ] && [ "${saw}" -eq 1 ] && [ "${crash}" -eq 0 ]; then
   printf '%s\n' "PASS: mismatch prints the OCR-saw excerpt and does not crash the diagnostic"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: mismatch diagnostic broken (rc=${mm_rc}, saw=${saw}, crash=${crash})" >&2
   printf '%s\n' "  stderr: $(cat -- "${err_file}")" >&2
   fail=$((fail + 1))
fi

## (5) A non-UTF-8 read under ONE mode must not crash: the OTHER mode decides. psm 6 emits invalid
## bytes, psm 3 reads the token -> pass (the decodable mode wins, the bad one is skipped).
expect_rc "non-UTF-8 under psm6 + token in psm3 -> pass (bad mode skipped)" \
   0 env TESS_P6_BIN=1 TESS_P3_OUT='Welcome to the Calamares installer' \
      "${assert_bin}" --expect 'Welcome to the Calamares installer' -- "${img}"
## psm 3 emits invalid bytes, psm 6 reads but LACKS the token -> clean MISMATCH (1), not a crash.
expect_rc "non-UTF-8 under psm3 + psm6 mismatch -> MISMATCH, not crash" \
   1 env TESS_P3_BIN=1 TESS_P6_OUT='only a menu' "${assert_bin}" --expect GUIROW -- "${img}"
## BOTH modes emit invalid bytes -> a genuine OCR read error (exit 3), never a crash or a pass.
expect_rc "non-UTF-8 under BOTH modes -> OCR-read error (exit 3)" \
   3 env TESS_P3_BIN=1 TESS_P6_BIN=1 "${assert_bin}" --expect GUIROW -- "${img}"

## image-ocr-sidecar default publishes text carrying BOTH tokens (so a golden is approvable from
## the sidecar regardless of which mode read a given row), and survives a per-mode failure.
"${sidecar_bin}" -- "${img}" >/dev/null 2>&1
if [ -f "${img}.ocr.txt" ] \
   && grep --quiet GUIROW "${img}.ocr.txt" && grep --quiet MENUTOKEN "${img}.ocr.txt"; then
   printf '%s\n' "PASS: ocr-sidecar default carries both single-mode tokens"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: ocr-sidecar default did not carry both tokens" >&2
   fail=$((fail + 1))
fi
safe-rm --force -- "${img}.ocr.txt"
TESS_P3_RC=1 TESS_P6_OUT='surviving mode text' "${sidecar_bin}" -- "${img}" >/dev/null 2>&1
if [ -f "${img}.ocr.txt" ] && grep --quiet 'surviving mode text' "${img}.ocr.txt"; then
   printf '%s\n' "PASS: ocr-sidecar survives a per-mode failure (writes the surviving transcript)"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: ocr-sidecar did not survive a per-mode failure" >&2
   fail=$((fail + 1))
fi

printf '%s\n' "===== ocr_union_psm_test: ${pass} pass, ${fail} fail ====="
[ "${fail}" -eq 0 ]

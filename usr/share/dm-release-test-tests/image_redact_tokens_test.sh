#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins image-redact-tokens: mask ONLY the OCR word boxes whose text matches a regex (a kernel
## timestamp, a per-install LUKS UUID), leaving the rest of the frame intact so a published
## screenshot is reproducible without going blank. Behavioural: render known text, redact, and
## OCR the result -- the tokens must be gone and the marker words must remain.
##
## Drives the REAL tool + the REAL tesseract (a hard dependency of the redaction it performs).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
subject=""
for candidate in "${IMAGE_REDACT_TOKENS:-}" \
   "${test_dir}/../../bin/image-redact-tokens" \
   "/usr/bin/image-redact-tokens"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${subject}" ] || { printf '%s\n' "FATAL: image-redact-tokens not found" >&2; exit 1; }

fixture_gen="${test_dir}/make-redact-fixture.py"
[ -x "${fixture_gen}" ] || { printf '%s\n' "FATAL: make-redact-fixture.py not found/executable" >&2; exit 1; }
## tesseract drives the OCR this tool redacts by. It is an OVH e2e-lane dependency (the redaction
## runs only inside the install lane, which already uses tesseract for OCR), not a unit-CI tool,
## so SKIP where it is absent rather than fail a unit container that never runs the lane.
if ! tesseract --version >/dev/null 2>&1; then
   printf '%s\n' "SKIP: tesseract not available (e2e-lane OCR dependency)" >&2
   ## style-ok: allow-skip: tesseract is an e2e-lane OCR dependency, absent in the unit-CI env
   exit 77
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }
ocr() { tesseract "$1" stdout --psm 6 2>/dev/null; }

ts_pat='[0-9]+\.[0-9]{6}'
uuid_pat='luks-[0-9a-fA-F]+'

## --- matching tokens are masked; marker words survive --------------------------------------
img="${work}/frame.png"
"${fixture_gen}" "${img}"
before_ocr="$(ocr "${img}")"
## sanity: the fixture really contains the tokens + markers before redaction (else the test
## proves nothing). A broken OCR environment fails HERE, loud, not as a false pass.
got=0; { has 345678 "${before_ocr}" && has ALPHA "${before_ocr}"; } || got=1
check "fixture OCRs the timestamp + markers before redaction" "${got}"

rc=0; "${subject}" --pattern "${ts_pat}" --pattern "${uuid_pat}" -- "${img}" >"${work}/out1" 2>&1 || rc=$?
check "redact exits 0" "${rc}"
got=0; has 'word(s) masked' "$(cat -- "${work}/out1")" || got=1
check "redact reports its work" "${got}"

after_ocr="$(ocr "${img}")"
got=0; has 345678 "${after_ocr}" && got=1
check "timestamp digits are gone after redaction" "${got}"
got=0; has abcd1234 "${after_ocr}" && got=1
check "luks uuid is gone after redaction" "${got}"
## case-INSENSITIVE: the fixture's UPPER-case 'LUKS-DEADBEEF01' must be masked by the
## lower-case 'luks-...' pattern (OCR returns unstable case on real frames).
got=0; { has DEADBEEF "${after_ocr}" || has deadbeef "${after_ocr}"; } && got=1
check "an UPPER-case luks token is masked by a lower-case pattern (case-insensitive)" "${got}"
## markers on the SAME lines as the tokens must survive (only the token box is masked, not the
## whole line -- so the frame keeps content + stays non-uniform).
got=0; has ALPHA "${after_ocr}" || got=1
check "marker before the timestamp survives" "${got}"
got=0; { has DELTA "${after_ocr}" || has CHARLIE "${after_ocr}"; } || got=1
check "a marker on the uuid line survives" "${got}"

## --- a non-matching pattern leaves the image byte-identical ---------------------------------
img2="${work}/frame2.png"
"${fixture_gen}" "${img2}"
cp -- "${img2}" "${work}/frame2.orig.png"
rc=0; "${subject}" --pattern 'ZZZ_no_such_token_ZZZ' -- "${img2}" >/dev/null 2>&1 || rc=$?
check "redact with no match exits 0" "${rc}"
got=0; cmp --quiet "${img2}" "${work}/frame2.orig.png" || got=1
check "no-match leaves the image byte-identical" "${got}"

## --- an unreadable input: nothing processed -> nonzero -------------------------------------
printf '%s\n' "not an image" > "${work}/notimg.txt"
rc=0; "${subject}" --pattern "${ts_pat}" -- "${work}/notimg.txt" >/dev/null 2>&1 || rc=$?
check "an unreadable-only input exits nonzero" "$(( rc != 0 ? 0 : 1 ))"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0

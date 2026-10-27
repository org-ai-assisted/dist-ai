#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests the sourceable content gate (content-gate.bsh content_gate_run), the DISPLAY/publish
## half of screenshot-validity. Drives the REAL function (sourced define-only) over a temp shot_dir
## with image-text-assert + image-ocr-sidecar STUBBED (a unit-isolation stub -- the real tools are
## OCR, covered by their own suites). Asserts the graduated policy maps each image-text-assert exit
## to the right per-shot .status token (validated/mismatch/unvalidated/ocr-error), that a broken
## golden (exit 2) counts as a failing content check, that a no-golden stage is UNVALIDATED (never a
## pass, never a fail), that the OCR text sidecars are published, and that content_gate_run RETURNS
## the content-mismatch count so the lane flips the run rc.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib="${CONTENT_GATE_LIB:-}"
if [ -z "${lib}" ]; then
   if [ -f "${test_dir}/../../libexec/image-test/content-gate.bsh" ]; then
      lib="${test_dir}/../../libexec/image-test/content-gate.bsh"
   else
      lib='/usr/libexec/image-test/content-gate.bsh'
   fi
fi
[ -r "${lib}" ] || { printf '%s\n' "FATAL: content-gate.bsh not found at ${lib}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${lib}"

work="$(mktemp --directory --tmpdir content-gate-test.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

pass=0
fail=0
check() {
   local label="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "ok: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')" >&2
      fail=$((fail + 1))
   fi
}

## Stub image-text-assert: map the LAST arg (the image) to an exit code so every graduated branch
## is exercised deterministically -- 0 validated, 1 mismatch, 2 broken golden, 3 OCR read error.
assert_stub="${work}/image-text-assert"
cat > "${assert_stub}" <<'STUB'
#!/bin/bash
img="${*: -1}"
case "${img}" in
   *-good.png) exit 0 ;;
   *-bad.png) exit 1 ;;
   *-broken.png) exit 2 ;;
   *-ocrerr.png) exit 3 ;;
   *) exit 0 ;;
esac
STUB

## Stub image-ocr-sidecar: write a .ocr.txt beside every png in the dir it is handed.
ocr_stub="${work}/image-ocr-sidecar"
cat > "${ocr_stub}" <<'STUB'
#!/bin/bash
d="${*: -1}"
for f in "${d}"/*.png; do
   [ -f "${f}" ] && printf '%s\n' 'stub ocr text' > "${f}.ocr.txt"
done
STUB
chmod +x "${assert_stub}" "${ocr_stub}"
export IMAGE_TEXT_ASSERT="${assert_stub}"
export IMAGE_OCR_SIDECAR="${ocr_stub}"

## shot_dir: one shot per branch. Golden present for good/bad/broken/ocrerr; ABSENT for nogold.
shot_dir="${work}/shots"
golden_dir="${work}/golden"
mkdir --parents -- "${shot_dir}" "${golden_dir}"
for s in 10-good 20-bad 30-ocrerr 40-broken 50-nogold; do
   printf '%s' 'PNG' > "${shot_dir}/${s}.png"
done
for g in good bad ocrerr broken; do
   printf '%s\n' 'token' > "${golden_dir}/${g}.tokens"
done

## A non-png sibling (a card or a status file) must be IGNORED by the gate loop (globs *.png only).
printf '%s\n' 'card text' > "${shot_dir}/15-vm-defined.card.txt"

mismatch=0
content_gate_run "${golden_dir}" "${shot_dir}" || mismatch=$?

## Per-shot .status token for each graduated branch.
check "validated shot -> status validated" "$(cat -- "${shot_dir}/10-good.png.status")" 'validated'
check "mismatch shot -> status mismatch" "$(cat -- "${shot_dir}/20-bad.png.status")" 'mismatch'
check "ocr-error shot -> status ocr-error" "$(cat -- "${shot_dir}/30-ocrerr.png.status")" 'ocr-error'
check "broken-golden shot -> status mismatch (fails the check)" \
   "$(cat -- "${shot_dir}/40-broken.png.status")" 'mismatch'
check "no-golden shot -> status unvalidated" "$(cat -- "${shot_dir}/50-nogold.png.status")" 'unvalidated'

## content_gate_run RETURNS the content-mismatch count (bad + broken = 2) so the lane flips rc.
check "returns the mismatch count (bad + broken)" "${mismatch}" '2'

## OCR sidecars published beside every shot (evidence).
check "OCR sidecar written for a shot" \
   "$([ -s "${shot_dir}/10-good.png.ocr.txt" ] && printf '%s' yes || printf '%s' no)" 'yes'

## The card .txt must get NO .status (the gate globs *.png only -- a card is never a shot).
check "card .card.txt gets no .status" \
   "$([ -e "${shot_dir}/15-vm-defined.card.txt.status" ] && printf '%s' bad || printf '%s' no)" 'no'

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || { printf '%s\n' "FAILED" >&2; exit 1; }
printf '%s\n' "OK"

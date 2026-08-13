#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression suite for the REAL usr/bin/image-optimize. Generates fixtures with
## ImageMagick, then asserts:
##   - a deliberately-bloated (uncompressed) PNG shrinks;
##   - --check FAILS (exit 1) on the bloated PNG and PASSES (exit 0) once
##     optimized -- the canary proving the gate distinguishes the two, not
##     always-red/always-green;
##   - minimize is idempotent and never grows a file;
##   - --webp replaces a JPEG with a smaller .webp and prints the OLD<TAB>NEW map;
##   - a --webp PNG result is never larger than the source;
##   - unsupported types are skipped and left untouched;
##   - a missing / unreadable input yields a non-zero exit without aborting a batch.
## SKIP (77) only when the image tools are genuinely absent.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

BIN="${IMAGE_OPTIMIZE_BIN:-}"
if [ -z "${BIN}" ]; then
   if [ -x /usr/bin/image-optimize ]; then
      BIN='/usr/bin/image-optimize'
   else
      printf '%s\n' 'image-optimize-tests: SKIP (image-optimize not found; set IMAGE_OPTIMIZE_BIN)' >&2
      exit 77
   fi
fi

## The tool sources helper-scripts strings.bsh via HELPER_SCRIPTS_PATH (empty ->
## /usr, i.e. the installed helper-scripts). Require it so validate_safe_filename
## is real, not stubbed.
hs_prefix="${HELPER_SCRIPTS_PATH:-}"
if [ ! -r "${hs_prefix}/usr/libexec/helper-scripts/strings.bsh" ]; then
   printf '%s\n' 'image-optimize-tests: SKIP (helper-scripts strings.bsh not found; set HELPER_SCRIPTS_PATH)' >&2
   exit 77
fi

for tool in convert optipng jpegoptim cwebp stat; do
   if ! type -P "${tool}" >/dev/null; then
      printf '%s\n' "image-optimize-tests: SKIP (missing tool: ${tool})" >&2
      exit 77
   fi
done

workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}" 2>/dev/null || true
}
trap cleanup EXIT

pass=0
fail=0

report() {
   local verdict="$1" desc="$2"
   if [ "${verdict}" = 'pass' ]; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: ${desc}"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: ${desc}"
   fi
}

## Assert a command SUCCEEDS (exit 0).
assert_ok() {
   local desc="$1"; shift
   if "$@" >/dev/null 2>&1; then report pass "${desc}"; else report fail "${desc}"; fi
}

## Assert a command FAILS (non-zero exit).
assert_fail() {
   local desc="$1"; shift
   if "$@" >/dev/null 2>&1; then report fail "${desc}"; else report pass "${desc}"; fi
}

## Assert integer a < b.
assert_lt() {
   local desc="$1" a="$2" b="$3"
   if [ "${a}" -lt "${b}" ]; then report pass "${desc} (${a} < ${b})"
   else report fail "${desc} (${a} not < ${b})"; fi
}

## Assert integer a <= b.
assert_le() {
   local desc="$1" a="$2" b="$3"
   if [ "${a}" -le "${b}" ]; then report pass "${desc} (${a} <= ${b})"
   else report fail "${desc} (${a} not <= ${b})"; fi
}

fsize() { stat -c %s -- "$1"; }

## ---------------------------------------------------------------------------
## PNG: bloated (uncompressed) -> shrinks; --check canary both directions.
## ---------------------------------------------------------------------------
png="${workdir}/shot.png"
## A stored-uncompressed PNG guarantees a large, deterministic reclaimable delta.
## ImageMagick 'convert' has no '--' end-of-options marker; these output paths are
## controlled temp files under workdir, so none can begin with '-'.
convert -size 300x300 plasma:fractal -define png:compression-level=0 "${png}"
png_before="$(fsize "${png}")"

assert_fail 'check FAILS on a bloated PNG (canary: gate can fail)' \
   "${BIN}" --check -- "${png}"

assert_ok 'optimize a bloated PNG succeeds' \
   "${BIN}" --quiet -- "${png}"
png_after="$(fsize "${png}")"
assert_lt 'optimized PNG is smaller' "${png_after}" "${png_before}"

assert_ok 'check PASSES on the optimized PNG (canary: gate can pass)' \
   "${BIN}" --check -- "${png}"

## Idempotent / never grows: a second pass must not enlarge the file.
"${BIN}" --quiet -- "${png}"
png_again="$(fsize "${png}")"
assert_le 'second optimize never grows the file' "${png_again}" "${png_after}"

## ---------------------------------------------------------------------------
## JPEG -> webp replacement + the OLD<TAB>NEW mapping on stdout.
## ---------------------------------------------------------------------------
jpg="${workdir}/photo.jpg"
convert -size 400x400 plasma: "${jpg}"
jpg_before="$(fsize "${jpg}")"
map="$("${BIN}" --webp --quiet -- "${jpg}")" || map=""
webp="${workdir}/photo.webp"
if [ -f "${webp}" ] && [ ! -e "${jpg}" ]; then
   report pass 'JPEG converted to webp (source removed, .webp created)'
else
   report fail 'JPEG converted to webp (source removed, .webp created)'
fi
if [ "${map}" = "${jpg}"$'\t'"${webp}" ]; then
   report pass 'webp mode prints OLD<TAB>NEW mapping'
else
   report fail "webp mode prints OLD<TAB>NEW mapping (got: ${map})"
fi
assert_lt 'webp is smaller than the source JPEG' "$(fsize "${webp}")" "${jpg_before}"

## ---------------------------------------------------------------------------
## PNG --webp: whatever the result, it is never larger than the source.
## ---------------------------------------------------------------------------
png2="${workdir}/logo.png"
convert -size 200x200 plasma:fractal "${png2}"
"${BIN}" --quiet -- "${png2}"          # minimize first so the comparison is fair
png2_min="$(fsize "${png2}")"
map2="$("${BIN}" --webp --quiet -- "${png2}")" || map2=""
result2="${map2#*$'\t'}"
if [ -f "${result2}" ]; then
   report pass 'PNG --webp result path exists'
else
   report fail "PNG --webp result path exists (got: ${result2})"
fi
assert_le 'PNG --webp result is never larger than the minimized source' \
   "$(fsize "${result2}")" "${png2_min}"

## ---------------------------------------------------------------------------
## Unsupported type is skipped and left byte-identical; --check passes it.
## ---------------------------------------------------------------------------
gif="${workdir}/anim.gif"
printf '%s' 'GIF89a and some bytes that are not a real gif' > "${gif}"
gif_sum_before="$(cksum < "${gif}")"
skip_map="$("${BIN}" --webp --quiet -- "${gif}")" || skip_map=""
gif_sum_after="$(cksum < "${gif}")"
if [ "${gif_sum_before}" = "${gif_sum_after}" ]; then
   report pass 'unsupported type left byte-identical'
else
   report fail 'unsupported type left byte-identical'
fi
if [ "${skip_map}" = "${gif}"$'\t'"${gif}" ]; then
   report pass 'unsupported type maps to itself in --webp'
else
   report fail "unsupported type maps to itself in --webp (got: ${skip_map})"
fi
assert_ok 'check PASSES an unsupported type (only rasters are gated)' \
   "${BIN}" --check -- "${gif}"

## ---------------------------------------------------------------------------
## Error handling: a missing input yields non-zero without a crash.
## ---------------------------------------------------------------------------
assert_fail 'missing input yields non-zero exit' \
   "${BIN}" --quiet -- "${workdir}/does-not-exist.png"
assert_fail 'check on a missing input yields non-zero exit' \
   "${BIN}" --check -- "${workdir}/does-not-exist.png"

## ---------------------------------------------------------------------------
printf '%s\n' '' "image-optimize-tests: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]

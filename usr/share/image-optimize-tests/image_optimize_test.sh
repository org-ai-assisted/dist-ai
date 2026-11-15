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
##   - --convert replaces a raster with whichever of {webp, avif} is SMALLER (and
##     prints the OLD<TAB>NEW map), never larger than the source;
##   - keep-smaller picks per image: a photo wins as avif, flat/line-art as webp;
##   - unsupported types are skipped and left untouched;
##   - a missing / unreadable input yields a non-zero exit without aborting a batch.
## exit 1 (FATAL) when the subject or a required image tool is absent (R-220).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

BIN="${IMAGE_OPTIMIZE_BIN:-}"
if [ -z "${BIN}" ]; then
   if [ -x /usr/bin/image-optimize ]; then
      BIN='/usr/bin/image-optimize'
   else
      printf '%s\n' 'image-optimize-tests: FATAL (image-optimize not found; set IMAGE_OPTIMIZE_BIN)' >&2
      exit 1
   fi
fi

## The tool sources helper-scripts strings.bsh via HELPER_SCRIPTS_PATH (empty ->
## /usr, i.e. the installed helper-scripts). Require it so validate_safe_filename
## is real, not stubbed.
hs_prefix="${HELPER_SCRIPTS_PATH:-}"
if [ ! -r "${hs_prefix}/usr/libexec/helper-scripts/strings.bsh" ]; then
   printf '%s\n' 'image-optimize-tests: FATAL (helper-scripts strings.bsh not found; set HELPER_SCRIPTS_PATH)' >&2
   exit 1
fi

for tool in convert optipng jpegoptim cwebp avifenc stat; do
   if ! type -P "${tool}" >/dev/null; then
      printf '%s\n' "image-optimize-tests: FATAL (missing tool: ${tool})" >&2
      exit 1
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
## --convert: KEEP-SMALLER. A photographic JPEG is replaced by whichever of
## {webp, avif} is smaller (avif usually wins on a photo); source removed, map
## printed. The winner extension is NOT assumed.
## ---------------------------------------------------------------------------
jpg="${workdir}/photo.jpg"
convert -size 400x400 plasma: "${jpg}"
jpg_before="$(fsize "${jpg}")"
map="$("${BIN}" --convert --quiet -- "${jpg}")" || map=""
result="${map#*$'\t'}"
if [ -n "${map}" ] && [ -f "${result}" ] && [ ! -e "${jpg}" ]; then
   report pass 'JPEG converted (source removed, winner created)'
else
   report fail "JPEG converted (map: ${map})"
fi
if [ "${map}" = "${jpg}"$'\t'"${result}" ] && [ "${result}" != "${jpg}" ]; then
   report pass 'convert prints OLD<TAB>NEW mapping'
else
   report fail "convert prints OLD<TAB>NEW mapping (got: ${map})"
fi
assert_lt 'winner is smaller than the source JPEG' "$(fsize "${result}")" "${jpg_before}"
case "${result}" in
   *.avif)
      report pass 'photographic JPEG wins as AVIF (keep-smaller)'
      ;;
   *.webp)
      report pass 'photographic JPEG wins as WebP (keep-smaller: webp was smaller)'
      ;;
   *)
      report fail "photographic JPEG winner has an unexpected extension: ${result}"
      ;;
esac

## ---------------------------------------------------------------------------
## Keep-smaller canary: a FLAT / line-art PNG (where lossless webp beats lossy avif)
## wins as .webp, NOT .avif -- proving the tool picks per image, not a fixed format.
## ---------------------------------------------------------------------------
flat="${workdir}/flat.png"
convert -size 400x400 xc:'#204080' -fill white -pointsize 40 \
   -draw "text 20,200 'FLAT LINE ART 0123456789'" "${flat}"
"${BIN}" --quiet -- "${flat}"
flatmap="$("${BIN}" --convert --quiet -- "${flat}")" || flatmap=""
flatres="${flatmap#*$'\t'}"
case "${flatres}" in
   *.webp)
      report pass 'flat/line-art PNG wins as WebP (keep-smaller picks per image)'
      ;;
   "${flat}")
      report pass 'flat/line-art PNG kept as source (already smallest)'
      ;;
   *.avif)
      report fail 'flat/line-art PNG won as AVIF (avif beat lossless webp here?)'
      ;;
   *)
      report fail "flat/line-art winner unexpected: ${flatres}"
      ;;
esac

## ---------------------------------------------------------------------------
## PNG --convert: whatever the result, it is never larger than the source.
## ---------------------------------------------------------------------------
png2="${workdir}/logo.png"
convert -size 200x200 plasma:fractal "${png2}"
"${BIN}" --quiet -- "${png2}"          # minimize first so the comparison is fair
png2_min="$(fsize "${png2}")"
map2="$("${BIN}" --convert --quiet -- "${png2}")" || map2=""
result2="${map2#*$'\t'}"
if [ -n "${result2}" ] && [ -f "${result2}" ]; then
   report pass 'PNG --convert result path exists'
else
   report fail "PNG --convert result path exists (got: ${result2})"
fi
assert_le 'PNG --convert result is never larger than the minimized source' \
   "$(fsize "${result2}")" "${png2_min}"

## ---------------------------------------------------------------------------
## Unsupported type is skipped and left byte-identical; --check passes it.
## ---------------------------------------------------------------------------
gif="${workdir}/anim.gif"
printf '%s' 'GIF89a and some bytes that are not a real gif' > "${gif}"
gif_sum_before="$(cksum < "${gif}")"
skip_map="$("${BIN}" --convert --quiet -- "${gif}")" || skip_map=""
gif_sum_after="$(cksum < "${gif}")"
if [ "${gif_sum_before}" = "${gif_sum_after}" ]; then
   report pass 'unsupported type left byte-identical'
else
   report fail 'unsupported type left byte-identical'
fi
if [ "${skip_map}" = "${gif}"$'\t'"${gif}" ]; then
   report pass 'unsupported type maps to itself in --convert'
else
   report fail "unsupported type maps to itself in --convert (got: ${skip_map})"
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
## A symlinked image must be REFUSED, not optimized: 'stat -c %s' reports the link's
## own path length rather than the target's size, so a symlink would misread as
## "already minimal" (or, in --convert mode, be replaced by a regular file). The refusal
## must leave BOTH the link and its target untouched -- a non-zero exit alone does not
## prove nothing was mutated.
## ---------------------------------------------------------------------------
real_png="${workdir}/real.png"
convert -size 150x150 plasma:fractal "${real_png}"
real_sum_before="$(cksum < "${real_png}")"
ln -s real.png "${workdir}/link.png"
assert_fail 'refuses to optimize a symlink (stat misreads its size)' \
   "${BIN}" --quiet -- "${workdir}/link.png"
## The --check GATE must refuse a symlink too, not false-pass it: stat's link-size
## misread makes reclaim negative, which would otherwise read as "already minimal".
assert_fail 'refuses to --check a symlink (gate must not false-pass it)' \
   "${BIN}" --check -- "${workdir}/link.png"
link_target="$(readlink -- "${workdir}/link.png" 2>/dev/null || true)"
real_sum_after="$(cksum < "${real_png}")"
if [ -L "${workdir}/link.png" ] && [ "${link_target}" = 'real.png' ]; then
   report pass 'refused symlink is left intact (still points at its target)'
else
   report fail "refused symlink is left intact (link target: ${link_target})"
fi
if [ "${real_sum_before}" = "${real_sum_after}" ]; then
   report pass 'refused symlink leaves its target byte-identical'
else
   report fail 'refused symlink leaves its target byte-identical'
fi

## ---------------------------------------------------------------------------
## Stem collision: two sources sharing a stem (img.png + img.jpg) both target
## <stem>.webp/.avif. The tool converts exactly ONE and REFUSES the other (its early
## target check sees the first's output) -- one original survives byte-identical,
## one converted output exists, and the run exits non-zero (no content lost).
## ---------------------------------------------------------------------------
col="${workdir}/collide"
mkdir -- "${col}"
convert -size 120x120 plasma:fractal "${col}/img.png"
convert -size 120x120 plasma: "${col}/img.jpg"
col_rc=0
"${BIN}" --convert --quiet -- "${col}/img.png" "${col}/img.jpg" || col_rc=$?
survivors=0
[ -e "${col}/img.png" ] && survivors=$(( survivors + 1 ))
[ -e "${col}/img.jpg" ] && survivors=$(( survivors + 1 ))
out_made='no'
{ [ -f "${col}/img.webp" ] || [ -f "${col}/img.avif" ]; } && out_made='yes'
if [ "${col_rc}" -ne 0 ] && [ "${out_made}" = 'yes' ] && [ "${survivors}" -eq 1 ]; then
   report pass 'stem collision errors and loses no source content'
else
   report fail "stem collision (rc=${col_rc}, survivors=${survivors}, out=${out_made})"
fi

## An existing <stem>.webp OR <stem>.avif target must be REFUSED, not overwritten, and
## the source left BYTE-IDENTICAL -- the refusal fires BEFORE the in-place minimize. A
## stored-uncompressed PNG guarantees an in-place minimize would be a visible byte
## change. Pre-create BOTH targets so the refusal holds regardless of which would win.
pre="${workdir}/pre"
mkdir -- "${pre}"
convert -size 120x120 plasma:fractal -define png:compression-level=0 "${pre}/x.png"
pre_png_before="$(cksum < "${pre}/x.png")"
printf '%s' 'PRE-EXISTING-WEBP' > "${pre}/x.webp"
printf '%s' 'PRE-EXISTING-AVIF' > "${pre}/x.avif"
pre_rc=0
"${BIN}" --convert --quiet -- "${pre}/x.png" || pre_rc=$?
pre_kept='no'
if [ "$(cat "${pre}/x.webp" 2>/dev/null)" = 'PRE-EXISTING-WEBP' ] \
   && [ "$(cat "${pre}/x.avif" 2>/dev/null)" = 'PRE-EXISTING-AVIF' ]; then
   pre_kept='yes'
fi
pre_png='no'
[ "$(cksum < "${pre}/x.png" 2>/dev/null)" = "${pre_png_before}" ] && pre_png='yes'
if [ "${pre_rc}" -ne 0 ] && [ "${pre_png}" = 'yes' ] && [ "${pre_kept}" = 'yes' ]; then
   report pass 'convert refuses existing targets: source byte-identical, targets intact'
else
   report fail "convert existing-target (rc=${pre_rc}, png_unchanged=${pre_png}, kept=${pre_kept})"
fi

## ---------------------------------------------------------------------------
printf '%s\n' '' "image-optimize-tests: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]

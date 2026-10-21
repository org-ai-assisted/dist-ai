#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## image-blank-check flags a degenerate (blank) milestone screenshot -- an all-white
## or all-black frame, or one so close it carries no content -- so a release-test run
## that produced a black rectangle FAILS instead of silently publishing it. Drives the
## REAL tool against synthetic frames (built with ImageMagick); no root, no VM.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

checker="${IMAGE_BLANK_CHECK_BIN:-}"
if [ -z "${checker}" ]; then
   if [ -f "${test_dir}/../../bin/image-blank-check" ]; then
      checker="${test_dir}/../../bin/image-blank-check"
   else
      checker='/usr/bin/image-blank-check'
   fi
fi
[ -r "${checker}" ] || { printf '%s\n' "FATAL: image-blank-check not found at ${checker}" >&2; exit 1; }

magick_bin='convert'
if type -P magick >/dev/null 2>&1; then
   magick_bin='magick'
fi

workdir="$(mktemp --directory --tmpdir image-blank-check-test.XXXXXX)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## Synthesize the frames the tool must and must not flag.
"${magick_bin}" -size 64x48 xc:white "${workdir}/white.png"
"${magick_bin}" -size 64x48 xc:black "${workdir}/black.png"
## 99% black + a single gray line: a real captured-too-early desktop frame (2 colours).
"${magick_bin}" -size 100x100 xc:black -fill '#aaaaaa' -draw 'line 0,0 99,0' "${workdir}/near_blank.png"
## Content-rich: a plasma fill is thousands of distinct colours -> must NOT flag.
"${magick_bin}" -size 80x60 plasma: "${workdir}/rich.png"
## Dark-but-real: a dim gradient, many distinct shades -> must NOT flag.
"${magick_bin}" -size 80x60 "gradient:#000000-#303040" "${workdir}/dark_real.png"
## A blank frame named 'NN-<token>' to exercise the dash-delimited --allow suffix match.
## In its own subdir so the one-level ${workdir} scans above are unaffected.
mkdir -- "${workdir}/sfx"
"${magick_bin}" -size 64x48 xc:black "${workdir}/sfx/11-power-on-first-frame.png"

pass=0
fail=0
expect_rc() {
   ## $1 description, $2 expected-rc, $3.. files
   local desc="$1" want="$2"
   shift 2
   local got=0
   "${checker}" "$@" >/dev/null 2>&1 || got=$?
   if [ "${got}" -eq "${want}" ]; then
      printf '%s\n' "PASS: ${desc}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${desc} (rc=${got}, want ${want})" >&2
      fail=$((fail + 1))
   fi
}

expect_rc "uniform white is flagged"            1 "${workdir}/white.png"
expect_rc "uniform black is flagged"            1 "${workdir}/black.png"
expect_rc "near-blank (99% black) is flagged"   1 "${workdir}/near_blank.png"
expect_rc "content-rich frame is NOT flagged"   0 "${workdir}/rich.png"
expect_rc "dark-but-real frame is NOT flagged"  0 "${workdir}/dark_real.png"
## Directory scan: a dir containing any degenerate frame fails.
expect_rc "a dir with a blank frame fails"      1 "${workdir}"
## --allow excludes a by-design-blank frame by exact name.
expect_rc "--allow excludes the named frames"   0 --allow white --allow black --allow near_blank "${workdir}"
## --allow matches a dash-delimited suffix token of the stem ('11-power-on-first-frame').
expect_rc "--allow matches a dash-suffix token"  0 --allow power-on-first-frame "${workdir}/sfx/11-power-on-first-frame.png"

## FAIL-OPEN guards: a token with no alphanumeric char ('' / '.' / '-') is not a real
## frame name and must exempt NOTHING -- else a bare '.' matches a stem ending in '-.'.
expect_rc "--allow '' exempts nothing (not fail-open)"   1 --allow '' "${workdir}/white.png"
expect_rc "--allow . exempts nothing (not fail-open)"    1 --allow . "${workdir}/white.png"
expect_rc "--allow - exempts nothing (not fail-open)"    1 --allow - "${workdir}/white.png"
## A blank frame whose stem ends in '-.' must NOT be exempted by a bare '.' token.
"${magick_bin}" -size 64x48 xc:black "${workdir}/sfx/shot-..png"
expect_rc "--allow . does not match a '-.'-stem frame"   1 --allow . "${workdir}/sfx/shot-..png"

## CANARY: a detector that flagged EVERYTHING would fail the two NOT-flagged cases above;
## one that flagged NOTHING would fail the three flagged cases. Both are asserted, so the
## suite is non-vacuous.

printf '%s\n' "===== image_blank_check_test: ${pass} pass, ${fail} fail ====="
[ "${fail}" -eq 0 ]

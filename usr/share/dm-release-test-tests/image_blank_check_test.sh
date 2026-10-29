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
## New standalone fixtures live in their own subdir so the one-level ${workdir} scans above
## are unaffected (they are referenced by direct path, never by a dir scan).
mkdir -- "${workdir}/extra"
## ~92% white, 2 colours: a card the OLD 0.98 frac MISSED; the 0.90 default must catch it.
## This is the regression for lowering --frac to 0.90 (fails on the pre-0.90 tool).
"${magick_bin}" -size 100x100 xc:white -fill black -draw 'rectangle 0,0 99,7' "${workdir}/extra/white_92.png"
## "Empty white plus systray redaction": a rendered state card whose text failed to draw --
## a white frame carrying only the small black systray-redaction box. The real published bug.
"${magick_bin}" -size 499x247 xc:white -fill black -draw 'rectangle 379,0 498,23' "${workdir}/extra/white_redaction.png"
## Content-rich dark terminal (a failure-log Qterminal, a grub menu): >90% black yet hundreds
## of distinct colours -> real content, must NOT flag. A plasma strip (many colours) over the
## top ~8%, black below. Written as WEBP to also exercise webp decoding on a NOT-flagged frame.
"${magick_bin}" -size 300x24 plasma: "${workdir}/extra/_strip.png"
"${magick_bin}" "${workdir}/extra/_strip.png" -background black -gravity north -extent 300x300 "${workdir}/extra/term_dark.webp"
## A black frame with only an ANTI-ALIASED cursor: ~0% lit area but hundreds of colours (the AA
## gradient), so the --max-colors heuristic MISSES it. This is the "black screen except the mouse
## pointer" failure frame / a missed firmware splash that --min-content-frac must catch.
"${magick_bin}" -size 200x200 xc:black -fill white -draw 'circle 100,100 100,97' -blur 0x1.5 "${workdir}/extra/black_aa_cursor.png"
## A uniform-black WEBP in its own dir: proves a webp is decoded AND a webp is picked up by a
## directory scan (iter_images scans *.png and *.webp).
mkdir -- "${workdir}/wdir"
"${magick_bin}" -size 64x48 xc:black "${workdir}/wdir/blank.webp"

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
## FAIL-CLOSED on a MISSING file: a path that does not exist is an unreadable/absent capture and
## must be flagged (rc 1), never silently 0-checked. dm-calamares-install's gate_check_path leans on
## this -- in window mode it points the gate at the REQUIRED guest sibling even when absent, so a
## dead-guest run FAILS here instead of falling back to the chrome window grab.
expect_rc "a nonexistent path is flagged (fail-closed)" 1 "${workdir}/does-not-exist.png"
## 0.90 frac threshold: a 92%-white few-colour card is degenerate (old 0.98 missed it).
expect_rc "92%-white few-colour card is flagged"         1 "${workdir}/extra/white_92.png"
## The real bug: a white frame with only the systray-redaction box.
expect_rc "white + systray-redaction card is flagged"    1 "${workdir}/extra/white_redaction.png"
## CONTENT GATE canary: a >90%-black frame with real content (hundreds of colours) must NOT
## flag -- the 0.90 rule is gated by --max-colors, so a terminal/grub screen stays safe.
expect_rc "content-rich dark terminal NOT flagged (webp)" 0 "${workdir}/extra/term_dark.webp"
## webp support: an explicitly named blank webp, and a blank webp found by a directory scan.
expect_rc "uniform-black webp is flagged"                1 "${workdir}/wdir/blank.webp"
expect_rc "dir scan picks up a blank webp"               1 "${workdir}/wdir"
## --uniform-only: gate a framebuffer grab (tty/console, boot screen) where sparse real content
## is legitimate. Only a TRULY uniform (1-colour) frame is degenerate; a mostly-black frame
## carrying a real prompt line (the 2-colour near_blank) must NOT be a false-positive all-black.
expect_rc "uniform-only: uniform black is flagged"       1 --uniform-only "${workdir}/black.png"
expect_rc "uniform-only: uniform white is flagged"       1 --uniform-only "${workdir}/white.png"
## This same sparse frame IS flagged in default mode ("near-blank (99% black) is flagged"
## above); --uniform-only is exactly what keeps a real tty login from false-positiving.
expect_rc "uniform-only: sparse tty-like frame NOT flagged" 0 --uniform-only "${workdir}/near_blank.png"
## --min-content-frac: a mostly-black frame (missed firmware splash, black failure frame) is
## degenerate even with an AA cursor. The colour-count default MISSES the AA-cursor frame -> this
## is the gap --min-content-frac closes; content-rich frames and the uniform check are unaffected.
expect_rc "min-content-frac: black + AA cursor is flagged"       1 --min-content-frac 0.01 "${workdir}/extra/black_aa_cursor.png"
expect_rc "default colour-count MISSES the AA-cursor black frame" 0 "${workdir}/extra/black_aa_cursor.png"
expect_rc "min-content-frac: content-rich dark frame NOT flagged" 0 --min-content-frac 0.01 "${workdir}/extra/term_dark.webp"
expect_rc "min-content-frac: uniform black still flagged"         1 --min-content-frac 0.01 "${workdir}/black.png"
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

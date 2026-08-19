#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: capture_settled must SKIP tighten_deadspace for the pinned full-viewport colour
## boards (art / gradient), so their shot dimensions stay deterministic run-to-run.
##
## Why: tighten_deadspace crops out the largest run of pure-background rows. On a board whose
## bottom edge colour is close to the terminal background (the truecolor gradient's near-white
## greyscale ramp on the light default theme), a sub-pixel antialiasing difference flips one
## boundary row between the void and the content, drifting the crop height by ~1 text row every
## run -- observed as gradient-tui-show alternating 534 vs 547 px tall. A colour board fills the
## viewport, so there is nothing legitimate to trim; the harness must leave these grabs at the
## pinned window geometry. capture_settled takes a 'skip-tighten' argument for exactly this, and
## the capture loop passes it for st_case = art || gradient.
##
## This test extracts capture_settled + tighten_deadspace from the CURRENT comparison-capture.sh
## text (no drift), stubs the window grab with a synthetic image carrying a large dead-space band,
## and asserts:
##   - WITHOUT the flag, tighten fires and the image shrinks (the band is removed);
##   - WITH 'skip-tighten', the image is returned untouched at its raw dimensions.
## Non-tautological canary: revert the fix (always tighten) and the skip case shrinks -> FAIL;
## break capture_settled (never emit an image) and the non-skip case FAILs too.
##
## Subject: comparison-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR / a checkout default /
## the install path (absent -> exit 77 SKIP). Needs ImageMagick (convert, identify); no Qt, no
## display -- runs in the dist-ai container in milliseconds.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/comparison-capture.sh" \
   "${script_dir}/../secure-terminal-shots/comparison-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/comparison-capture.sh" \
   '/usr/share/secure-terminal-shots/comparison-capture.sh'; do
   ## An unset SECURE_TERMINAL_SHOTS_DIR leaves a bare '/comparison-capture.sh' candidate; it is
   ## simply not a file, so -f rejects it -- no special-casing needed.
   if [ -f "${cand}" ]; then
      subject="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' 'SKIP: comparison-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 77
fi

if ! type -P convert >/dev/null 2>&1 || ! type -P identify >/dev/null 2>&1; then
   printf '%s\n' 'SKIP: ImageMagick (convert/identify) not on PATH' >&2
   exit 77
fi

## SOURCE the real script (it is source-safe: its was_executed guard runs no capture when
## sourced), so capture_settled + tighten_deadspace are the CURRENT bodies with zero drift.
## The stubs below override capture_settled's collaborators (capture_window, shots_shot_is_blank).
# shellcheck source=../secure-terminal-shots/comparison-capture.sh
source "${subject}"
if ! declare -F capture_settled >/dev/null 2>&1 || ! declare -F tighten_deadspace >/dev/null 2>&1; then
   printf '%s\n' 'FAIL: capture_settled / tighten_deadspace not defined after sourcing comparison-capture.sh' >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

## Synthetic fixture: a tall canvas with a large band of pure-background rows between two thin
## content bars -- exactly the shape tighten_deadspace removes (largest bg-row run >> its 40-row
## threshold). Raw height 300; a dead band of ~260 rows.
fixture="${work}/fixture.png"
raw_h=300
convert -size "200x${raw_h}" xc:white \
   -fill black -draw 'rectangle 0,0 199,20' -draw 'rectangle 0,281 199,299' \
   "${fixture}"

## Stubs for capture_settled's collaborators. capture_window: drop the fixture at dest (a fresh
## copy each call). shots_shot_is_blank: never blank, so capture_settled proceeds on first grab.
capture_window() { cp -- "${fixture}" "$1"; }
shots_shot_is_blank() { return 1; }

pass=0
fail=0

height_of() { identify -format '%h' "$1"; }

## Case 1: default (tighten ON) -- the dead band is removed, so the image gets shorter.
dest1="${work}/tightened.png"
capture_settled "${dest1}" dummy-wid
h1="$(height_of "${dest1}")"
if [ -s "${dest1}" ] && [ "${h1}" -lt "${raw_h}" ]; then
   printf '%s\n' "PASS: default path tightens (height ${h1} < raw ${raw_h})"
   pass=$(( pass + 1 ))
else
   printf '%s\n' "FAIL: default path did not tighten (height ${h1:-none}, raw ${raw_h})"
   fail=$(( fail + 1 ))
fi

## Case 2: skip-tighten -- the colour-board path. The grab is returned at its raw dimensions.
dest2="${work}/untouched.png"
capture_settled "${dest2}" dummy-wid skip-tighten
h2="$(height_of "${dest2}")"
if [ -s "${dest2}" ] && [ "${h2}" -eq "${raw_h}" ]; then
   printf '%s\n' "PASS: skip-tighten leaves the raw grab intact (height ${h2} == raw ${raw_h})"
   pass=$(( pass + 1 ))
else
   printf '%s\n' "FAIL: skip-tighten altered the grab (height ${h2:-none}, expected raw ${raw_h})"
   fail=$(( fail + 1 ))
fi

## The capture loop must actually PASS 'skip-tighten' for art/gradient (and only tighten
## otherwise). Assert the wiring in the source so a future edit that drops the argument is caught.
## The gate must cover BOTH boards: the drift was gradient-specific, so dropping just `gradient`
## from the condition would silently regress it while `st_tighten_arg='skip-tighten'` still exists.
## Check the condition guarding the skip-tighten assignment names both cases, that the flag defaults
## OFF (empty) for every other case, and that the flag is forwarded to capture_settled.
gate_ctx="$(grep -B3 "st_tighten_arg='skip-tighten'" "${subject}" || true)"
if grep -E --quiet '\= *art\b' <<< "${gate_ctx}" \
   && grep -E --quiet '\= *gradient\b' <<< "${gate_ctx}" \
   && grep -E --quiet "^[[:space:]]*st_tighten_arg=''" "${subject}" \
   && grep -E --quiet 'capture_settled .*"\$\{st_tighten_arg\}"' "${subject}"; then
   printf '%s\n' 'PASS: loop gates skip-tighten on art AND gradient, defaults off, forwards to capture_settled'
   pass=$(( pass + 1 ))
else
   printf '%s\n' 'FAIL: skip-tighten wiring changed -- gate must cover art AND gradient, default off, and forward the flag' >&2
   fail=$(( fail + 1 ))
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: capture_settled honours skip-tighten for the pinned colour boards'

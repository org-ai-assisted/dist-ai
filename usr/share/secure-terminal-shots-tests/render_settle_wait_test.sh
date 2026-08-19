#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: st_wait_render_settled must wait for the render to ACTUALLY settle, bounded by
## wall-clock, NOT a fixed short iteration count.
##
## Why: a full-viewport 24-bit board in SHOW/TUI mode paints ROW BY ROW over ~20s -- every cell
## carries a distinct truecolour format, which defeats the same-format run coalescing the grid
## renderer relies on, so the document is rebuilt one slow frame per PTY read. The old settle wait
## looped a fixed 10 times (~8s) and then RETURNED whether or not painting had stopped, so the
## capture grabbed a half-drawn board -- the gradient-tui-show shot lost its bottom rows, the
## greyscale ramp and the returning prompt. The fix waits until two consecutive grabs match
## (painting stopped), capped just under the per-capture SHOT_DEADLINE.
##
## This extracts st_wait_render_settled from the CURRENT comparison-capture.sh text (no drift) and
## drives it with stubs (no display, no real capture, milliseconds):
##   - a SLOW-settling window that keeps changing for 14 frames then stabilises at frame 15 must be
##     waited out to frame 15 -- the old 10-cap returned at frame 10, mid-change (the tripwire);
##   - a window already settled on the first compare returns at once (a fast render is not over-waited);
##   - a source-level check that the loop bound is wall-clock (SECONDS), not the old fixed count.
##
## Non-tautological canary: revert to `for i in 1 2 3 4 5 6 7 8 9 10` and the slow-settle case
## stops at 10 -> FAIL; drop the settle break entirely and the fast case runs to the cap -> FAIL.
##
## Subject: comparison-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR / a checkout default /
## the install path (absent -> exit 77 SKIP). Needs ImageMagick's `compare` on PATH (the function
## early-returns without it); the actual comparisons are stubbed, so it is only the PATH guard.

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
   if [ -f "${cand}" ]; then
      subject="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' 'SKIP: comparison-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 77
fi

## The function early-returns unless `compare` is on PATH; require it so the loop is exercised.
if ! type -P compare >/dev/null 2>&1; then
   printf '%s\n' 'SKIP: ImageMagick `compare` not on PATH (st_wait_render_settled early-returns)' >&2
   exit 77
fi

## Extract the function from the current script text (opens `name() {` at column 0, closes with a
## column-0 `}`), so the tested body stays in step with the source -- no re-embedded copy to drift.
fn="$(sed -n '/^st_wait_render_settled() {/,/^}/p' "${subject}")"
if [ -z "${fn}" ]; then
   printf '%s\n' 'FAIL: could not extract st_wait_render_settled from comparison-capture.sh' >&2
   printf '%s\n' '' '0 pass, 1 fail, 0 skip'
   exit 1
fi
eval "${fn}"

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

## Collaborators the function calls. runtime_dir/SHOT_DEADLINE are globals it reads.
runtime_dir="${work}"
SHOT_DEADLINE=90
## No real waiting or grabbing: sleep is a no-op (the test is instant and the wall-clock budget is
## never approached), capture_window just succeeds, and `compare` returns a scripted diff sequence
## driven by a call counter -- a big diff (still painting) until `settle_at`, then 0 (settled).
sleep() { :; }
capture_window() { return 0; }
settle_at=0
compare() {
   local n
   n="$(cat "${work}/n" 2>/dev/null || printf '%s' 0)"
   n=$(( n + 1 ))
   printf '%s' "${n}" > "${work}/n"
   if [ "${n}" -ge "${settle_at}" ]; then printf '%s' 0; else printf '%s' 999999; fi
}

pass=0
fail=0
eq() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf '%s\n' "PASS: $3"; pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $3"; printf '%s\n' "  got : $1" "  want: $2"; fail=$(( fail + 1 ))
   fi
}

## --- slow-settling window: keeps changing for 14 frames, stable at 15 -------------------------
## The old fixed 10-iteration cap returned at frame 10 (still changing) -> a half-drawn grab.
printf '%s' 0 > "${work}/n"
settle_at=15
st_wait_render_settled dummy-wid
eq "$(cat "${work}/n")" 15 'waits out a slow-settling window to the frame it stabilises (past the old 10-cap)'

## --- already-settled window: first compare matches -> return at once (no over-wait) -----------
printf '%s' 0 > "${work}/n"
settle_at=1
st_wait_render_settled dummy-wid
eq "$(cat "${work}/n")" 1 'a window already settled returns on the first comparison (fast render not over-waited)'

## --- source-level: the loop bound is wall-clock, not the old fixed 10 iterations ---------------
if grep -E --quiet 'while \[ \$\(\( SECONDS - start \)\) -lt "\$\{budget\}" \]' "${subject}" \
   && ! grep -E --quiet 'for i in 1 2 3 4 5 6 7 8 9 10; do' "${subject}"; then
   eq present present 'the settle loop is wall-clock bounded (SECONDS), not a fixed 10 iterations'
else
   eq missing present 'the settle loop is wall-clock bounded (SECONDS), not a fixed 10 iterations'
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]

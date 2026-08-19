#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: hero-slider-compose.py must produce a homepage slider pair whose two windows are
## the SAME horizontal length. The two hero shots are pinned to one width at capture
## (comparison-capture.sh HERO_WIN_W_BASE, applied to BOTH the secure-terminal and the
## gnome-terminal window); compose is the final guarantor -- it unifies the pair to the narrower
## window's width and FAILS LOUD on a gap wider than one shared cell.
##
## Asserts:
##   match     a 6 px cell-snap gap composes to two EQUAL-sized outputs unified to the narrower
##             window (no white dead-space band on one side of the slider).
##   mismatch  the pre-fix 123 px gap is REJECTED (non-zero) instead of papered over.
##
## FAILS on the pre-change tree: the old compose padded to the MAX width and returned 0 for any
## gap, so the mismatch case is accepted and the outputs are unequal-width -- a genuine
## regression test, not a tautology.
##
## Subject: hero-slider-compose.py in secure-terminal-shots/ (absent -> exit 77 SKIP). Needs
## python3-pil (a declared package dependency); genuinely absent -> exit 77 SKIP.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

shots_dir=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}" \
   "${script_dir}/../secure-terminal-shots" \
   "${script_dir}/../../share/secure-terminal-shots" \
   '/usr/share/secure-terminal-shots'; do
   if [ -n "${cand}" ] && [ -d "${cand}" ] && [ -f "${cand}/hero-slider-compose.py" ]; then
      shots_dir="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${shots_dir}" ]; then
   printf '%s\n' 'SKIP: secure-terminal-shots dir not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 77
fi
if ! python3 -c 'import PIL' 2>/dev/null; then
   printf '%s\n' 'SKIP: python3-pil (Pillow) not installed' >&2
   exit 77
fi
compose="${shots_dir}/hero-slider-compose.py"
checker="${script_dir}/hero_slider_compose_check.py"

pass=0
fail=0

check() {  ## $1=label $2=mode $3=expected-verdict
   local label="$1" mode="$2" want="$3" got
   got="$(python3 "${checker}" "${compose}" "${mode}" 2>/dev/null || true)"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label} (expected '${want}', got '${got}')"
      fail=$(( fail + 1 ))
   fi
}

check 'a cell-snap gap unifies to the narrower window (equal-width outputs)' match 'OK match'
check 'a large width gap is rejected (capture-time pin regression canary)'   mismatch 'OK mismatch'

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: hero-slider-compose.py unifies the hero pair width and rejects a broken pin'

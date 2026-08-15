#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: hero-board.py must emit the homepage hero board carrying EXACTLY the four
## documented display-deception primitives (homoglyph U+0430, bidi U+202E/U+202C, an OSC-0
## title-set, an OSC-52 clipboard-write) and NOTHING more dangerous -- the honest-bytes
## contract the page's before/after slider and its caption rest on. Also asserts the SOURCE
## stays pure ASCII (the hostile bytes live only in the emitted stream, via \u/\x escapes), so
## a future edit that pastes a literal non-ASCII byte -- or drops/mangles a primitive, or lets
## an unsafe escape (CSI / alt-screen / clear / charset shift) creep in -- fails here.
##
## FAILS on a tree where any primitive is dropped or an unsafe escape is added (hero_board_check
## returns non-'OK cat-safe'), and where the source carries a literal non-ASCII byte -- a genuine
## regression test, not a tautology.
##
## Subject: hero-board.py in secure-terminal-shots/ (absent -> exit 77 SKIP). Pure Python stdlib,
## no display, no Qt -- runs in the dist-ai container in milliseconds.

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
   if [ -n "${cand}" ] && [ -d "${cand}" ] && [ -f "${cand}/hero-board.py" ]; then
      shots_dir="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${shots_dir}" ]; then
   printf '%s\n' 'SKIP: secure-terminal-shots dir not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 77
fi
gen="${shots_dir}/hero-board.py"
checker="${script_dir}/hero_board_check.py"

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0

check() {  ## $1=label $2=condition-rc (0 pass) -- caller already evaluated
   if [ "$2" -eq 0 ]; then
      printf '%s\n' "PASS: $1"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"
      fail=$(( fail + 1 ))
   fi
}

## 1. The board emits all four primitives and stays cat-safe.
rc=0
"${gen}" > "${work}/hero.payload" 2>"${work}/err.log" || rc=$?
check 'generator exits 0 with no args' "${rc}"
verdict="$(python3 "${checker}" "${work}/hero.payload" 2>/dev/null || true)"
[ "${verdict}" = 'OK cat-safe' ]; check "board carries the four primitives and is cat-safe (got '${verdict}')" "$?"

## 2. The SOURCE is pure ASCII -- the hostile bytes are \u/\x escapes, not literals.
if grep -qP '[^\x00-\x7F]' "${gen}"; then
   check 'hero-board.py source is pure ASCII' 1
else
   check 'hero-board.py source is pure ASCII' 0
fi

## 3. Extra args are rejected (usage error), so a mis-call cannot silently emit a partial board.
rc=0
"${gen}" unexpected-arg >/dev/null 2>&1 || rc=$?
[ "${rc}" -ne 0 ]; check "extra argument rejected (rc=${rc})" "$?"

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: hero-board.py emits the four documented primitives, stays cat-safe, ASCII source'

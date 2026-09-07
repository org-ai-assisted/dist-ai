#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the full-viewport colour boards (truecolor-art.py / truecolor-gradient.py) are
## pinned to secure-terminal's inner grid width (ST_BOARD_COLS). Pin them WIDER than the live
## grid and every board line hard-wraps into a short continuation row -- the "striped board" shot
## that once shipped when the pinned width drifted past the real grid. board-wrap-check.py reads
## the captured transcript (SECURE_TERMINAL_TRANSCRIPT_FILE) and FAILS a capture whose board
## wrapped, so a stale pin cannot silently publish a striped board. The check is mode-agnostic (a
## clean board is a rectangle of equal-width rows once the prompt is dropped), so it covers BOTH
## the Show board (U+2580 rows) AND the neutralised Box board (multi-char cells, no U+2580). This
## exercises the guard against synthetic transcripts (no display, no Qt, milliseconds).
##
## FAILS on a tree without the guard: board-wrap-check.py is absent -> FATAL below (the exact
## silent-drift regression this closes).
##
## Subject: board-wrap-check.py in secure-terminal-shots/ (absent -> exit 1 FATAL). Pure Python
## stdlib.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

shots_dir=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}" \
   "${script_dir}/../secure-terminal-shots" \
   "${script_dir}/../../share/secure-terminal-shots" \
   '/usr/share/secure-terminal-shots'; do
   if [ -n "${cand}" ] && [ -d "${cand}" ] && [ -f "${cand}/board-wrap-check.py" ]; then
      shots_dir="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${shots_dir}" ]; then
   printf '%s\n' 'FATAL: board-wrap-check.py not found (set SECURE_TERMINAL_SHOTS_DIR) -- old harness, no wrap guard' >&2
   exit 1
fi
guard="${shots_dir}/board-wrap-check.py"

prompt='user@host:~$ '

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0

## U+2580 UPPER HALF BLOCK as its raw UTF-8 bytes (E2 96 80), emitted via octal escape so this
## test source stays pure ASCII; board-wrap-check.py decodes the file as UTF-8 regardless of the
## C locale set above.
hb_line() {  ## $1=count [$2=trailing-space-count] -> half-blocks (+ optional trailing spaces) + newline
   local n="$1" pad="${2:-0}" i line=''
   for (( i = 0; i < n; i++ )); do
      line+="$(printf '\342\226\200')"
   done
   for (( i = 0; i < pad; i++ )); do
      line+=' '
   done
   printf '%s\n' "${line}"
}

## A neutralised (Box-mode) board row: a multi-char cell unit repeated, no U+2580. Width scales
## with the cell count, exactly like the real Box transcript (each cell many chars).
box_line() {  ## $1=cell-count -> that many '[X]' cells + newline
   local n="$1" i line=''
   for (( i = 0; i < n; i++ )); do
      line+='[X]'
   done
   printf '%s\n' "${line}"
}

## $1=label $2=want-rc  (transcript already written to ${work}/t.txt)
run_rc() {
   local label="$1" want="$2" got=0
   "${guard}" "${work}/t.txt" --cols 118 --prompt "${prompt}" >/dev/null 2>&1 || got="$?"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label} (rc=${got})"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label}"
      printf '%s\n' "  got rc : ${got}"
      printf '%s\n' "  want rc: ${want}"
      fail=$(( fail + 1 ))
   fi
}

## --- Show board (U+2580 rows) ---

## Clean: 3 rows each exactly the pinned 118 wide, with the prompt echo + returning prompt around
## it -- the prompt lines are dropped, the board is a clean rectangle -> passes.
{ printf '%s\n' 'user@host:~$ cat gradient.payload'; hb_line 118; hb_line 118; hb_line 118; \
   printf '%s\n' 'user@host:~$'; } > "${work}/t.txt"
run_rc 'a clean 118-wide Show board (with prompt lines) passes' 0

## Wrapped: the striped-shot shape -- each source line overflowed by 2 and hard-wrapped, so a full
## 118 row alternates with a 2-wide fragment.
{ hb_line 118; hb_line 2; hb_line 118; hb_line 2; hb_line 118; hb_line 2; } > "${work}/t.txt"
run_rc 'a wrapped Show board (ragged rows) is rejected' 1

## Uniformly narrow: every Show row rendered at 110 (the pin 118 does not match) -> rejected even
## though the rows are all the same width (payload/grid mismatch, caught by the exact-cols check).
{ hb_line 110; hb_line 110; hb_line 110; } > "${work}/t.txt"
run_rc 'a uniformly-narrow Show board (width != pinned cols) is rejected' 1

## --- Neutralised Box board (multi-char cells, no U+2580) ---

## Clean: 3 rows of 118 identical multi-char cells -> a clean rectangle -> passes (no exact-cols
## assertion for a non-Show board, since a cell is many chars wide).
{ box_line 118; box_line 118; box_line 118; } > "${work}/t.txt"
run_rc 'a clean Box board (multi-char cells) passes' 0

## Wrapped: full 118-cell rows alternating with 2-cell fragments -- the striped Box shot the
## old Show-only guard missed entirely.
{ box_line 118; box_line 2; box_line 118; box_line 2; box_line 118; box_line 2; } > "${work}/t.txt"
run_rc 'a wrapped Box board (ragged rows) is rejected' 1

## --- trailing-whitespace robustness (grid padding) ---

## A wrap fragment padded with trailing spaces is still a fragment (width is rstrip'd) -> rejected.
{ hb_line 118; hb_line 2 116; hb_line 118; hb_line 2 116; } > "${work}/t.txt"
run_rc 'a space-padded wrap fragment is still caught' 1

## A clean board whose rows carry trailing grid padding is still clean -> passes.
{ hb_line 118 3; hb_line 118 3; hb_line 118 3; } > "${work}/t.txt"
run_rc 'a clean board with trailing grid padding still passes' 0

## --- degenerate transcripts ---

## No board rows at all (only prompts) is a MISS, never a pass.
printf '%s\n' 'user@host:~$' '' > "${work}/t.txt"
run_rc 'a transcript with no board rows is rejected (board never rendered)' 1

## A missing transcript file is an error (rc 2), not a silent pass.
missing_rc=0
"${guard}" "${work}/does-not-exist.txt" --cols 118 --prompt "${prompt}" >/dev/null 2>&1 || missing_rc="$?"
if [ "${missing_rc}" = 2 ]; then
   printf '%s\n' 'PASS: a missing transcript file errors (rc=2), not a pass'
   pass=$(( pass + 1 ))
else
   printf '%s\n' 'FAIL: a missing transcript file should error with rc=2'
   printf '%s\n' "  got rc: ${missing_rc}"
   fail=$(( fail + 1 ))
fi

printf '%s\n' ''
printf '%s\n' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]

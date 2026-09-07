#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the full-viewport colour boards (truecolor-art.py / truecolor-gradient.py) are
## pinned to secure-terminal's inner grid width (ST_BOARD_COLS). Pin them WIDER than the live
## grid and every board line hard-wraps into a short continuation row -- the "striped gradient"
## shot that once shipped when the pinned width drifted past the real grid. board-wrap-check.py
## reads the captured transcript (SECURE_TERMINAL_TRANSCRIPT_FILE) and FAILS a capture whose
## board wrapped, so a stale pin cannot silently publish a striped board. This exercises that
## guard against synthetic transcripts (no display, no Qt, milliseconds).
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

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0

## U+2580 UPPER HALF BLOCK as its raw UTF-8 bytes (E2 96 80), emitted via octal escape so this
## test source stays pure ASCII; board-wrap-check.py decodes the file as UTF-8 regardless of the
## C locale set above.
hb_line() {  ## $1=count -> that many half-block glyphs + newline
   local n="$1" i line=''
   for (( i = 0; i < n; i++ )); do
      line+="$(printf '\342\226\200')"
   done
   printf '%s\n' "${line}"
}

## $1=label $2=expected-rc  -- runs the guard on ${work}/t.txt at --cols 118 and compares rc.
run_rc() {  ## $1=label $2=want-rc  (transcript already written to ${work}/t.txt)
   local label="$1" want="$2" got=0
   "${guard}" "${work}/t.txt" --cols 118 >/dev/null 2>&1 || got="$?"
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

## A CLEAN board: 3 rows, each exactly the pinned 118 wide -> passes (rc 0). This is the shape a
## correctly-pinned board renders (the linefeed deferred-wrap fix leaves no trailing blank row).
{ hb_line 118; hb_line 118; hb_line 118; } > "${work}/t.txt"
run_rc 'a clean 118-wide board passes' 0

## A WRAPPED board: the exact striped-shot shape -- each source line overflowed the 118 grid by 2
## and hard-wrapped, so a full 118 row alternates with a 2-wide continuation fragment. MUST fail.
{ hb_line 118; hb_line 2; hb_line 118; hb_line 2; hb_line 118; hb_line 2; } > "${work}/t.txt"
run_rc 'a wrapped board (full rows + short fragments) is rejected' 1

## An OVERSHOT board: the pin (118) is WIDER than the live grid (all rows rendered at 110), so
## every row is short. The original bug: a board pinned past the grid renders uniformly narrow.
{ hb_line 110; hb_line 110; hb_line 110; } > "${work}/t.txt"
run_rc 'a board narrower than the pin (grid shrank) is rejected' 1

## Board rows mixed with the shell echo + prompt (non-half-block lines): the prompt/echo are
## ignored, the board rows are all 118 -> passes. Proves the guard keys on board rows only.
{ printf '%s\n' 'user@host:~$ cat gradient.payload'; hb_line 118; hb_line 118; \
   printf '%s\n' 'user@host:~$'; } > "${work}/t.txt"
run_rc 'prompt/echo lines are ignored; a clean board still passes' 0

## No board rows at all (an empty / never-rendered transcript) is a MISS, never a pass.
printf '%s\n' 'user@host:~$' '' > "${work}/t.txt"
run_rc 'a transcript with no board rows is rejected (board never rendered)' 1

## A missing transcript file is an error (rc 2), not a silent pass.
missing_rc=0
"${guard}" "${work}/does-not-exist.txt" --cols 118 >/dev/null 2>&1 || missing_rc="$?"
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

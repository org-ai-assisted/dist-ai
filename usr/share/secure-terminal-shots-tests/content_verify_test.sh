#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the secure-terminal GUI shots gained a CONTENT verifier so a capture can
## never publish an EMPTY terminal (bare prompt) as if the payload had rendered -- a
## screenshot cannot tell the two apart because the window chrome paints either way. Two
## pure-shell helpers, tested here (no display, no capture, milliseconds):
##
##   shots_transcript_has_content <file> <prompt>
##     True iff secure-terminal's live transcript file (SECURE_TERMINAL_TRANSCRIPT_FILE)
##     carries real payload output, not just bare prompts + grid padding. Rejects an empty grab.
##
##   shots_st_inject_cmd <case> <tui?>
##     The command injected for a GUI shot: the plain payload, EXCEPT tui-showcase in TUI, which
##     cats the WITH-prompt board sibling so its embedded prompt shows 'cat' at the top of the
##     alt-screen shot. CLI cats the in-place-stripped tui-showcase.payload (clean echo, no dup).
##
## Both FAIL on the old harness (neither helper existed), so this is a real tripwire.
##
## Subject: lib-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR, a checkout default, or
## the installed path. Absent -> exit 1 (FATAL): a required subject is an environment bug (R-220).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/lib-capture.sh" \
   "${script_dir}/../secure-terminal-shots/lib-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/lib-capture.sh" \
   '/usr/share/secure-terminal-shots/lib-capture.sh'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      lib="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${lib}" ]; then
   printf '%s\n' 'FATAL: lib-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi

# shellcheck source=../secure-terminal-shots/lib-capture.sh
source "${lib}"

pass=0
fail=0
eq() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf '%s\n' "PASS: $3"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $3"
      printf '%s\n' "  got : $1"
      printf '%s\n' "  want: $2"
      fail=$(( fail + 1 ))
   fi
}

## Both helpers MUST exist -- absent means the old harness (no content verifier / no mode-aware
## tui-showcase payload selection), a regression trip.
for fn in shots_transcript_has_content shots_st_inject_cmd; do
   if ! declare -F "${fn}" >/dev/null 2>&1; then
      printf '%s\n' "FAIL: ${fn} not defined -- old harness"
      printf '%s\n' '' '0 pass, 1 fail, 0 skip'
      exit 1
   fi
done

prompt='user@host:~$ '
tmp="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${tmp}" 2>/dev/null || true; }
trap cleanup EXIT

## --- shots_transcript_has_content --------------------------------------------------

## An EMPTY terminal: only bare prompts and blank grid rows (the exact shape of the
## empty altscreen-tui shot -- the returning prompt clobbered the alt-screen frame).
printf '%s\n' 'user@host:~$' 'user@host:~$' '   ' '' > "${tmp}/empty.txt"
if shots_transcript_has_content "${tmp}/empty.txt" "${prompt}"; then
   eq has-content empty 'a prompt-only transcript is rejected as EMPTY'
else
   eq empty empty 'a prompt-only transcript is rejected as EMPTY'
fi

## A FULL terminal: the alt-screen canary rendered (held frame). Must pass.
printf '%s\n' \
   'POC-CORPUS-CANARY-FIRED -- stuck in the alternate screen; no prompt, no cursor' \
   'user@host:~$' > "${tmp}/canary.txt"
if shots_transcript_has_content "${tmp}/canary.txt" "${prompt}"; then
   eq has-content has-content 'a transcript carrying the rendered canary passes'
else
   eq empty has-content 'a transcript carrying the rendered canary passes'
fi

## A CLI shot: the command echo alone (payload printed nothing visible) is still content.
printf '%s\n' 'user@host:~$ cat escape.payload' 'user@host:~$' > "${tmp}/cli.txt"
if shots_transcript_has_content "${tmp}/cli.txt" "${prompt}"; then
   eq has-content has-content 'a transcript with the injected command echo passes'
else
   eq empty has-content 'a transcript with the injected command echo passes'
fi

## A truecolor board fills the grid with glyphs -- clearly content, no prompt needed.
printf '%s\n' '########################################' > "${tmp}/board.txt"
if shots_transcript_has_content "${tmp}/board.txt" "${prompt}"; then
   eq has-content has-content 'a full-screen board transcript passes'
else
   eq empty has-content 'a full-screen board transcript passes'
fi

## A missing transcript file is a MISS (never treated as content-present).
if shots_transcript_has_content "${tmp}/does-not-exist.txt" "${prompt}"; then
   eq has-content miss 'a missing transcript file is a miss, not a pass'
else
   eq miss miss 'a missing transcript file is a miss, not a pass'
fi

## --- shots_st_inject_cmd: tui-showcase payload is mode-aware --------------------------

## tui-showcase in TUI enters the alt screen (hiding the real command), so it cats the WITH-prompt
## board sibling -- that board's embedded prompt line is what shows 'cat' at the top.
eq "$(shots_st_inject_cmd tui-showcase tui)" 'cat tui-showcase-withprompt.payload' \
   'tui-showcase TUI cats the WITH-prompt board sibling (embedded prompt shows at the top)'

## tui-showcase in CLI renders inline and shows the REAL typed prompt, so it cats the plain
## tui-showcase.payload (stripped in place) by its clean name -- no duplicate, clean echo.
eq "$(shots_st_inject_cmd tui-showcase '')" 'cat tui-showcase.payload' \
   'tui-showcase CLI cats the plain (in-place-stripped) board by its clean name'

## Every other case is mode-independent and cats its plain payload in both modes.
eq "$(shots_st_inject_cmd altscreen tui)" 'cat altscreen.payload' \
   'altscreen TUI cats the plain payload (no special-casing)'
eq "$(shots_st_inject_cmd escape '')" 'cat escape.payload' \
   'escape CLI cats the plain payload'

printf '%s\n' ''
printf '%s\n' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]

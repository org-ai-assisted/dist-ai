#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Driven by terminal-resilience-tests (opt-in). On a private Xvfb display:
##   1. feed a hostile stream (an OSC 0 title-set to a known marker, plus a
##      charset shift, a stuck colour and some bytes) to xterm, and assert its
##      window title (WM_NAME, read via xdotool) was HIJACKED to the marker --
##      proving a traditional emulator acts on untrusted output;
##   2. feed the identical stream through secure-terminal-cli and assert it is
##      NEUTRALIZED: the output carries no escape byte and the marker text is
##      stripped (never emitted, so it could never reach a title).
## Exit 0 if both hold, 1 on any failure. Cleans up the emulator and Xvfb.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

repo="$1"
cli="${repo}/usr/bin/secure-terminal-cli"

marker='RESILIENCE-HIJACK-MARKER'
## printf format string: OSC 0 title-set to the marker, DEC line-drawing charset
## shift, a stuck SGR colour, and plain text. \033 = ESC, \007 = BEL.
payload='before\033]0;'"${marker}"'\007\033(0lqk\033[31;41mSTUCK\033[0mafter\n'

## -- private X display -----------------------------------------------------
display_num=99
while [ -e "/tmp/.X11-unix/X${display_num}" ] && [ "${display_num}" -lt 120 ]; do
   display_num=$(( display_num + 1 ))
done
export DISPLAY=":${display_num}"
runtime_dir="$(mktemp --directory)"
export XDG_RUNTIME_DIR="${runtime_dir}"

xvfb_pid=''
xterm_pid=''
cleanup() {
   [ -z "${xterm_pid}" ] || kill "${xterm_pid}" 2>/dev/null || true
   [ -z "${xvfb_pid}" ] || kill "${xvfb_pid}" 2>/dev/null || true
   rm -rf -- "${runtime_dir}" 2>/dev/null || true
}
trap cleanup EXIT

Xvfb "${DISPLAY}" -screen 0 800x600x24 >/dev/null 2>&1 &
xvfb_pid="$!"
sleep 2

overall=0

## -- 1. xterm: title must be hijacked -------------------------------------
xterm -T 'resilience-probe-start' -e bash -c "printf '${payload}'; sleep 8" \
   >/dev/null 2>&1 &
xterm_pid="$!"

win=''
for _ in $(seq 1 40); do
   win="$(xdotool search --onlyvisible --class xterm 2>/dev/null | head -1 || true)"
   [ -n "${win}" ] && break
   sleep 0.25
done

if [ -z "${win}" ]; then
   printf 'terminal-resilience-tests: FAIL (xterm window never appeared)\n' >&2
   overall=1
else
   sleep 1
   title="$(xdotool getwindowname "${win}" 2>/dev/null || true)"
   if printf '%s' "${title}" | grep --quiet --fixed-strings -- "${marker}"; then
      printf 'ok   xterm: title HIJACKED to %s (traditional emulator acts on output)\n' "${marker}"
   else
      printf 'terminal-resilience-tests: FAIL (xterm title not hijacked; got %s)\n' "${title:-<empty>}" >&2
      overall=1
   fi
fi
kill "${xterm_pid}" 2>/dev/null || true
xterm_pid=''

## -- 2. secure-terminal: stream must be neutralized -----------------------
out="$( printf '' | python3 -- "${cli}" -- printf "${payload}" 2>/dev/null || true )"

if printf '%s' "${out}" | grep --quiet --perl-regexp -- '\x1b'; then
   printf 'terminal-resilience-tests: FAIL (secure-terminal output still carries an escape byte)\n' >&2
   overall=1
elif printf '%s' "${out}" | grep --quiet --fixed-strings -- "${marker}"; then
   printf 'terminal-resilience-tests: FAIL (secure-terminal leaked the title marker %s)\n' "${marker}" >&2
   overall=1
else
   printf 'ok   secure-terminal: stream NEUTRALIZED (no escape byte, title marker stripped)\n'
fi

if [ "${overall}" -eq 0 ]; then
   printf 'terminal-resilience-tests: PASS (xterm hijacked, secure-terminal neutralized)\n'
fi
exit "${overall}"

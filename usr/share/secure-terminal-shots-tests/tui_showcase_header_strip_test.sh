#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: shots_generate_logs (lib-capture.sh) must strip the human-facing "read me
## first" safety preamble from the tui-showcase SHOT payload, keeping the board proper --
## which begins at the first ESC (0x1b) and still carries the 'cat tui-showcase.payload'
## echo. The corpus payload keeps its header (for raw downloads); only the shot copy is
## stripped. Without the strip the header lingers in secure-terminal's CLI shot (normal
## terminals hide it via the alt-screen switch), wasting vertical space and making the ST
## shot look artificially different from the emulator shots.
##
## Drives the REAL shots_generate_logs (no synthetic copy). Subjects: lib-capture.sh + the
## terminal-poc-corpus (reproduce.py). Absent is an environment bug -> exit 1 (FATAL, R-220).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

## Resolve the shots harness dir (holds lib-capture.sh), mirroring shot_generators_smoke_test.sh.
shots_dir=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}" \
   "${script_dir}/../secure-terminal-shots" \
   "${script_dir}/../../share/secure-terminal-shots" \
   '/usr/share/secure-terminal-shots'; do
   if [ -n "${cand}" ] && [ -d "${cand}" ] && [ -f "${cand}/lib-capture.sh" ]; then
      shots_dir="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${shots_dir}" ]; then
   printf '%s\n' 'FATAL: secure-terminal-shots dir not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi

## The corpus (reproduce.py) is the payload source; absent -> exit 1 (FATAL), matching shots_generate_logs.
corpus=''
for cand in \
   "${CORPUS_REPO:-}" \
   "${shots_dir}/../../../../terminal-poc-corpus" \
   "${HOME}/private-sources/terminal-poc-corpus"; do
   if [ -n "${cand}" ] && [ -f "${cand}/tools/reproduce.py" ]; then
      corpus="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${corpus}" ]; then
   printf '%s\n' 'FATAL: terminal-poc-corpus not found (set CORPUS_REPO)' >&2
   exit 1
fi
export CORPUS_REPO="${corpus}"

# shellcheck source=../secure-terminal-shots/lib-capture.sh
. "${shots_dir}/lib-capture.sh"

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

## Real generation. Any non-zero (corpus absent or a real generation failure) is a
## hard failure -- the corpus is a required input (R-220).
rc=0
shots_generate_logs "${shots_dir}" "${work}" || rc=$?
if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: shots_generate_logs exited ${rc}" >&2
   exit 1
fi

payload="${work}/tui-showcase.payload"
pass=0
fail=0
assert() {  ## $1=description ; succeeds iff $2==ok
   if [ "$2" = ok ]; then
      printf '%s\n' "PASS: $1"; pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"; fail=$(( fail + 1 ))
   fi
}

[ -s "${payload}" ] && assert 'tui-showcase.payload produced' ok || assert 'tui-showcase.payload produced' no

## Starts with ESC (header stripped to the board's first escape).
if [ -s "${payload}" ] && grep --quiet '1b' <<< "$(head -c 1 -- "${payload}" | od -An -tx1)"; then
   assert 'payload starts with ESC (header stripped)' ok
else
   assert 'payload starts with ESC (header stripped)' no
fi
## After the HEADER strip the embedded prompt is KEPT (traditional emulators need it: their
## alt-screen hides the real typed command, so it puts 'cat' at the top of THEIR shots).
if grep --quiet --fixed-strings 'user@host:~$ cat tui-showcase.payload' -- "${payload}"; then
   assert 'embedded prompt kept after header strip (for emulators)' ok
else
   assert 'embedded prompt kept after header strip (for emulators)' no
fi
## The board itself is intact (only the header was trimmed).
if grep --quiet --fixed-strings 'TERMINAL TEXT' -- "${payload}"; then
   assert 'board content intact' ok
else
   assert 'board content intact' no
fi
## The secure-terminal-pass prompt strip then removes the embedded prompt (it renders inline and
## shows the real prompt, so the embedded copy would duplicate). Board stays intact.
"${shots_dir}/strip-tui-showcase-prompt.py" "${payload}"
if grep --quiet --fixed-strings 'user@host:~$ cat tui-showcase.payload' -- "${payload}"; then
   assert 'embedded prompt removed for secure-terminal pass' no
else
   assert 'embedded prompt removed for secure-terminal pass' ok
fi
if grep --quiet --fixed-strings 'TERMINAL TEXT' -- "${payload}"; then
   assert 'board content intact after prompt strip' ok
else
   assert 'board content intact after prompt strip' no
fi
## Header text and its URL are gone.
if grep --quiet --fixed-strings 'read me first' -- "${payload}"; then
   assert 'read-me-first header removed' no
else
   assert 'read-me-first header removed' ok
fi
if grep --quiet --fixed-strings 'secure-terminal.github.io' <<< "$(head -c 200 -- "${payload}")"; then
   assert 'header URL removed from top of payload' no
else
   assert 'header URL removed from top of payload' ok
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
printf '%s\n' 'OK: tui-showcase shot payload header stripped, board + cat echo intact'

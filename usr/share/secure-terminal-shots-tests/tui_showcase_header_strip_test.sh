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
## terminal-poc-corpus (reproduce.py). Genuinely absent -> exit 77 (SKIP), never FAIL.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

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
   printf '%s\n' 'SKIP: secure-terminal-shots dir not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 77
fi

## The corpus (reproduce.py) is the payload source; absent -> SKIP, matching shots_generate_logs.
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
   printf '%s\n' 'SKIP: terminal-poc-corpus not found (set CORPUS_REPO)' >&2
   exit 77
fi
export CORPUS_REPO="${corpus}"

# shellcheck source=../secure-terminal-shots/lib-capture.sh
. "${shots_dir}/lib-capture.sh"

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

## Real generation. 77 from the function means the corpus vanished mid-run -> SKIP; any other
## non-zero is a real generation failure.
rc=0
shots_generate_logs "${shots_dir}" "${work}" || rc=$?
if [ "${rc}" -eq 77 ]; then
   printf '%s\n' 'SKIP: shots_generate_logs reported the corpus absent' >&2
   exit 77
fi
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
if [ -s "${payload}" ] && head -c 1 -- "${payload}" | od -An -tx1 | grep -q '1b'; then
   assert 'payload starts with ESC (header stripped)' ok
else
   assert 'payload starts with ESC (header stripped)' no
fi
## After the HEADER strip the embedded prompt is KEPT (traditional emulators need it: their
## alt-screen hides the real typed command, so it puts 'cat' at the top of THEIR shots).
if grep -qF 'user@host:~$ cat tui-showcase.payload' -- "${payload}"; then
   assert 'embedded prompt kept after header strip (for emulators)' ok
else
   assert 'embedded prompt kept after header strip (for emulators)' no
fi
## The board itself is intact (only the header was trimmed).
if grep -qF 'TERMINAL TEXT' -- "${payload}"; then
   assert 'board content intact' ok
else
   assert 'board content intact' no
fi
## The secure-terminal-pass prompt strip then removes the embedded prompt (it renders inline and
## shows the real prompt, so the embedded copy would duplicate). Board stays intact.
"${shots_dir}/strip-tui-showcase-prompt.py" "${payload}"
if grep -qF 'user@host:~$ cat tui-showcase.payload' -- "${payload}"; then
   assert 'embedded prompt removed for secure-terminal pass' no
else
   assert 'embedded prompt removed for secure-terminal pass' ok
fi
if grep -qF 'TERMINAL TEXT' -- "${payload}"; then
   assert 'board content intact after prompt strip' ok
else
   assert 'board content intact after prompt strip' no
fi
## Header text and its URL are gone.
if grep -qF 'read me first' -- "${payload}"; then
   assert 'read-me-first header removed' no
else
   assert 'read-me-first header removed' ok
fi
if head -c 200 -- "${payload}" | grep -qF 'secure-terminal.github.io'; then
   assert 'header URL removed from top of payload' no
else
   assert 'header URL removed from top of payload' ok
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
printf '%s\n' 'OK: tui-showcase shot payload header stripped, board + cat echo intact'

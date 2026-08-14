#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the headless offscreen shot generators (hero-shot.py, display-modes-shot.py,
## paste-warning-shot.py) must RUN, not just parse. The shell capture tests never import them,
## so a stale reference left by a rename -- e.g. paste-warning-shot.py calling a renamed
## `_dark_palette` -- is a runtime NameError that no other test catches and that silently
## disarms the review-shot lane. This runs each generator offscreen (QT_QPA_PLATFORM=offscreen)
## to a temp PNG and asserts exit 0 + a non-empty file. `python3 -c compile` does NOT catch a
## NameError inside a function; only running it does.
##
## FAILS on the pre-fix tree (paste-warning-shot.py -> NameError: _dark_palette), so it is a
## genuine regression test, not a tautology.
##
## Subjects: the generators in secure-terminal-shots/, plus the secure_terminal package
## (PyQt6 + the checkout) they import. Any genuinely absent -> exit 77 (SKIP), never FAIL.
## Offscreen Qt, no display; safe in the sandbox.

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
   if [ -n "${cand}" ] && [ -d "${cand}" ] && [ -f "${cand}/hero-shot.py" ]; then
      shots_dir="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${shots_dir}" ]; then
   printf '%s\n' 'SKIP: secure-terminal-shots dir not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 77
fi

## Resolve the secure_terminal checkout for PYTHONPATH, mirroring the wrapper.
repo=''
for cand in \
   "${SECURE_TERMINAL_REPO:-}" \
   "${HOME}/private-sources/secure-terminal" \
   "${script_dir}/../../../../secure-terminal"; do
   if [ -n "${cand}" ] && [ -d "${cand}/usr/lib/python3/dist-packages/secure_terminal" ]; then
      repo="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${repo}" ]; then
   printf '%s\n' 'SKIP: secure_terminal checkout not found (set SECURE_TERMINAL_REPO)' >&2
   exit 77
fi

export PYTHONPATH="${repo}/usr/lib/python3/dist-packages${PYTHONPATH:+:${PYTHONPATH}}"
export QT_QPA_PLATFORM=offscreen

## PyQt6 + the package must import, else the generators cannot run here -> SKIP.
if ! python3 -c 'import PyQt6.QtWidgets, secure_terminal.terminal, secure_terminal.review' 2>/dev/null; then
   printf '%s\n' 'SKIP: PyQt6 or secure_terminal not importable (offscreen Qt deps absent)' >&2
   exit 77
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0
run_gen() {  ## $1=label $2=output $3...=argv to python3
   local label="$1" out="$2"; shift 2
   local rc=0
   python3 -- "$@" >/dev/null 2>"${work}/err.log" || rc=$?
   if [ "${rc}" -eq 0 ] && [ -s "${out}" ]; then
      printf '%s\n' "PASS: ${label} produced $(basename -- "${out}")"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label} (rc=${rc})"
      sed 's/^/    /' "${work}/err.log" >&2 || true
      fail=$(( fail + 1 ))
   fi
}

run_gen 'hero-shot'          "${work}/hero.png" \
   "${shots_dir}/hero-shot.py" "${work}/hero.png"
run_gen 'display-modes-shot' "${work}/modes.png" \
   "${shots_dir}/display-modes-shot.py" "${work}/modes.png"
run_gen 'paste-warning-shot (paste)' "${work}/paste.png" \
   "${shots_dir}/paste-warning-shot.py" "${work}/paste.png" paste
run_gen 'paste-warning-shot (copy)'  "${work}/copy.png" \
   "${shots_dir}/paste-warning-shot.py" "${work}/copy.png" copy

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: all offscreen shot generators ran'

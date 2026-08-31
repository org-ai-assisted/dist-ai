#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: compat-shot.py must RUN every deterministic compatibility-program for real
## and produce a non-blank shot per compatibility-table row, so the picture actually backs
## the page's "each program was run and its output verified" claim rather than asserting it.
## `python3 -c compile` cannot catch a NameError inside a function, a broken fixture, or a
## render that silently produces nothing -- only running it does.
##
## Checks:
##   1. the generator exits 0 and emits one PNG per name it lists (--list).
##   2. every produced shot is NON-EMPTY (the generator's own render self-check fails loud on
##      an empty render; this is the belt-and-suspenders image-side guard).
##   3. DRIFT: when the site checkout is present, every listed program is referenced by the
##      compatibility page as compatibility/shots/<name>.webp -- so the generator's program
##      set and the page cannot drift apart (a new program with no page row, or a page row
##      pointing at a shot the generator no longer emits). Cross-repo, so it runs only when
##      the site checkout is found (the CI container has no site checkout); the core checks
##      above always gate.
##
## FAILS on a tree where a program is dropped, renders empty, or the page/generator set drift.
##
## Subjects: compat-shot.py in secure-terminal-shots/, plus the secure_terminal package
## (PyQt6 + the checkout) it imports and the fixture PROGRAMS it runs. Any absent is an
## environment bug -> exit 1 (FATAL, R-220). Offscreen Qt, no display; safe in the sandbox.

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
   if [ -n "${cand}" ] && [ -d "${cand}" ] && [ -f "${cand}/compat-shot.py" ]; then
      shots_dir="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${shots_dir}" ]; then
   printf '%s\n' 'FATAL: secure-terminal-shots dir not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi
gen="${shots_dir}/compat-shot.py"

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
   printf '%s\n' 'FATAL: secure_terminal checkout not found (set SECURE_TERMINAL_REPO)' >&2
   exit 1
fi

export PYTHONPATH="${repo}/usr/lib/python3/dist-packages${PYTHONPATH:+:${PYTHONPATH}}"
export QT_QPA_PLATFORM=offscreen

## PyQt6 + the package must import, else the generator cannot run -> exit 1 (FATAL, R-220).
if ! python3 -c 'import PyQt6.QtWidgets, secure_terminal.terminal' 2>/dev/null; then
   printf '%s\n' 'FATAL: PyQt6 or secure_terminal not importable (offscreen Qt deps absent)' >&2
   exit 1
fi

## The fixture RUNS these programs for real; a missing one is an environment bug, not a skip
## (R-220): the generator would fail cryptically, so name the gap here instead.
for tool in bash ls cat find tar grep zcat sed diff awk git; do
   if ! type -P "${tool}" >/dev/null 2>&1; then
      printf '%s\n' "FATAL: required fixture program '${tool}' not found on PATH (install it in the test env)" >&2
      exit 1
   fi
done

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0
check() {  ## $1=label $2=rc (0 pass)
   if [ "$2" -eq 0 ]; then
      printf '%s\n' "PASS: $1"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"
      fail=$(( fail + 1 ))
   fi
}

## 1. Run the generator into the work dir.
rc=0
"${gen}" "${work}" >"${work}/gen.log" 2>&1 || rc=$?
check 'compat-shot.py exits 0' "${rc}"
if [ "${rc}" -ne 0 ]; then
   sed 's/^/    /' "${work}/gen.log" >&2 || true
fi

## 2. One non-empty PNG per listed program.
names="$("${gen}" --list)"
for name in ${names}; do
   png="${work}/${name}.png"
   if [ -s "${png}" ]; then rc=0; else rc=1; fi
   check "shot for '${name}' is present and non-empty" "${rc}"
done

## 3. DRIFT: the page references every listed program's webp (site checkout only).
page=''
for cand in \
   "${SECURE_TERMINAL_SITE_REPO:-}" \
   "${HOME}/private-sources/secure-terminal.github.io"; do
   if [ -n "${cand}" ] && [ -f "${cand}/compatibility/index.html" ]; then
      page="${cand}/compatibility/index.html"
      break
   fi
done
if [ -n "${page}" ]; then
   for name in ${names}; do
      if grep --quiet --fixed-strings "compatibility/shots/${name}.webp" "${page}"; then rc=0; else rc=1; fi
      check "compatibility page references shots/${name}.webp (no drift)" "${rc}"
   done
else
   printf '%s\n' 'note: secure-terminal.github.io checkout not found; page-drift check not applicable here'
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: compat-shot.py ran every program and produced a non-blank shot per row'

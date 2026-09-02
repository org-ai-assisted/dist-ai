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
## It ALSO gates the review-shot framing: the paste/copy shots must be TIGHT -- no band of
## dead white space below their one-line payload. The ReviewBar panes carry a 130px minimum
## height and auto scrollbars sized for a multi-line paste, so a verbatim grab leaves a
## screenful of empty pane (bare white, or a stray horizontal scrollbar). paste-warning-shot.py
## sizes each pane to its line and trims to a uniform margin; this asserts no run of background
## rows exceeds MAX_DEAD_ROWS. FAILS on a tree that drops that (largest run ~150-180 rows).
##
## Subjects: the generators in secure-terminal-shots/, plus the secure_terminal package
## (PyQt6 + the checkout) they import. Any absent is an environment bug -> exit 1 (FATAL, R-220).
## Offscreen Qt, no display; safe in the sandbox.

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
   if [ -n "${cand}" ] && [ -d "${cand}" ] && [ -f "${cand}/hero-shot.py" ]; then
      shots_dir="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${shots_dir}" ]; then
   printf '%s\n' 'FATAL: secure-terminal-shots dir not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
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
   printf '%s\n' 'FATAL: secure_terminal checkout not found (set SECURE_TERMINAL_REPO)' >&2
   exit 1
fi

export PYTHONPATH="${repo}/usr/lib/python3/dist-packages${PYTHONPATH:+:${PYTHONPATH}}"
export QT_QPA_PLATFORM=offscreen

## PyQt6 + the package must import, else the generators cannot run -> exit 1 (FATAL, R-220).
if ! python3 -c 'import PyQt6.QtWidgets, secure_terminal.terminal, secure_terminal.review' 2>/dev/null; then
   printf '%s\n' 'FATAL: PyQt6 or secure_terminal not importable (offscreen Qt deps absent)' >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0
run_gen() {  ## $1=label $2=output $3...=argv (first is the +x generator, called directly)
   local label="$1" out="$2"; shift 2
   local rc=0
   "$@" >/dev/null 2>"${work}/err.log" || rc=$?
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
## zoom-shot.py sweeps the font-zoom levels and grabs the LIVE TUI grid at each (the
## white-band diagnostic). It writes one PNG per level into a DIR (not a single file),
## so smoke it with a two-level sweep and check the per-level file exists. Its output
## PATH is the dir; the checked file is one level inside it.
run_gen 'zoom-shot' "${work}/zoom/zoom-100.png" \
   "${shots_dir}/zoom-shot.py" "${work}/zoom" 100 200

## The largest contiguous run of pure-background rows a tight review shot may contain: the
## uniform frame margin plus small inter-element gaps. A dead-space regression (empty pane
## height / scrollbar band) blows far past this. The generators default to HiDPI SHOT_SCALE=2,
## so every pixel dimension -- the frame margin AND the tolerance here -- scales with it; a
## 2x-composition regression (a wrongly-DPR'd panel drawn at half size) leaves a huge dead
## band that still blows far past the scaled bound. Mirror the generators' own default so the
## two stay in step.
shot_scale="${SHOT_SCALE:-2}"
case "${shot_scale}" in ''|*[!0-9]*|0*) shot_scale=2 ;; esac
MAX_DEAD_ROWS=$(( 30 * shot_scale ))
check_tight() {  ## $1=label $2=png
   local label="$1" png="$2" run=''
   if [ ! -s "${png}" ]; then
      printf '%s\n' "FAIL: ${label} tightness (no image; generation failed)"
      fail=$(( fail + 1 ))
      return
   fi
   ## Largest run of rows entirely equal to the corner (background) pixel.
   run="$("${script_dir}/largest_bg_row_run.py" "${png}")" || run=''
   if [[ "${run}" =~ ^[0-9]+$ ]] && [ "${run}" -le "${MAX_DEAD_ROWS}" ]; then
      printf '%s\n' "PASS: ${label} tight (largest bg-row run ${run} <= ${MAX_DEAD_ROWS})"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label} has a dead-space band (largest bg-row run ${run:-?} > ${MAX_DEAD_ROWS})"
      fail=$(( fail + 1 ))
   fi
}

check_tight 'paste-warning-shot (paste)' "${work}/paste.png"
check_tight 'paste-warning-shot (copy)'  "${work}/copy.png"

## The review shots must SHOW the unicode-revealing render: the editable box, opened in the
## keep-printable form, must NAME each hidden look-alike inline (detail mode). A generator
## that breaks that render hides the very unicode detection the shot exists to demonstrate.
uc_rc=0
python3 "${script_dir}/paste_warning_unicode_check.py" "${shots_dir}/paste-warning-shot.py" \
   >/dev/null 2>"${work}/uc.log" || uc_rc=$?
if [ "${uc_rc}" -eq 0 ]; then
   printf '%s\n' 'PASS: review shot boxes show the unicode render'
   pass=$(( pass + 1 ))
else
   printf '%s\n' 'FAIL: review shot box does not show the unicode render'
   sed 's/^/    /' "${work}/uc.log" >&2 || true
   fail=$(( fail + 1 ))
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: all offscreen shot generators ran'

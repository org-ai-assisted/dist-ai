#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the comparison shots must carry an HONEST per-app favicon for secure-terminal --
## its own titlebar icon, not the compositor's generic fallback logo.
##
## Why: labwc's server-side-decoration titlebar resolves a window's icon by app-id -> a matching
## .desktop's Icon= -> the icon theme. For an X11 (Xwayland) window labwc reads that app-id from
## the WM_CLASS *instance* (Qt's -name). The capture also has to stamp each ST process with the
## run's unique reaping marker (a mktemp path) so a crashed run's orphans can be swept. The two
## needs collided: the capture passed the marker as `--name "${run_marker}"`, so ST's WM_CLASS
## instance became the temp path, labwc tried to load `<temp-path>.desktop` ("invalid file
## extension"), and every ST shot fell back to labwc's own logo. The fix pins the instance to a
## stable, theme-resolvable literal (`--name secure-terminal`, matching the installed .desktop)
## and moves the marker to the WM-neutral `--class` slot (still in argv for the pgrep reaper,
## ignored by labwc's app-id resolution).
##
## The honest-favicon chain has three source-level halves, all asserted here from the CURRENT
## text (no drift):
##   1. comparison-capture.sh pins ST's WM_CLASS instance to `secure-terminal` and NEVER to the
##      per-run marker, while still carrying the marker via `--class` (reaping intact);
##   2. comparison-capture.sh points labwc at an icon theme (Papirus) that carries the app icons;
##   3. lib-capture.sh installs secure-terminal.desktop into the session XDG_DATA_HOME so labwc
##      can complete app-id -> .desktop -> Icon= for the ST window.
##
## Non-tautological canary: on the pre-fix tree `--name "${run_marker}"` is present (assertion 1a
## FAILS) and `--class "${run_marker}"` / `--name secure-terminal` are absent (1b/1c FAIL); drop
## the Papirus theme line and 2 FAILS; drop the .desktop install and 3 FAILS.
##
## Subjects: comparison-capture.sh + lib-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR / a
## checkout default / the install path (absent -> exit 1 FATAL, R-220: the code under test is a
## required part of the shots stack, never a silent skip). Pure static text checks -- no display,
## no capture; instant and safe anywhere.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

resolve() {  ## $1=basename -> echoes the resolved path or exits 1 FATAL
   local base="$1" cand
   for cand in \
      "${SECURE_TERMINAL_SHOTS_DIR:-}/${base}" \
      "${script_dir}/../secure-terminal-shots/${base}" \
      "${script_dir}/../../share/secure-terminal-shots/${base}" \
      "/usr/share/secure-terminal-shots/${base}"; do
      if [ -f "${cand}" ]; then
         readlink --canonicalize -- "${cand}"
         return 0
      fi
   done
   printf '%s\n' "FATAL: ${base} not found (set SECURE_TERMINAL_SHOTS_DIR)" >&2
   exit 1
}

capture_sh="$(resolve comparison-capture.sh)"
lib_sh="$(resolve lib-capture.sh)"

pass=0
fail=0
ok() {  ## $1=condition-already-evaluated(0/1 via if) label -- called from if-branches
   printf '%s\n' "PASS: $1"; pass=$(( pass + 1 ))
}
no() {
   printf '%s\n' "FAIL: $1"; fail=$(( fail + 1 ))
}

## count occurrences of a FIXED string in a file. `grep -c` prints the count (0 when none) and
## exits 1 on no match, so swallow only its EXIT status -- the "0" it already printed is the answer.
count_f() { grep -F --count -- "$2" "$1" 2>/dev/null || true; }

## 1a. The exact bug must be gone: the per-run marker is NEVER ST's WM_CLASS instance.
if [ "$(count_f "${capture_sh}" '--name "${run_marker}"')" -eq 0 ]; then
   ok 'ST launch never passes the per-run marker as --name (WM_CLASS instance)'
else
   no 'ST launch never passes the per-run marker as --name (WM_CLASS instance)'
fi

## 1b. The instance is pinned to the stable, theme-resolvable app-id -- once per ST launch site.
if [ "$(count_f "${capture_sh}" '--name secure-terminal')" -ge 1 ]; then
   ok 'ST launch pins --name to the resolvable literal secure-terminal'
else
   no 'ST launch pins --name to the resolvable literal secure-terminal'
fi

## 1c. The marker is still stamped into ST's argv (via --class) so the pgrep reaper still finds it.
if [ "$(count_f "${capture_sh}" '--class "${run_marker}"')" -ge 1 ]; then
   ok 'ST launch still carries the reaping marker in argv (via --class)'
else
   no 'ST launch still carries the reaping marker in argv (via --class)'
fi

## 1d. Every ST --name is the pinned literal: as many `--name secure-terminal` as `--name ` total.
name_total="$(count_f "${capture_sh}" '--name ')"
name_pinned="$(count_f "${capture_sh}" '--name secure-terminal')"
if [ "${name_total}" -ge 1 ] && [ "${name_total}" -eq "${name_pinned}" ]; then
   ok 'every ST --name value is the pinned secure-terminal literal'
else
   no "every ST --name value is the pinned secure-terminal literal (total=${name_total} pinned=${name_pinned})"
fi

## 2. labwc is pointed at an icon theme that carries the app icons (Papirus inherits hicolor).
if [ "$(count_f "${capture_sh}" '<icon>Papirus</icon>')" -ge 1 ]; then
   ok 'comparison-capture.sh points labwc at the Papirus icon theme'
else
   no 'comparison-capture.sh points labwc at the Papirus icon theme'
fi

## 3. secure-terminal's .desktop is installed into the session XDG_DATA_HOME (app-id -> .desktop).
if [ "$(count_f "${lib_sh}" '${data_home}/applications/secure-terminal.desktop')" -ge 1 ]; then
   ok 'lib-capture.sh installs secure-terminal.desktop into the session XDG_DATA_HOME'
else
   no 'lib-capture.sh installs secure-terminal.desktop into the session XDG_DATA_HOME'
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]

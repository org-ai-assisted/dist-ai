#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the comparison shots must carry an HONEST per-app favicon for secure-terminal --
## its own titlebar icon, not the compositor's generic fallback logo. This is the STATIC guard
## (source text only); the RENDERED counterpart (assert the captured titlebar icon really is
## secure-terminal's, not the fallback / a wrong app's) lives in the favicon rendered-capture test.
##
## Why: labwc's server-side-decoration titlebar resolves a window's icon by app-id -> a matching
## .desktop's Icon= -> the icon theme. Under NATIVE Wayland the app-id is whatever the CLIENT
## sets; secure-terminal already sets its own app-id `secure-terminal` idiomatically
## (QGuiApplication::setDesktopFileName) which resolves to the shipped secure-terminal.svg. So the
## capture must NOT sabotage that: it needs (a) to pass NO per-run temp path on any window-identity
## slot (a `--class`/`--name` carrying the mktemp reaping marker becomes the Wayland app-id / X11
## WM_CLASS and forces labwc's fallback -- the exact native-Wayland bug), (b) to carry the reaping
## marker OUT of band, via the SHOTS_RUN_MARKER env (in argv for the pgrep reaper, invisible to
## labwc), (c) to launch secure-terminal DIRECTLY (its shebang runs `python3 -Bsu`), not by
## wrapping it in a bare `python3 <script>` (drops -Bsu and is a style violation), and (d) the
## general capture-side icon chain: labwc pointed at an icon theme (Papirus, inherits hicolor) and
## secure-terminal.desktop installed into the session XDG_DATA_HOME.
##
## Asserted from the CURRENT text (no drift). Non-tautological canary: pass the marker as
## `--class "${run_marker}"` (the bug) -> 1b FAILS; as `--name "${run_marker}"` -> 1a FAILS; wrap
## the launch in `python3 "${st_bin}"` -> 3 FAILS; drop the SHOTS_RUN_MARKER env -> 2 FAILS; drop
## the Papirus theme line -> 4 FAILS; drop the .desktop install -> 5 FAILS.
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
ok() {
   printf '%s\n' "PASS: $1"; pass=$(( pass + 1 ))
}
no() {
   printf '%s\n' "FAIL: $1"; fail=$(( fail + 1 ))
}

## count occurrences of a FIXED string in a file. `grep -c` prints the count (0 when none) and
## exits 1 on no match, so swallow only its EXIT status -- the "0" it already printed is the answer.
count_f() { grep -F --count -- "$2" "$1" 2>/dev/null || true; }

## 1a. The per-run marker is NEVER ST's X11 WM_CLASS instance (--name).
if [ "$(count_f "${capture_sh}" '--name "${run_marker}"')" -eq 0 ]; then
   ok 'the per-run marker is never passed as --name (X11 WM_CLASS instance)'
else
   no 'the per-run marker is never passed as --name (X11 WM_CLASS instance)'
fi

## 1b. The per-run marker is NEVER ST's Wayland app-id (--class): setDesktopFileName(--class) would
## make the temp path the app-id and force labwc's fallback icon -- the exact native-Wayland bug.
if [ "$(count_f "${capture_sh}" '--class "${run_marker}"')" -eq 0 ]; then
   ok 'the per-run marker is never passed as --class (Wayland app-id)'
else
   no 'the per-run marker is never passed as --class (Wayland app-id) -- forces the fallback favicon'
fi

## 2. The reaping marker is carried out of band, via the SHOTS_RUN_MARKER env (in argv for the
## pgrep reaper, invisible to labwc's icon resolution).
if [ "$(count_f "${capture_sh}" 'SHOTS_RUN_MARKER=')" -ge 1 ]; then
   ok 'the reaping marker is carried via the SHOTS_RUN_MARKER env (off every window-identity slot)'
else
   no 'the reaping marker is carried via the SHOTS_RUN_MARKER env (off every window-identity slot)'
fi

## 3. secure-terminal is launched DIRECTLY (its `python3 -Bsu` shebang), never wrapped in a bare
## `python3 "${st_bin}"` (which drops -Bsu and is a style violation).
if [ "$(count_f "${capture_sh}" 'python3 "${st_bin}"')" -eq 0 ]; then
   ok 'secure-terminal is launched directly via its shebang, not wrapped in python3'
else
   no 'secure-terminal is launched directly via its shebang, not wrapped in python3'
fi

## 4. labwc is pointed at an icon theme that carries the app icons (Papirus inherits hicolor, where
## secure-terminal.svg is installed).
if [ "$(count_f "${capture_sh}" '<icon>Papirus</icon>')" -ge 1 ]; then
   ok 'comparison-capture.sh points labwc at the Papirus icon theme'
else
   no 'comparison-capture.sh points labwc at the Papirus icon theme'
fi

## 5. secure-terminal's .desktop is installed into the session XDG_DATA_HOME (app-id -> .desktop).
if [ "$(count_f "${lib_sh}" '${data_home}/applications/secure-terminal.desktop')" -ge 1 ]; then
   ok 'lib-capture.sh installs secure-terminal.desktop into the session XDG_DATA_HOME'
else
   no 'lib-capture.sh installs secure-terminal.desktop into the session XDG_DATA_HOME'
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]

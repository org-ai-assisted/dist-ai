#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Launch gnome-terminal for the hero-compare shot with secure-terminal's Hack font at 72 DPI, so
## the homepage before/after slider's two windows share a cell size and their text overlaps. Kept as
## its own file rather than an inline `sh -c` in comparison-capture.sh's launch recipe: an inline
## multi-command interpreter program is a style violation (belongs in a file), and it also avoids a
## process-replacement `exec`.
##
## Runs INSIDE the per-launch dbus-run-session: it sets the system monospace font (VTE uses it when
## the built-in profile keeps use-system-font) and Xft.dpi 72 (GTK's X11 backend reads it), then runs
## gnome-terminal --wait as a CHILD -- no exec, so its exit is forwarded and the capture's session
## tracks it. Setup is best-effort (|| true): a sandbox without the gsettings schema still captures,
## just with the default font.
##
## Usage (in the dbus session): gnome-hero-launch.sh <COLSxROWS> -- <shell> [args...]

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ "$#" -lt 1 ]; then
   printf '%s\n' 'gnome-hero-launch.sh: need <COLSxROWS> -- <shell> [args...]' >&2
   exit 2
fi
geom="$1"
shift
[ "${1:-}" = '--' ] && shift

## HiDPI: scale the hero cell size by SHOT_SCALE (default 2) so this gnome-terminal render
## overlaps secure-terminal's hero shot, which is captured at QT_FONT_DPI=72 x QT_SCALE_FACTOR.
## 72 DPI x SHOT_SCALE keeps the SAME Hack cell at 2x pixels (the shared cell the slider needs).
shot_scale="${SHOT_SCALE:-2}"
## '0*' rejects the whole leading-zero class (0/00/08/09): a leading zero is read as octal
## in the arithmetic below (00 -> DPI 0, 08/09 -> fatal abort). Fall back to 2.
case "${shot_scale}" in ''|*[!0-9]*|0*) shot_scale=2 ;; esac
hero_dpi="$(( 72 * shot_scale ))"

gsettings set org.gnome.desktop.interface monospace-font-name 'Hack 11' 2>/dev/null || true
printf '%s\n' "Xft.dpi: ${hero_dpi}" | xrdb -merge 2>/dev/null || true

gnome-terminal --wait --geometry "${geom}" -- "$@"

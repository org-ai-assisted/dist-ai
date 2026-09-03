#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Launch gnome-terminal for a comparison / hero shot ROBUSTLY. Two things a bare
## `gnome-terminal --wait` gets wrong in this capture environment:
##
## 1. LOCALE. gnome-terminal-server (VTE 0.80) hard-refuses to start under a non-UTF-8
##    locale -- it prints "Non UTF-8 locale (ANSI_X3.4-1968) is not supported!" and exits at
##    once. The capture harness (and this script's own preamble) runs under the C locale, so
##    the server never comes up: no window, no shot ("gnome-terminal window never appeared").
##    The server and client are therefore invoked with an LC_ALL=C.UTF-8 PREFIX (UTF-8 charset,
##    C behaviour) while the script itself keeps the C locale. This is the regression: older
##    gnome-terminal tolerated the C locale.
##
## 2. ACTIVATION RACE. gnome-terminal is a thin client to a D-Bus-activated
##    gnome-terminal-server whose GtkApplication startup takes ~26s here (portal cascade) --
##    past D-Bus's 25s auto-activation timeout -- so client-triggered activation loses the
##    race ("StartServiceByName ... Timeout"). Pre-start the server ourselves and WAIT for
##    its bus name before running the client. Runs INSIDE the per-launch dbus-run-session, so
##    the pre-started server shares the client's bus and is reaped with the capture's PGID.
##
## With --hero: also set the system monospace font (VTE uses it via the built-in profile's
## use-system-font) and Xft.dpi to 72 x SHOT_SCALE, matching secure-terminal's hero cell
## metrics so the homepage before/after slider's two windows share a cell size.
##
## Usage (in the dbus session): gnome-launch.sh [--hero] <COLSxROWS> -- <shell> [args...]

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## gnome-terminal-server / -client reject a non-UTF-8 locale (see the header); give just them
## a UTF-8 charset via this prefix, leaving the script's own LC_ALL=C intact.
utf8=(env LC_ALL=C.UTF-8)

hero=0
if [ "${1:-}" = '--hero' ]; then
   hero=1
   shift
fi

if [ "$#" -lt 1 ]; then
   printf '%s\n' 'gnome-launch.sh: need [--hero] <COLSxROWS> -- <shell> [args...]' >&2
   exit 2
fi
geom="$1"
shift
[ "${1:-}" = '--' ] && shift

if [ "${hero}" = 1 ]; then
   ## HiDPI: scale the hero cell size by SHOT_SCALE (default 2) so this gnome-terminal render
   ## overlaps secure-terminal's hero shot (captured at QT_FONT_DPI=72 x QT_SCALE_FACTOR).
   ## '0*' rejects the whole leading-zero class (0/00/08/09): a leading zero is read as octal
   ## in the arithmetic below (00 -> DPI 0, 08/09 -> fatal abort). Fall back to 2.
   shot_scale="${SHOT_SCALE:-2}"
   case "${shot_scale}" in ''|*[!0-9]*|0*) shot_scale=2 ;; esac
   hero_dpi="$(( 72 * shot_scale ))"
   ## Best-effort (|| true): a sandbox without the gsettings schema still captures, just with
   ## the default font.
   gsettings set org.gnome.desktop.interface monospace-font-name 'Hack 11' 2>/dev/null || true
   printf '%s\n' "Xft.dpi: ${hero_dpi}" | xrdb -merge 2>/dev/null || true
fi

## Pre-start the server and wait for its bus name (see the header). Best-effort start: a
## server already owning the name makes this spare one exit harmlessly; the WAIT is what
## matters. The 60s bound comfortably covers the ~26s portal-stalled registration while
## still failing loud (not hanging) if the server never comes up.
"${utf8[@]}" /usr/libexec/gnome-terminal-server &

registered=0
for _ in $(seq 1 60); do
   owner="$(gdbus call --session --dest org.freedesktop.DBus \
      --object-path /org/freedesktop/DBus \
      --method org.freedesktop.DBus.NameHasOwner org.gnome.Terminal 2>/dev/null || true)"
   case "${owner}" in
      *true*)
         registered=1
         break
         ;;
   esac
   sleep 1
done

if [ "${registered}" != 1 ]; then
   printf '%s\n' 'gnome-launch.sh: gnome-terminal-server did not register org.gnome.Terminal within 60s' >&2
   exit 1
fi

"${utf8[@]}" gnome-terminal --wait --geometry "${geom}" -- "$@"

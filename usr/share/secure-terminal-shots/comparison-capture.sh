#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Reproduce the secure-terminal "hostile byte streams" comparison, headless.
## For each installed Debian terminal emulator it starts an interactive shell,
## TYPES a command into it (so the shot shows the prompt, the command, its output
## and the state of the prompt AFTER it -- what a user actually sees, and how to
## reproduce it), and screenshots the DECORATED window (title bar included):
##   Case A (random) : head -c 1200 /dev/random   -- genuine random data, sized so
##                     the returned prompt stays visible below the garble.
##   Case B (crafted): cat crafted.log            -- an OSC-0 title hijack plus a
##                     stuck colour and a DEC line-drawing charset shift, none reset
##                     (generated deterministically by hostile-script.sh, so the
##                     shots use the exact bytes that script emits).
##   Case C (homoglyph): cat homoglyph.txt          -- an install one-liner whose
##                     domain carries a Cyrillic look-alike (U+0430 for Latin a), so
##                     a traditional terminal shows a clean "example.com". secure-
##                     terminal is shot in TWO modes: box (look-alike -> a coloured
##                     box) and detail (<U+0430 CYRILLIC SMALL LETTER A>).
## secure-terminal (its real GUI, from ST_REPO) is captured the same way. Output
## PNGs go to ./shots/ (copy them to the site's comparison/shots/). Usually driven
## via 'secure-terminal-shots comparison'; see this dir's README.md. The sibling
## generator here, paste-warning-shot.py, does the headless review-bar shots.
##
## The prompt is a fixed "user@host:~$" -- deliberately CONTRASTING with the
## root@prod-db the OSC-0 escape forces into the title bar: the prompt shows who
## you really are, the hijacked title lies.
##
## Decorations come from labwc -- the wlroots compositor LXQt ships -- running
## nested on the host X server (WLR x11 backend) with the Clearlooks Openbox
## theme. labwc draws the SAME real, themed server-side title bar on EVERY window
## it manages, X11 (Xwayland) and toolkit alike, exactly as on a real LXQt
## desktop -- so an OSC-0 title hijack shows up in that bar as it would for a
## user. Each shot is cropped to the emulator's window by its real geometry grown
## by the WM's title bar (labwc's _NET_FRAME_EXTENTS). Nothing is painted on.
##
## Needs: an X server on $DISPLAY, labwc (+ its Xwayland), the Clearlooks Openbox
## theme, x11-xserver-utils (setxkbmap), xdotool, xprop, ImageMagick. Installs
## NOTHING itself (supply-chain hygiene).
##
## Usage (normally via the wrapper: 'secure-terminal-shots comparison'):
##   ST_REPO=/path/to/secure-terminal/checkout ./comparison-capture.sh
## Deterministic Case B; Case A is random by nature (that is the point).
##
## NOTE: on a hardened Kicksecure/Whonix system the permission-hardener strips the
## exec bit from urxvt; restore it first: sudo chmod a+x /usr/bin/urxvt

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

here="$(dirname -- "$(readlink --canonicalize -- "$0")")"
out="${here}/shots"
mkdir --parents -- "${out}"

host_display="${DISPLAY:-:0}"
THEME='Clearlooks'
RANDOM_BYTES=1200
## Case A reads /dev/random (not /dev/urandom): on a modern kernel the two are
## equivalent once the pool is seeded, and Kicksecure prefers /dev/random. See
## https://www.kicksecure.com/wiki/Dev/Entropy#/dev/random_vs._/dev/urandom
RANDOM_SOURCE='/dev/random'
## Clearlooks title bar + border height (fallback if _NET_FRAME_EXTENTS is unread).
FRAME_TOP=26

runtime_dir="$(mktemp --directory)"
export XDG_RUNTIME_DIR="${runtime_dir}"
export HOME="${runtime_dir}/home"
export XDG_CONFIG_HOME="${runtime_dir}/config"
mkdir --parents -- "${HOME}" "${XDG_CONFIG_HOME}/labwc"

## Generate the two payloads from their deterministic ASCII source scripts (so
## this subsystem is self-contained and its source stays ASCII -- the non-ASCII
## homoglyph byte exists only in the generated file).
"${here}/hostile-script.sh"   > "${HOME}/crafted.log"
"${here}/homoglyph-script.sh" > "${HOME}/homoglyph.txt"
cat > "${HOME}/.strc" <<'RC'
PS1='user@host:~$ '
RC

## Install secure-terminal's icon into the session icon theme, so labwc -- which
## resolves a window's title-bar icon by its app-id (WM_CLASS) through the icon
## theme, NOT via _NET_WM_ICON -- shows the real logo in secure-terminal's title
## bar, exactly as on a system where the package (and its icon) is installed.
export XDG_DATA_HOME="${runtime_dir}/data"
st_icon="${ST_REPO:-}/usr/share/icons/hicolor/scalable/apps/secure-terminal.svg"
if [ -n "${ST_REPO:-}" ] && [ -f "${st_icon}" ]; then
   th="${XDG_DATA_HOME}/icons/hicolor"
   mkdir --parents -- "${th}/scalable/apps"
   cp -- "${st_icon}" "${th}/scalable/apps/secure-terminal.svg"
   for sz in 16 22 24 32 48 64 128 256; do
      mkdir --parents -- "${th}/${sz}x${sz}/apps"
      convert -background none -resize "${sz}x${sz}" "${st_icon}" \
         "${th}/${sz}x${sz}/apps/secure-terminal.png" 2>/dev/null || true
   done
   gtk-update-icon-cache -f "${th}" 2>/dev/null || true
fi

## labwc config: the Clearlooks theme, server-side decorations.
cat > "${XDG_CONFIG_HOME}/labwc/rc.xml" <<XML
<?xml version="1.0"?>
<labwc_config>
  <theme><name>${THEME}</name></theme>
  <core><decoration>server</decoration></core>
  <placement><policy>automatic</policy></placement>
</labwc_config>
XML

## launch each emulator FROM ${HOME} so a plain "cat crafted.log" finds it.
cd "${HOME}"

cmd_for() {  ## $1=case
   case "$1" in
      crafted)
         printf 'cat crafted.log'
         ;;
      random)
         printf 'head -c %s %s' "${RANDOM_BYTES}" "${RANDOM_SOURCE}"
         ;;
      homoglyph)
         printf 'cat homoglyph.txt'
         ;;
   esac
}

wm_pid=''
labwc_wid=''
xwl_display=''
base_wids=''
cleanup() {
   [ -z "${wm_pid}" ] || kill "${wm_pid}" 2>/dev/null || true
   [ -z "${wm_pid}" ] || wait "${wm_pid}" 2>/dev/null || true
   safe-rm -r -f -- "${runtime_dir}" 2>/dev/null || true
}
trap cleanup EXIT

## start labwc nested on the host X server; discover its Xwayland display and its
## host window (the compositor output we screenshot).
start_labwc() {
   local before_sock before_win after_win _ s w f
   before_sock=' '
   for f in /tmp/.X11-unix/X*; do
      [ -e "${f}" ] || continue        # no match -> the literal glob; skip it
      before_sock+="${f##*/} "
   done
   before_win=" $(DISPLAY="${host_display}" xdotool search --onlyvisible '' 2>/dev/null | tr '\n' ' ')"
   WLR_BACKENDS=x11 WLR_X11_OUTPUTS=1 DISPLAY="${host_display}" \
      labwc >"${runtime_dir}/labwc.log" 2>&1 &
   wm_pid="$!"
   labwc_wid=''; xwl_display=''
   for _ in $(seq 1 60); do
      kill -0 "${wm_pid}" 2>/dev/null || return 1
      if [ -z "${xwl_display}" ]; then
         for f in /tmp/.X11-unix/X*; do
            [ -e "${f}" ] || continue
            s="${f##*/}"
            case "${before_sock}" in *" ${s} "*) : ;; *) xwl_display=":${s#X}" ;; esac
         done
      fi
      if [ -z "${labwc_wid}" ]; then
         after_win=" $(DISPLAY="${host_display}" xdotool search --onlyvisible '' 2>/dev/null | tr '\n' ' ')"
         for w in ${after_win}; do
            case "${before_win}" in *" ${w} "*) : ;; *) labwc_wid="${w}" ;; esac
         done
      fi
      if [ -n "${xwl_display}" ] && [ -n "${labwc_wid}" ]; then
         sleep 1
         ## give labwc a roomier output than the 1024x768 default.
         DISPLAY="${host_display}" xdotool windowsize "${labwc_wid}" 1440 900 2>/dev/null || true
         sleep 1
         base_wids=" $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null | tr '\n' ' ')"
         return 0
      fi
      sleep 0.5
   done
   return 1
}

## launch an emulator as an Xwayland (X11) client so labwc decorates it.
launch() {  ## $1=emulator
   local e="$1"
   local base=(env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}")
   local sh=(bash --rcfile "${HOME}/.strc" -i)
   case "$e" in
      xterm)
         "${base[@]}" xterm -geometry 84x24 -fa 'Monospace' -fs 11 -e "${sh[@]}"
         ;;
      urxvt)
         "${base[@]}" urxvt -geometry 84x24 -fn 'xft:Monospace:size=11' -e "${sh[@]}"
         ;;
      st)
         "${base[@]}" st -g 84x24 -f 'Monospace:size=11' -e "${sh[@]}"
         ;;
      konsole)
         "${base[@]}" QT_QPA_PLATFORM=xcb konsole --nofork -e "${sh[@]}"
         ;;
      qterminal)
         "${base[@]}" QT_QPA_PLATFORM=xcb qterminal -e "${sh[@]}"
         ;;
      xfce4-terminal)
         "${base[@]}" GDK_BACKEND=x11 xfce4-terminal --disable-server --geometry 84x24 -x "${sh[@]}"
         ;;
      mate-terminal)
         "${base[@]}" GDK_BACKEND=x11 mate-terminal --disable-factory --geometry 84x24 -x "${sh[@]}"
         ;;
      alacritty)
         "${base[@]}" WINIT_UNIX_BACKEND=x11 alacritty -o 'window.dimensions.columns=84' -o 'window.dimensions.lines=24' -o 'font.size=11' -e "${sh[@]}"
         ;;
      kitty)
         "${base[@]}" KITTY_ENABLE_WAYLAND=0 kitty -o 'remember_window_size=no' -o 'initial_window_width=720' -o 'initial_window_height=430' -o 'font_size=11' "${sh[@]}"
         ;;
   esac
}

## type a command into the focused terminal window and run it, as if a user did.
inject() {  ## $1=window-id  $2=command
   local wid="$1" cmd="$2"
   DISPLAY="${xwl_display}" xdotool windowactivate --sync "${wid}" 2>/dev/null || true
   DISPLAY="${xwl_display}" setxkbmap us 2>/dev/null || true    # '/' else types as '&'
   sleep 0.4
   DISPLAY="${xwl_display}" xdotool type --delay 45 -- "${cmd}"
   sleep 0.3
   DISPLAY="${xwl_display}" xdotool key --clearmodifiers Return
}

## screenshot labwc's output, crop to the emulator's window by its geometry grown
## by the themed frame (labwc's _NET_FRAME_EXTENTS, fallback FRAME_TOP).
capture_window() {  ## $1=output-path  $2=xwayland-window-id
   local dest="$1" wid="$2" tmp X='' Y='' WIDTH='' HEIGHT='' ext l r t b
   DISPLAY="${host_display}" xdotool mousemove 1439 899 2>/dev/null || true
   sleep 0.3
   tmp="$(mktemp --suffix=.png)"
   if ! import -display "${host_display}" -window "${labwc_wid}" "${tmp}" 2>/dev/null; then
      safe-rm -f -- "${tmp}"
      return 1
   fi
   eval "$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${wid}" 2>/dev/null \
      | grep -E '^(X|Y|WIDTH|HEIGHT)=' || true)"
   ext="$(DISPLAY="${xwl_display}" xprop -id "${wid}" _NET_FRAME_EXTENTS 2>/dev/null | grep -oE '= .*' || true)"
   ext="${ext#= }"; ext="${ext//,/}"
   read -r l r t b <<< "${ext}"
   [ -n "${b:-}" ] || { l=1; r=1; t="${FRAME_TOP}"; b=1; }
   if [ -n "${X}" ] && [ -n "${WIDTH}" ] && [ "${WIDTH}" -gt 0 ]; then
      local cx cy cw ch
      cx=$(( X - l )); [ "${cx}" -lt 0 ] && cx=0
      cy=$(( Y - t )); [ "${cy}" -lt 0 ] && cy=0
      cw=$(( WIDTH + l + r )); ch=$(( HEIGHT + t + b ))
      convert "${tmp}" -crop "${cw}x${ch}+${cx}+${cy}" +repage "${dest}" \
         2>/dev/null || cp -- "${tmp}" "${dest}"
   else
      cp -- "${tmp}" "${dest}"
   fi
   safe-rm -f -- "${tmp}"
}

clear_windows() {
   local wid
   for wid in $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null || true); do
      case "${base_wids}" in *" ${wid} "*) continue ;; esac
      DISPLAY="${xwl_display}" xdotool windowkill "${wid}" 2>/dev/null || true
   done
}

## the largest NEW (non-baseline) window: the emulator's real top-level.
find_window() {
   local _ cur wid best X Y WIDTH HEIGHT area
   for _ in $(seq 1 80); do
      kill -0 "${wm_pid}" 2>/dev/null || return 1
      wid=''; best=0
      for cur in $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null || true); do
         case "${base_wids}" in *" ${cur} "*) continue ;; esac
         X=''; Y=''; WIDTH=''; HEIGHT=''
         eval "$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${cur}" 2>/dev/null | grep -E '^(WIDTH|HEIGHT)=' || true)"
         area=$(( ${WIDTH:-0} * ${HEIGHT:-0} ))
         if [ "${area}" -gt "${best}" ]; then best="${area}"; wid="${cur}"; fi
      done
      if [ -n "${wid}" ] && [ "${best}" -gt 40000 ]; then
         printf '%s' "${wid}"
         return 0
      fi
      sleep 0.25
   done
   return 1
}

shoot() {  ## $1=emulator  $2=case
   local e="$1" case="$2" wid='' ww
   launch "$e" >/dev/null 2>&1 &
   local epid="$!"
   wid="$(find_window || true)"
   if [ -z "${wid}" ]; then
      printf 'warn %s.%s: window never appeared, no shot\n' "${e}" "${case}"
      clear_windows; kill "${epid}" 2>/dev/null || true; sleep 1
      return 1
   fi
   ## qterminal opens maximized and ignores a plain resize; unmaximize it first.
   if [ "$e" = qterminal ]; then
      DISPLAY="${xwl_display}" wmctrl -i -r "${wid}" -b remove,maximized_vert,maximized_horz 2>/dev/null || true
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 720 440 2>/dev/null || true
      sleep 0.7
   fi
   sleep 2
   inject "${wid}" "$(cmd_for "${case}")"
   sleep 3
   ww="$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${wid}" 2>/dev/null | sed -n 's/^WIDTH=//p' || true)"
   if [ -n "${ww}" ] && [ "${ww}" -lt 300 ]; then
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 720 430 2>/dev/null || true
      sleep 1.5
   fi
   capture_window "${out}/${e}.${case}.png" "${wid}" \
      || printf 'warn %s.%s: screenshot failed\n' "${e}" "${case}"
   clear_windows
   kill "${epid}" 2>/dev/null || true
   sleep 1
}

if ! start_labwc; then
   printf 'labwc did not start; log:\n'; tail -6 "${runtime_dir}/labwc.log"; exit 1
fi

## lxterminal is omitted: its single-instance startup maps no window headless.
## TERMINALS can be overridden to trial a subset (e.g. TERMINALS='xterm st').
## A MISSING terminal is a HARD ERROR, not a silent skip -- an incomplete grid
## would misrepresent the comparison. Install the emulator, or set ALLOW_SKIP=1 to
## deliberately authorize skipping (it is then logged, never silent).
TERMINALS="${TERMINALS:-xterm urxvt st konsole xfce4-terminal mate-terminal qterminal alacritty kitty}"
for e in ${TERMINALS}; do
   if ! type -P "$e" >/dev/null 2>&1; then
      if [ -n "${ALLOW_SKIP:-}" ]; then
         printf 'SKIP %s (not installed; ALLOW_SKIP authorized)\n' "$e" >&2
         continue
      fi
      printf 'ERROR: terminal %s is not installed. Install it, or set ALLOW_SKIP=1 to authorize skipping.\n' "$e" >&2
      exit 1
   fi
   shoot "$e" crafted   || true
   shoot "$e" random    || true
   shoot "$e" homoglyph || true
   printf 'captured %s\n' "$e"
done

st_bin="${ST_REPO:-}/usr/bin/secure-terminal"
st_pkg="${ST_REPO:-}/usr/lib/python3/dist-packages"
if [ -n "${ST_REPO:-}" ] && [ -f "${st_bin}" ]; then
   ## Each entry is "<case> <mode> <output-suffix>". secure-terminal is captured in
   ## the display mode that matters for each case: box for the byte-stream cases,
   ## and BOTH box and detail for the homoglyph -- box flags the look-alike byte as
   ## a coloured box, detail names its exact codepoint (<U+0430 CYRILLIC SMALL
   ## LETTER A>). The homoglyph-strip suffix is kept for the committed PNG /
   ## Pages reference (the mode it captures is now box; the file name is a label).
   st_specs=(
      'crafted box crafted'
      'random box random'
      'homoglyph box homoglyph-strip'
      'homoglyph detail homoglyph-detail'
   )
   for spec in "${st_specs[@]}"; do
      read -r st_case st_mode st_suffix <<< "${spec}"
      env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}" QT_QPA_PLATFORM=xcb \
         PYTHONPATH="${st_pkg}" python3 "${st_bin}" --new-instance --mode "${st_mode}" \
         -- bash --rcfile "${HOME}/.strc" -i >/dev/null 2>&1 &
      epid="$!"
      stwid="$(find_window || true)"
      if [ -n "${stwid}" ]; then
         sleep 2
         inject "${stwid}" "$(cmd_for "${st_case}")"
         sleep 3
         capture_window "${out}/secure-terminal.${st_suffix}.png" "${stwid}"
      else
         printf 'warn secure-terminal.%s: window never appeared\n' "${st_suffix}"
      fi
      clear_windows
      kill "${epid}" 2>/dev/null || true
      sleep 1.5
   done
   printf 'captured secure-terminal (real GUI)\n'
elif [ -n "${ALLOW_SKIP:-}" ]; then
   printf 'SKIP secure-terminal (ST_REPO not set/found; ALLOW_SKIP authorized)\n' >&2
else
   printf 'ERROR: secure-terminal not found. Set ST_REPO=/path/to/checkout, or set ALLOW_SKIP=1 to authorize skipping.\n' >&2
   exit 1
fi

printf 'done; shots in %s\n' "${out}"

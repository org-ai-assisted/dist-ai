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
##   Case B (crafted): cat crafted.payload       -- an OSC-0 title hijack plus a
##                     stuck colour and a DEC line-drawing charset shift, none reset
##                     (the terminal-poc-corpus crafted-hostile-log PoC, decoded by
##                     its reproduce.py -- the single source of truth for the bytes).
##   Case C (homoglyph): cat homoglyph.payload      -- a domain carrying a Cyrillic
##                     look-alike (U+0430 for Latin a), so
##                     a traditional terminal shows a clean "example.com". secure-
##                     terminal is shot in TWO modes: box (look-alike -> a coloured
##                     box) and detail (<U+0430 CYRILLIC SMALL LETTER A>).
##   Case D (tui-showcase): cat tui-showcase.payload -- a safe display-only board that
##                     exercises EVERY text-attack class at once (homoglyph, bidi,
##                     zero-width, BOM, combining, fullwidth, DEC charset, SGR, OSC 8,
##                     OSC 0 title, alt-screen); secure-terminal box + detail.
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

## style-ok: no-tmp-hardcode -- /tmp/.X11-unix is the X11 socket directory fixed by
## the protocol; libX11 looks there and nowhere else, so it cannot follow TMPDIR.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

here="$(dirname -- "$(readlink --canonicalize -- "$0")")"
out="${here}/shots"
mkdir --parents -- "${out}"

## the shared hostile-DATA contract (payload command + log generation).
# shellcheck source=./lib-capture.sh
source "${here}/lib-capture.sh"

## Resolve the corpus NOW, while HOME is still the operator's -- the reassignment
## below would otherwise hide the documented ~/private-sources default from the
## resolver. Export it so shots_generate_logs (run after the reassign) reuses it.
CORPUS_REPO="$(shots_resolve_corpus "${here}/../../../../terminal-poc-corpus" || true)"
export CORPUS_REPO

host_display="${DISPLAY:-:0}"
THEME='Clearlooks'
## Clearlooks title bar + border height (fallback if _NET_FRAME_EXTENTS is unread).
FRAME_TOP=26

runtime_dir="$(mktemp --directory)"
export XDG_RUNTIME_DIR="${runtime_dir}"
export HOME="${runtime_dir}/home"
export XDG_CONFIG_HOME="${runtime_dir}/config"
mkdir --parents -- "${HOME}" "${XDG_CONFIG_HOME}/labwc"

## Attack payloads come from the terminal-poc-corpus (single source of truth), decoded
## by its reproduce.py. shots_generate_logs resolves the checkout and returns 77
## (a SKIP, like a missing ST_REPO) ONLY when the corpus is absent; a real
## payload-generation failure returns a distinct non-77 code, which is propagated
## here so a broken reproduce.py is not reported as a skip.
shots_generate_logs "${here}" "${HOME}" || exit "$?"
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

## launch each emulator FROM ${HOME} so a plain "cat crafted.payload" finds it.
cd "${HOME}"

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
launch() {  ## $1=emulator  $2=case
   local e case base sh rows kh
   e="$1"; case="$2"
   base=(env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}")
   sh=(bash --rcfile "${HOME}/.strc" -i)
   ## The tui-showcase board paints ~26 lines on the alternate screen; at the 24 rows
   ## the short cases use, its title bar scrolled off the top. Only that case gets the
   ## taller window, so the other cases' shots (and their committed on-page dimensions)
   ## are unchanged. kitty is sized in pixels, so it gets a matching taller height.
   rows=24; kh=430
   if [ "${case}" = tui-showcase ]; then rows=32; kh=620; fi
   case "${e}" in
      xterm)
         "${base[@]}" xterm -geometry "84x${rows}" -fa 'Monospace' -fs 11 -e "${sh[@]}"
         ;;
      urxvt)
         "${base[@]}" urxvt -geometry "84x${rows}" -fn 'xft:Monospace:size=11' -e "${sh[@]}"
         ;;
      st)
         "${base[@]}" st -g "84x${rows}" -f 'Monospace:size=11' -e "${sh[@]}"
         ;;
      konsole)
         "${base[@]}" QT_QPA_PLATFORM=xcb konsole --nofork -p TerminalColumns=84 -p "TerminalRows=${rows}" -e "${sh[@]}"
         ;;
      qterminal)
         "${base[@]}" QT_QPA_PLATFORM=xcb qterminal -e "${sh[@]}"
         ;;
      xfce4-terminal)
         "${base[@]}" GDK_BACKEND=x11 xfce4-terminal --disable-server --geometry "84x${rows}" -x "${sh[@]}"
         ;;
      gnome-terminal)
         ## gnome-terminal is a thin client to gnome-terminal-server over D-Bus
         ## (--disable-factory was removed in 3.14+): give each launch a PRIVATE
         ## session bus so its server starts fresh and dies with the bus, and
         ## --wait so this backgrounded launcher blocks until the window closes
         ## (clear_windows/windowkill then unblocks it). VTE reads its profile
         ## from dconf; with no dconf daemon on the private bus it falls back to
         ## the built-in default profile -- the shipped default we want to show.
         "${base[@]}" GDK_BACKEND=x11 dbus-run-session -- \
            gnome-terminal --wait --geometry "84x${rows}" -- "${sh[@]}"
         ;;
      mate-terminal)
         "${base[@]}" GDK_BACKEND=x11 mate-terminal --disable-factory --geometry "84x${rows}" -x "${sh[@]}"
         ;;
      alacritty)
         "${base[@]}" WINIT_UNIX_BACKEND=x11 alacritty -o 'window.dimensions.columns=84' -o "window.dimensions.lines=${rows}" -o 'font.size=11' -e "${sh[@]}"
         ;;
      kitty)
         "${base[@]}" KITTY_ENABLE_WAYLAND=0 kitty -o 'remember_window_size=no' -o 'initial_window_width=720' -o "initial_window_height=${kh}" -o 'font_size=11' "${sh[@]}"
         ;;
   esac
}

## type a command into the focused terminal window and run it, as if a user did.
inject() {  ## $1=window-id  $2=command
   local wid cmd
   wid="$1"; cmd="$2"
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
   local dest wid tmp X Y WIDTH HEIGHT ext l r t b
   dest="$1"; wid="$2"; X=''; Y=''; WIDTH=''; HEIGHT=''
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

## Remove the largest contiguous run of empty (background) terminal rows from a shot,
## so a few lines of content no longer sit above a screenful of dead space. The
## payloads are short, and the ST GUI will not shrink its window below ~400px (a Qt
## minimum-size floor), so the tail of every short case is empty terminal rows. Handles
## both content-at-the-top (traditional emulators: void at the bottom) and a fixed
## bottom banner/status bar with a void above it (secure-terminal: void in the middle).
## Only PURE background rows are removed, so content is never touched; a screen-filling
## case (random) has no large run and is left untouched. Side columns are excluded when
## classifying a row so a full-height scrollbar cannot mask the void.
tighten_deadspace() {  ## $1=png-path
   local f w h side mw bg tmpmap best_start best_len run_start run_len y line
   local best_end top_h bot_y bot_h margin threshold
   margin=10
   threshold=40
   f="$1"
   [ -f "${f}" ] || return 0
   w="$(identify -format '%w' "${f}")"; h="$(identify -format '%h' "${f}")"
   side=40; [ "${w}" -gt 200 ] || side=0
   mw=$(( w - 2 * side ))
   ## background = most-frequent colour of the lower half (skips the light top chrome;
   ## background dominates even a screen of garble). grep -m1 closes the pipe after the
   ## top colour; '|| true' keeps the upstream SIGPIPE from tripping errexit+pipefail.
   bg="$(convert "${f}" -gravity South -crop "${w}x50%+0+0" +repage \
           -depth 8 -format '%c' histogram:info:- \
         | sort -rn | grep -m1 -oiE '#[0-9A-F]{6}')" || true
   [ -n "${bg}" ] || bg="$(convert "${f}" -format "#%[hex:p{2,$(( h - 4 ))}]" info: | cut -c1-7)"
   ## per-row emptiness map: drop the side columns, take the absolute difference from a
   ## solid-background image (robust to any bg colour, incl. pure black/white) and
   ## threshold it (background -> black, content -> white), then the per-row maximum so
   ## any content pixel lights the whole row. Column 0 read out: an empty row is #000000.
   ## The statistic neighbourhood is CENTRED, so a width of mw would leave column 0's max
   ## covering only the left half and miss content near the right edge; 2*mw makes column
   ## 0 span the full row. Erring wide is safe -- it can only classify a row as non-empty,
   ## never delete real content.
   tmpmap="$(mktemp)"
   convert "${f}" -crop "${mw}x${h}+${side}+0" +repage \
      \( +clone -fill "${bg}" -colorize 100 \) \
      -compose difference -composite -threshold 6% \
      -statistic maximum "$(( 2 * mw ))x1" -crop "1x${h}+0+0" +repage txt:- \
      | tail -n +2 > "${tmpmap}"
   best_start=-1; best_len=0; run_start=-1; run_len=0; y=0
   while IFS= read -r line; do
      case "${line}" in
         *"#000000"*)
            [ "${run_start}" -ge 0 ] || run_start="${y}"
            run_len=$(( run_len + 1 ))
            if [ "${run_len}" -gt "${best_len}" ]; then best_len="${run_len}"; best_start="${run_start}"; fi
            ;;
         *)
            run_start=-1; run_len=0
            ;;
      esac
      y=$(( y + 1 ))
   done < "${tmpmap}"
   safe-rm -f -- "${tmpmap}"
   [ "${best_start}" -ge 0 ] && [ "${best_len}" -ge "${threshold}" ] || return 0
   best_end=$(( best_start + best_len - 1 ))
   top_h=$(( best_start + margin ))
   bot_y=$(( best_end - margin )); [ "${bot_y}" -lt "${top_h}" ] && bot_y="${top_h}"
   bot_h=$(( h - bot_y ))
   convert "${f}" \
      \( -clone 0 -crop "${w}x${top_h}+0+0" +repage \) \
      \( -clone 0 -crop "${w}x${bot_h}+0+${bot_y}" +repage \) \
      -delete 0 -append "${f}"
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
   local e case wid ww rescue_h
   e="$1"; case="$2"; wid=''
   ## the tall tui-showcase board needs a taller pixel-resized window (qterminal +
   ## the shrink rescue); the short cases keep their prior heights so their shots and
   ## committed page dimensions do not move.
   rescue_h=430; [ "${case}" = tui-showcase ] && rescue_h=620
   launch "${e}" "${case}" >/dev/null 2>&1 &
   local epid
   epid="$!"
   wid="$(find_window || true)"
   if [ -z "${wid}" ]; then
      printf '%s\n' "warn ${e}.${case}: window never appeared, no shot"
      clear_windows; kill "${epid}" 2>/dev/null || true; sleep 1
      return 1
   fi
   ## qterminal opens maximized and ignores a plain resize; unmaximize it first.
   if [ "${e}" = qterminal ]; then
      DISPLAY="${xwl_display}" wmctrl -i -r "${wid}" -b remove,maximized_vert,maximized_horz 2>/dev/null || true
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 720 "${rescue_h}" 2>/dev/null || true
      sleep 0.7
   fi
   sleep 2
   inject "${wid}" "$(shots_payload_cmd "${case}")"
   sleep 3
   ww="$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${wid}" 2>/dev/null | sed -n 's/^WIDTH=//p' || true)"
   if [ -n "${ww}" ] && [ "${ww}" -lt 300 ]; then
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 720 "${rescue_h}" 2>/dev/null || true
      sleep 1.5
   fi
   capture_window "${out}/${e}.${case}.png" "${wid}" \
      && tighten_deadspace "${out}/${e}.${case}.png" \
      || printf '%s\n' "warn ${e}.${case}: screenshot failed"
   clear_windows
   kill "${epid}" 2>/dev/null || true
   sleep 1
}

if ! start_labwc; then
   printf '%s\n' 'labwc did not start; log:'; tail -6 "${runtime_dir}/labwc.log"; exit 1
fi

## lxterminal is omitted: its single-instance startup maps no window headless.
## TERMINALS can be overridden to trial a subset (e.g. TERMINALS='xterm st').
## A MISSING terminal is a HARD ERROR, not a silent skip -- an incomplete grid
## would misrepresent the comparison. Install the emulator, or set ALLOW_SKIP=1 to
## deliberately authorize skipping (it is then logged, never silent).
TERMINALS="${TERMINALS:-xterm urxvt st konsole gnome-terminal xfce4-terminal mate-terminal qterminal alacritty kitty}"
for e in ${TERMINALS}; do
   if ! type -P "${e}" >/dev/null 2>&1; then
      if [ -n "${ALLOW_SKIP:-}" ]; then
         printf '%s\n' "SKIP ${e} (not installed; ALLOW_SKIP authorized)" >&2
         continue
      fi
      printf '%s\n' "ERROR: terminal ${e} is not installed. Install it, or set ALLOW_SKIP=1 to authorize skipping." >&2
      exit 1
   fi
   shoot "${e}" crafted      || true
   shoot "${e}" random       || true
   shoot "${e}" homoglyph    || true
   shoot "${e}" bidi         || true
   shoot "${e}" zerowidth    || true
   shoot "${e}" altscreen    || true
   shoot "${e}" tui-showcase || true
   printf '%s\n' "captured ${e}"
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
   ## Capture size for the ST GUI window. At the app's 820px default Qt collapses the
   ## trailing toolbar controls (unicode / mode / colours / Zoom) behind a ">>" overflow
   ## chevron, which reads as a truncated capture. 1360 is the empirically-verified width
   ## that shows the whole toolbar under the real xcb render (its font metrics run wider
   ## than an offscreen sizeHint predicts); it fits the 1440x900 labwc output.
   st_win_w=1360
   ## Each entry is "<case> <mode> <suffix> [tui]". The optional 4th field 'tui' launches
   ## secure-terminal with --tui (opt-in full-screen mode) instead of the default CLI mode.
   ## The tui-showcase board is captured across the CLI/TUI mode x box/show/detail
   ## unicode matrix so the page's view switcher has a real shot per combo. Show renders
   ## printable unicode as its glyph (readable) while still boxing invisible/bidi/control
   ## bytes; detail names each codepoint inline. Even in full-screen TUI every cell stays
   ## character-filtered.
   st_specs=(
      'crafted box crafted'
      'random box random'
      'homoglyph box homoglyph-strip'
      'homoglyph detail homoglyph-detail'
      'bidi box bidi'
      'zerowidth box zerowidth'
      'altscreen box altscreen'
      'tui-showcase box tui-showcase'
      'tui-showcase show tui-showcase-show'
      'tui-showcase detail tui-showcase-detail'
      'tui-showcase box tui-showcase-tui tui'
      'tui-showcase show tui-showcase-tui-show tui'
   )
   for spec in "${st_specs[@]}"; do
      read -r st_case st_mode st_suffix st_tui <<< "${spec}"
      st_mode_flags=(--mode "${st_mode}")
      [ "${st_tui:-}" = tui ] && st_mode_flags+=(--tui)
      ## tui-showcase: secure-terminal strips the alt-screen escape and renders the
      ## banner + ~26 board rows INLINE (no alt buffer), so a short window would show
      ## only the footer -- give it a taller window (820 fits the 900px labwc output
      ## once grown by the frame). The short cases keep 620 so their committed page
      ## dimensions do not move; tighten_deadspace trims either back to its content.
      st_win_h=620; [ "${st_case}" = tui-showcase ] && st_win_h=820
      env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}" QT_QPA_PLATFORM=xcb \
         PYTHONPATH="${st_pkg}" python3 "${st_bin}" --new-instance "${st_mode_flags[@]}" \
         -- bash --rcfile "${HOME}/.strc" -i >/dev/null 2>&1 &
      epid="$!"
      stwid="$(find_window || true)"
      if [ -n "${stwid}" ]; then
         sleep 2
         ## Widen the window so the whole toolbar fits (no ">>" overflow chevron),
         ## then let the layout settle before injecting + grabbing.
         DISPLAY="${xwl_display}" xdotool windowsize "${stwid}" "${st_win_w}" "${st_win_h}" 2>/dev/null || true
         sleep 0.6
         inject "${stwid}" "$(shots_payload_cmd "${st_case}")"
         sleep 3
         capture_window "${out}/secure-terminal.${st_suffix}.png" "${stwid}"
         tighten_deadspace "${out}/secure-terminal.${st_suffix}.png"
      else
         printf '%s\n' "warn secure-terminal.${st_suffix}: window never appeared"
      fi
      clear_windows
      kill "${epid}" 2>/dev/null || true
      sleep 1.5
   done
   printf '%s\n' 'captured secure-terminal (real GUI)'
elif [ -n "${ALLOW_SKIP:-}" ]; then
   printf '%s\n' 'SKIP secure-terminal (ST_REPO not set/found; ALLOW_SKIP authorized)' >&2
else
   printf '%s\n' 'ERROR: secure-terminal not found. Set ST_REPO=/path/to/checkout, or set ALLOW_SKIP=1 to authorize skipping.' >&2
   exit 1
fi

## Convert the captured PNGs to webp (the site references them as .webp).
shots_optimize_to_webp "${out}"/*.png

printf '%s\n' "done; shots in ${out}"

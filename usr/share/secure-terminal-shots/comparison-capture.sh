#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Reproduce the secure-terminal "hostile byte streams" comparison, headless.
## For each installed Debian terminal emulator it starts an interactive shell,
## TYPES a command into it (so the shot shows the prompt, the command, its output
## and the state of the prompt AFTER it -- what a user actually sees, and how to
## reproduce it), and screenshots the DECORATED window (title bar included):
##   Case A (random) : cat random.payload         -- a FIXED pseudo-random garble field
##                     (deterministic, seeded; see lib-capture.sh), sized so the returned
##                     prompt stays visible below the garble.
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
##
## REAPING (do not chase the wrong cause again): every terminal + the secure-terminal GUI is
## started in its OWN session (shots_spawn_session -> setsid) and reaped by the recorded PGID
## (kill -- -PGID) with a per-capture deadline; leaked orphans are swept by the run's unique
## MARKER via safe-pgrep/safe-pkill. This exists because the GUI runs as `python3
## .../secure-terminal` (process name `python3`), so a name kill never reaped it and there was
## no timeout, so GUIs piled up. Reaping model + cleanup command: lib-capture.sh.
##   MISDIAGNOSIS to NOT re-open: "TERMINALS='' makes secure-terminal capture first" is FALSE.
##   The loop below reads ${TERMINALS:-<full list>}, so an EMPTY TERMINALS coerces to the full
##   emulator list; the secure-terminal block always runs AFTER the loop, never before it.

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

## Fail BEFORE the expensive capture if the bundled webp optimizer is missing -- a direct
## run (not via the secure-terminal-shots wrapper) resolves it checkout-relative, not by PATH.
shots_require_image_optimize || exit 1

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

## The run's unique reaping MARKER: the mktemp runtime dir, which every spawned terminal / GUI
## carries in its argv (via `--rcfile ${HOME}/.strc` and the recorded pgid file), so a crashed
## run's orphans can be swept by exactly this string and nothing else.
run_marker="${runtime_dir}"
## Per-capture deadline (seconds): a render that hangs longer than this has its process group
## reaped and the loop continues, so a wedged terminal cannot stall the whole grid.
SHOT_DEADLINE="${SHOT_DEADLINE:-90}"

## Optional scope filters (a FAST PATH for iteration; the FULL matrix is the default, so a bare
## run never silently skips anything). --only NAME restricts the emulators (repeatable); --case C
## restricts the cases in BOTH loops (repeatable); --st-only skips the emulators; --quick is a
## smoke shortcut. The full case list is the single source of truth for both loops.
## notify is a secure-terminal-only case (emulators have no standard notify shot -- the page's
## kitty.notify popup is captured separately), so it is in the full matrix for the ST loop but
## skipped in the emulator loop below.
all_cases='crafted random homoglyph bidi zerowidth altscreen notify tui-showcase'
CASES="${CASES:-${all_cases}}"
only_terminals=''
cases_sel=''
st_only=''
while [ "$#" -gt 0 ]; do
   case "$1" in
      --only)
         [ "$#" -ge 2 ] || { printf '%s\n' 'comparison-capture: --only needs a terminal name' >&2; exit 2; }
         only_terminals="${only_terminals:+${only_terminals} }$2"
         shift 2
         ;;
      --case)
         [ "$#" -ge 2 ] || { printf '%s\n' 'comparison-capture: --case needs a case name' >&2; exit 2; }
         cases_sel="${cases_sel:+${cases_sel} }$2"
         shift 2
         ;;
      --st-only)
         st_only='true'
         shift
         ;;
      --quick)
         only_terminals='kitty'
         cases_sel='crafted'
         shift
         ;;
      *)
         printf '%s\n' "comparison-capture: unknown argument '$1'" >&2
         exit 2
         ;;
   esac
done
if [ -n "${cases_sel}" ]; then
   CASES="${cases_sel}"
fi

## Reliable reaping REQUIRES the safe-pgrep/safe-pkill wrappers -- fail loudly, never fall back.
shots_require_safe_ps || exit 1
## Pre-clean: reap orphaned groups left by any PRIOR crashed run (marker-scoped -- it can never
## touch a process lacking that run's unique marker), then register this run.
shots_reap_registered || true
shots_register_run "${run_marker}"

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
   ## safety net: reap any capture group that leaked from a failed shoot, then drop this run
   ## from the registry (its groups are gone) BEFORE the runtime dir is removed.
   shots_reap_run "${run_marker}" 2>/dev/null || true
   shots_deregister_run "${run_marker}" 2>/dev/null || true
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

## launch an emulator as an Xwayland (X11) client so labwc decorates it, in its OWN session so
## the whole tree (emulator + shell + any server it spawns) can be reaped by one recorded PGID.
launch() {  ## $1=emulator  $2=case  $3=pgid-file
   local e case pgf base sh rows kh cmd
   e="$1"; case="$2"; pgf="$3"
   base=(env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}")
   sh=(bash --rcfile "${HOME}/.strc" -i)
   ## The tui-showcase board paints ~26 lines on the alternate screen; at the 24 rows
   ## the short cases use, its title bar scrolled off the top. Only that case gets the
   ## taller window, so the other cases' shots (and their committed on-page dimensions)
   ## are unchanged. kitty is sized in pixels, so it gets a matching taller height.
   rows=24; kh=430
   if [ "${case}" = tui-showcase ]; then rows=32; kh=620; fi
   cmd=()
   case "${e}" in
      xterm)
         ## forceBoxChars: draw DEC line-drawing with xterm's own crisp integer
         ## line-drawing, not the AA'd font glyph. The font glyph rendered with a
         ## bistable 1px sub-pixel jitter run-to-run on the tui-showcase box border;
         ## the internal line-drawing is pixel-exact and deterministic.
         cmd=("${base[@]}" xterm -xrm 'XTerm.vt100.forceBoxChars: true' \
            -geometry "84x${rows}" -fa 'Monospace' -fs 11 -e "${sh[@]}")
         ;;
      urxvt)
         cmd=("${base[@]}" urxvt -geometry "84x${rows}" -fn 'xft:Monospace:size=11' -e "${sh[@]}")
         ;;
      st)
         cmd=("${base[@]}" st -g "84x${rows}" -f 'Monospace:size=11' -e "${sh[@]}")
         ;;
      konsole)
         cmd=("${base[@]}" QT_QPA_PLATFORM=xcb konsole --nofork -p TerminalColumns=84 -p "TerminalRows=${rows}" -e "${sh[@]}")
         ;;
      qterminal)
         cmd=("${base[@]}" QT_QPA_PLATFORM=xcb qterminal -e "${sh[@]}")
         ;;
      xfce4-terminal)
         cmd=("${base[@]}" GDK_BACKEND=x11 xfce4-terminal --disable-server --geometry "84x${rows}" -x "${sh[@]}")
         ;;
      gnome-terminal)
         ## gnome-terminal is a thin client to gnome-terminal-server over D-Bus, with no
         ## flag to force a private server: give each launch a PRIVATE session bus so its
         ## server starts fresh and dies with the bus, and --wait so the launched process stays
         ## alive until the window closes. The private bus + server sit in the same session, so
         ## reaping the recorded PGID takes the whole thing down. VTE reads its profile from
         ## dconf; with no dconf daemon on the private bus it falls back to the built-in default
         ## profile -- the shipped default we want to show.
         cmd=("${base[@]}" GDK_BACKEND=x11 dbus-run-session -- \
            gnome-terminal --wait --geometry "84x${rows}" -- "${sh[@]}")
         ;;
      mate-terminal)
         cmd=("${base[@]}" GDK_BACKEND=x11 mate-terminal --disable-factory --geometry "84x${rows}" -x "${sh[@]}")
         ;;
      alacritty)
         cmd=("${base[@]}" WINIT_UNIX_BACKEND=x11 alacritty -o 'window.dimensions.columns=84' -o "window.dimensions.lines=${rows}" -o 'font.size=11' -e "${sh[@]}")
         ;;
      kitty)
         cmd=("${base[@]}" KITTY_ENABLE_WAYLAND=0 kitty -o 'remember_window_size=no' -o 'initial_window_width=720' -o "initial_window_height=${kh}" -o 'font_size=11' "${sh[@]}")
         ;;
   esac
   if [ "${#cmd[@]}" -eq 0 ]; then
      ## an unknown emulator name must SKIP this cell, not return non-zero: the call site is a
      ## bare top-level command and `set -o errexit` would abort the whole capture run.
      printf '%s\n' "launch: no launch recipe for '${e}', skipped" >&2
      return 0
   fi
   shots_spawn_session "${pgf}" "${cmd[@]}"
}

## type a command into the focused terminal window and run it, as if a user did.
inject() {  ## $1=window-id  $2=command
   local wid cmd
   wid="$1"; cmd="$2"
   DISPLAY="${xwl_display}" xdotool windowactivate --sync "${wid}" 2>/dev/null || true
   DISPLAY="${xwl_display}" setxkbmap us 2>/dev/null || true    # '/' else types as '&'
   sleep 0.4
   DISPLAY="${xwl_display}" xdotool type --delay 12 -- "${cmd}"
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
   local e case wid ww rescue_h pgf flagf epgid wdog cur_w
   e="$1"; case="$2"; wid=''
   ## the tall tui-showcase board needs a taller pixel-resized window (qterminal +
   ## the shrink rescue); the short cases keep their prior heights so their shots and
   ## committed page dimensions do not move.
   rescue_h=430; [ "${case}" = tui-showcase ] && rescue_h=620
   pgf="$(mktemp -- "${runtime_dir}/pgid.XXXXXX")"
   flagf="${pgf}.timeout"
   ## launch the emulator in its own session (records its PGID into pgf); arm a per-capture
   ## watchdog that reaps that group if the render hangs past the deadline.
   launch "${e}" "${case}" "${pgf}" >/dev/null 2>&1
   ## A non-numeric SHOT_DEADLINE makes shots_watchdog_start refuse (return 1); under errexit
   ## that must NOT abort the whole capture -- run this shot unbounded (no watchdog) instead.
   wdog="$(shots_watchdog_start "${SHOT_DEADLINE}" "${pgf}" "${flagf}")" || wdog=''
   wid="$(find_window || true)"
   if [ -z "${wid}" ]; then
      printf '%s\n' "warn ${e}.${case}: window never appeared, no shot"
      shots_watchdog_cancel "${wdog}"
      epgid="$(cat "${pgf}" 2>/dev/null || true)"
      clear_windows
      shots_reap_group "${epgid}"
      safe-rm -f -- "${pgf}" "${flagf}" 2>/dev/null || true
      return 1
   fi
   ## qterminal opens maximized and ignores a plain resize; unmaximize it first.
   if [ "${e}" = qterminal ]; then
      DISPLAY="${xwl_display}" wmctrl -i -r "${wid}" -b remove,maximized_vert,maximized_horz 2>/dev/null || true
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 720 "${rescue_h}" 2>/dev/null || true
      sleep 0.7
   fi
   sleep 2
   ## tui-showcase's ~26-line board is taller than some emulators actually render (konsole
   ## ignores TerminalRows headlessly and paints ~22 rows), so the board's TOP line -- the
   ## embedded 'cat tui-showcase.payload' prompt that shows what produced the board -- scrolls
   ## off. Force a taller WINDOW before the board renders (the emulator reflows on the resize),
   ## keeping the emulator's own width, so that top line stays on-screen.
   if [ "${case}" = tui-showcase ]; then
      cur_w="$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${wid}" 2>/dev/null | sed -n 's/^WIDTH=//p' || true)"
      [ -n "${cur_w}" ] || cur_w=1100
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" "${cur_w}" 880 2>/dev/null || true
      sleep 0.6
   fi
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
   shots_watchdog_cancel "${wdog}"
   [ -e "${flagf}" ] && printf '%s\n' "warn ${e}.${case}: capture exceeded ${SHOT_DEADLINE}s deadline, group reaped"
   epgid="$(cat "${pgf}" 2>/dev/null || true)"
   clear_windows
   shots_reap_group "${epgid}"
   safe-rm -f -- "${pgf}" "${flagf}" 2>/dev/null || true
}

if ! start_labwc; then
   printf '%s\n' 'labwc did not start; log:'; tail -6 "${runtime_dir}/labwc.log"; exit 1
fi

## lxterminal is omitted: its single-instance startup maps no window headless.
## TERMINALS can be overridden to trial a subset (e.g. TERMINALS='xterm st').
## A MISSING terminal is a HARD ERROR, not a silent skip -- an incomplete grid
## would misrepresent the comparison. Install the emulator, or set ALLOW_SKIP=1 to
## deliberately authorize skipping (it is then logged, never silent).
if [ -n "${st_only}" ]; then
   TERMINALS=''
elif [ -n "${only_terminals}" ]; then
   TERMINALS="${only_terminals}"
else
   TERMINALS="${TERMINALS:-xterm urxvt st konsole gnome-terminal xfce4-terminal mate-terminal qterminal alacritty kitty}"
fi
for e in ${TERMINALS}; do
   ## `type -P` finds a binary that is on PATH and carries SOME exec bit, but that does
   ## not mean the CURRENT user may run it: a hardened Kicksecure/Whonix permission-hardener
   ## strips the others-exec bit from urxvt (mode 0754, owner root), so `type -P` succeeds
   ## yet the launch dies with "Permission denied" and the shot silently never appears.
   ## `[ -x ]` tests access for THIS user, so it catches that -- with an actionable message.
   e_path="$(type -P "${e}" 2>/dev/null || true)"
   if [ -z "${e_path}" ] || [ ! -x "${e_path}" ]; then
      if [ -z "${e_path}" ]; then
         reason="is not installed"
      else
         reason="is present at ${e_path} but not executable by you (a permission-hardener may have stripped its exec bit; restore it with: sudo chmod a+x ${e_path})"
      fi
      if [ -n "${ALLOW_SKIP:-}" ]; then
         printf '%s\n' "SKIP ${e} (${reason}; ALLOW_SKIP authorized)" >&2
         continue
      fi
      printf '%s\n' "ERROR: terminal ${e} ${reason}. Install/fix it, or set ALLOW_SKIP=1 to authorize skipping." >&2
      exit 1
   fi
   for c in ${CASES}; do
      ## notify is secure-terminal-only: the emulators have no standard notify shot (kitty's
      ## popup is a separate capture), so skip it here even though it is in the full ST matrix.
      case "${c}" in
         notify)
            continue
            ;;
      esac
      shoot "${e}" "${c}" || true
   done
   printf '%s\n' "captured ${e}"
done

## secure-terminal renders the board INLINE and shows the real typed prompt, so the board's
## embedded 'cat tui-showcase.payload' line would DUPLICATE it. The emulators (captured above)
## keep that embedded line -- their alt-screen hides the real command, so it is what puts 'cat'
## at the top of their shots. Strip it now, for the secure-terminal pass ONLY (dedicated sibling
## script, not inline scripting).
"${here}/strip-tui-showcase-prompt.py" "${HOME}/tui-showcase.payload"

st_bin="${ST_REPO:-}/usr/bin/secure-terminal"
st_pkg="${ST_REPO:-}/usr/lib/python3/dist-packages"
if [ -n "${ST_REPO:-}" ] && [ -f "${st_bin}" ]; then
   ## Each entry is "<case> <mode> <output-suffix>". secure-terminal is captured in
   ## the display mode that matters for each case: box for the byte-stream cases,
   ## including the homoglyph -- box flags the look-alike byte as a coloured box.
   ## The homoglyph-strip suffix is kept for the committed PNG / Pages reference
   ## (the mode it captures is box; the file name is a label).
   ## Capture width for the ST GUI window. 860 is the app's own default width
   ## (main.py TOOLBAR_DEFAULT_WIDTH): the responsive toolbar renders its "labeled"
   ## tier there -- icon-only action buttons plus every chip group captioned
   ## (unicode / mode / colours / Zoom) -- with no ">>" overflow chevron (labeled
   ## sizeHint 730 < 860 < full 902, so the compact tier is the one that fits). A
   ## wider frame only shrank the terminal text relative to the window; this matches
   ## how the app actually opens and keeps the frame close to the competitor shots.
   st_win_w=860
   ## Each entry is "<case> <mode> <suffix> [tui]". The optional 4th field 'tui' launches
   ## secure-terminal with --tui (opt-in full-screen mode) instead of the default CLI mode.
   ## The tui-showcase board is captured across the CLI/TUI mode x box/show/detail
   ## unicode matrix so the page's view switcher has a real shot per combo. Show renders
   ## printable unicode as its glyph (readable) while still boxing invisible/bidi/control
   ## bytes; detail names each codepoint inline. Even in full-screen TUI every cell stays
   ## character-filtered.
   ## Every demo case is captured in all 5 VALID secure-terminal views so the page's per-row
   ## switcher has a real shot per combo: CLI x {box, detail, show} + TUI x {box, show}. Detail
   ## (and Reveal) are CLI-only -- the fixed TUI grid cannot expand a codepoint inline. Suffix
   ## scheme: <box-suffix>, -detail, -show, -tui, -tui-show (matching tui-showcase's).
   st_specs=(
      'crafted box crafted'
      'crafted detail crafted-detail'
      'crafted show crafted-show'
      'crafted box crafted-tui tui'
      'crafted show crafted-tui-show tui'
      'notify box notify'
      'notify detail notify-detail'
      'notify show notify-show'
      'notify box notify-tui tui'
      'notify show notify-tui-show tui'
      'random box random'
      'random detail random-detail'
      'random show random-show'
      'random box random-tui tui'
      'random show random-tui-show tui'
      'homoglyph box homoglyph-strip'
      'homoglyph detail homoglyph-strip-detail'
      'homoglyph show homoglyph-strip-show'
      'homoglyph box homoglyph-strip-tui tui'
      'homoglyph show homoglyph-strip-tui-show tui'
      'bidi box bidi'
      'bidi detail bidi-detail'
      'bidi show bidi-show'
      'bidi box bidi-tui tui'
      'bidi show bidi-tui-show tui'
      'zerowidth box zerowidth'
      'zerowidth detail zerowidth-detail'
      'zerowidth show zerowidth-show'
      'zerowidth box zerowidth-tui tui'
      'zerowidth show zerowidth-tui-show tui'
      'altscreen box altscreen'
      'altscreen detail altscreen-detail'
      'altscreen show altscreen-show'
      'altscreen box altscreen-tui tui'
      'altscreen show altscreen-tui-show tui'
      'tui-showcase box tui-showcase'
      'tui-showcase show tui-showcase-show'
      'tui-showcase detail tui-showcase-detail'
      'tui-showcase box tui-showcase-tui tui'
      'tui-showcase show tui-showcase-tui-show tui'
   )
   for spec in "${st_specs[@]}"; do
      read -r st_case st_mode st_suffix st_tui <<< "${spec}"
      ## honour --case: skip a spec whose case is not selected (default = all cases).
      st_case_selected=false
      case " ${CASES} " in
         *" ${st_case} "*)
            st_case_selected=true
            ;;
      esac
      if [ "${st_case_selected}" = false ]; then
         continue
      fi
      st_mode_flags=(--mode "${st_mode}")
      [ "${st_tui:-}" = tui ] && st_mode_flags+=(--tui)
      ## tui-showcase: secure-terminal strips the alt-screen escape and renders the
      ## banner + ~26 board rows INLINE (no alt buffer), so a short window would show
      ## only the footer -- give it a taller window (820 fits the 900px labwc output
      ## once grown by the frame). The short cases keep 620 so their committed page
      ## dimensions do not move; tighten_deadspace trims either back to its content.
      st_win_h=620; [ "${st_case}" = tui-showcase ] && st_win_h=820
      ## The GUI runs as `python3 .../secure-terminal` -- process name `python3` -- so it MUST
      ## be reaped by its session PGID, never by name. Launch it in its own session and arm the
      ## per-capture watchdog, exactly like the emulator shots.
      st_pgf="$(mktemp -- "${runtime_dir}/pgid.XXXXXX")"
      st_flagf="${st_pgf}.timeout"
      ## Pin the font DPI to 72 so the render is deterministic regardless of the X
      ## server's DPI. The responsive toolbar's 860 default (st_win_w) is calibrated
      ## to the real compositor's ~9pt/72-DPI metrics (labeled tier: captioned chips,
      ## no ">>" overflow); a default Xvfb reports 96 DPI, which widens the toolbar
      ## and silently drops it to the leaner icons tier (captions hidden). Same
      ## font-metric determinism the test runner pins for the tier assertions.
      ## SECURE_TERMINAL_SHOT=1: deterministic screenshot mode (caret hidden +
      ## synchronous render) so the GUI shot is byte-reproducible run-to-run. Set on
      ## the secure-terminal GUI launch ONLY -- never on the competitor terminals.
      shots_spawn_session "${st_pgf}" \
         env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}" QT_QPA_PLATFORM=xcb \
         QT_FONT_DPI=72 SECURE_TERMINAL_SHOT=1 \
         PYTHONPATH="${st_pkg}" python3 "${st_bin}" --new-instance "${st_mode_flags[@]}" \
         -- bash --rcfile "${HOME}/.strc" -i >/dev/null 2>&1
      ## same guard as the emulator shots: an invalid SHOT_DEADLINE must not errexit-abort.
      st_wdog="$(shots_watchdog_start "${SHOT_DEADLINE}" "${st_pgf}" "${st_flagf}")" || st_wdog=''
      stwid="$(find_window || true)"
      if [ -n "${stwid}" ]; then
         sleep 2
         ## Size the window so the whole toolbar fits (no ">>" overflow chevron),
         ## then let the layout settle before injecting + grabbing.
         DISPLAY="${xwl_display}" xdotool windowsize "${stwid}" "${st_win_w}" "${st_win_h}" 2>/dev/null || true
         sleep 0.6
         inject "${stwid}" "$(shots_payload_cmd "${st_case}")"
         ## SECURE_TERMINAL_SHOT=1 renders synchronously, so a long fixed settle is unneeded.
         sleep 1
         capture_window "${out}/secure-terminal.${st_suffix}.png" "${stwid}"
         tighten_deadspace "${out}/secure-terminal.${st_suffix}.png"
      else
         printf '%s\n' "warn secure-terminal.${st_suffix}: window never appeared"
      fi
      shots_watchdog_cancel "${st_wdog}"
      [ -e "${st_flagf}" ] && printf '%s\n' "warn secure-terminal.${st_suffix}: capture exceeded ${SHOT_DEADLINE}s deadline, group reaped"
      st_epgid="$(cat "${st_pgf}" 2>/dev/null || true)"
      clear_windows
      shots_reap_group "${st_epgid}"
      safe-rm -f -- "${st_pgf}" "${st_flagf}" 2>/dev/null || true
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

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
## user. Each shot is grim-grabbed from the wayland output and trimmed to the single
## window's decorations (a blank pointer + labwc's shadowless default theme make the
## trim exact). Nothing is painted on.
##
## Needs: labwc (its own headless Wayland compositor, WLR_BACKENDS=headless + pixman,
## plus the bundled Xwayland for the X11-only trio xterm/urxvt/st), wlr-randr (HiDPI
## output scale), grim (capture), wtype (key injection), ImageMagick (trim), and
## optipng/jpegoptim/cwebp for the webp encode. Installs NOTHING itself (supply-chain
## hygiene); in the sandbox `sandbox provision shots` installs the whole set, and
## secure-terminal-shots-sandbox preflights it.
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


here="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
## the shared hostile-DATA contract (payload command + log generation).
# shellcheck source=./lib-capture.sh
source "${here}/lib-capture.sh"
## Single source for the labwc-headless bringup (compositor + socket/Xwayland discovery,
## blank cursor, favicon theme, grim trim-to-window). Native Wayland, no host X server.
# shellcheck source=../dist-ai-tests-common/wl-headless-lib.bash
source "${here}/../dist-ai-tests-common/wl-headless-lib.bash"

## check_runtime.bsh provides was_executed, so this script can be SOURCED (its functions reused
## by the dist-ai secure-terminal-shots tests) WITHOUT running the capture. Absent -> fail loud.
if [ ! -r /usr/libexec/helper-scripts/check_runtime.bsh ]; then
   printf '%s\n' 'comparison-capture: helper-scripts check_runtime.bsh not found' >&2
   exit 1
fi
source /usr/libexec/helper-scripts/check_runtime.bsh

## px() -- a geometry constant in LOGICAL pixels. HiDPI is supplied by the compositor's OUTPUT
## SCALE (SHOT_SCALE), set on the headless output by wl_headless_start: native Wayland clients
## render at that scale automatically and labwc scales Xwayland the same, so every window is
## captured at SHOT_SCALE x device pixels for the SAME logical size. So px() is now the identity
## (was `$1 * SHOT_SCALE` under the old per-client-DPI X11 path, which would double-scale here).
px() { printf '%s' "$1"; }

## Shared hero-compare window WIDTH (logical 1x px, scaled through px()). The homepage
## before/after slider overlays the secure-terminal and gnome-terminal hero shots, so BOTH
## windows are pinned to this ONE width -- secure-terminal in the ST pass, gnome-terminal in
## shoot() -- and cannot drift apart. Any other width leaves the narrower window ending short
## of the wider one, so dragging the slider exposes a dead-space band on one side.
HERO_WIN_W_BASE=700

cleanup() {
   ## safety net: reap any capture group that leaked from a failed shoot, then drop this run
   ## from the registry (its groups are gone) BEFORE the runtime dir is removed.
   shots_reap_run "${run_marker}" 2>/dev/null || true
   shots_deregister_run "${run_marker}" 2>/dev/null || true
   ## Tear down the compositor (kills labwc; the runtime dir is ours, removed below).
   wl_headless_stop 2>/dev/null || true
   ## remove the throwaway privileged remote_control drop-in (root-owned, so sudo) either lane may
   ## have created; LOUD on failure (a leaked drop-in keeps remote_control on system-wide), but
   ## never aborts the trap.
   shots_rc_dropin_remove "${rc_dropin}" || true
   safe-rm -r -f -- "${runtime_dir}" 2>/dev/null || true
}


## Bring up the private headless-Wayland compositor via the shared lib: labwc on
## WLR_BACKENDS=headless + WLR_RENDERER=pixman (no host X server, no GPU), a transparent
## pointer (so the trim-to-window crop is exact), the Papirus icon theme (honest per-app
## favicons: app-id/WM_CLASS -> .desktop Icon= -> theme; secure-terminal's own icon is
## session-installed by shots_install_icon_theme, which Papirus inherits via hicolor).
## WAYLAND_DISPLAY + WL_XWAYLAND_DISPLAY are exported; grim captures the wayland output
## directly, so there is no host output window to find.
start_labwc() {
   # shellcheck disable=SC2119
   wl_headless_start --runtime "${runtime_dir}" --icon-theme Papirus --output-scale "${SHOT_SCALE}" || return 1
   wm_pid="${WL_HEADLESS_LABWC_PID}"
   xwl_display="${WL_XWAYLAND_DISPLAY}"
   labwc_rc="${runtime_dir}/labwc-config/rc.xml"
   ## The X11-only emulators (xterm/urxvt/st) read Xft.dpi from their Xwayland display, so their
   ## fonts scale by SHOT_SCALE for the SAME point size (character grid unchanged, pixels-per-cell
   ## scaled) -- matching the native clients' scaled output.
   if [ -n "${xwl_display}" ]; then
      printf '%s\n' "Xft.dpi: ${xft_dpi}" | DISPLAY="${xwl_display}" xrdb -merge 2>/dev/null || true
   fi
   return 0
}

## Pin the next-mapped window's size via a labwc windowRule keyed on its app-id (native) or
## WM_CLASS (Xwayland), then reconfigure labwc so the rule applies on the client's map. This
## REPLACES every post-launch xdotool/wmctrl resize: native Wayland has no external window
## resize, and a rule is deterministic (it also un-maximizes qterminal, which ignores geometry).
## Sizes are logical px scaled by SHOT_SCALE, matching the old geometry.
set_window_rule() {  ## $1=identifier(app-id/WM_CLASS)  $2=width-base  $3=height-base
   local ident="$1" w h
   w="$(px "$2")"; h="$(px "$3")"
   cat > "${labwc_rc}" <<RCXML
<?xml version="1.0"?>
<labwc_config>
  <theme><icon>Papirus</icon></theme>
  <windowRules>
    <windowRule identifier="${ident}"><action name="ResizeTo" width="${w}" height="${h}"/></windowRule>
  </windowRules>
</labwc_config>
RCXML
   kill -s HUP "${wm_pid}" 2>/dev/null || true
   sleep 0.4
}

## The labwc app-id (native Wayland) or WM_CLASS (Xwayland) each emulator maps under -- the
## windowRule match key. Verified against the running windows; fix a value if a shot is mis-sized.
emu_window_id() {  ## $1=emulator -> echoes its labwc identifier
   case "$1" in
      konsole)
         printf '%s' 'org.kde.konsole'
         ;;
      qterminal)
         printf '%s' 'qterminal'
         ;;
      xfce4-terminal)
         printf '%s' 'xfce4-terminal'
         ;;
      mate-terminal)
         printf '%s' 'mate-terminal'
         ;;
      gnome-terminal)
         printf '%s' 'org.gnome.Terminal'
         ;;
      alacritty)
         printf '%s' 'Alacritty'
         ;;
      kitty)
         printf '%s' 'kitty'
         ;;
      xterm)
         printf '%s' 'xterm'
         ;;
      urxvt)
         printf '%s' 'URxvt'
         ;;
      st)
         printf '%s' 'st'
         ;;
      *)
         printf '%s' "$1"
         ;;
   esac
}

## launch an emulator so labwc decorates it (native Wayland, or Xwayland for the X11-only trio),
## in its OWN session so the whole tree (emulator + shell + any server it spawns) can be reaped by
## one recorded PGID.
launch() {  ## $1=emulator  $2=case  $3=pgid-file
   local e case pgf wl x sh rows kh cmd
   e="$1"; case="$2"; pgf="$3"
   ## LC_ALL=C.UTF-8 on every emulator: the harness runs under LC_ALL=C (deterministic payload
   ## byte-generation), but a terminal MUST render those bytes as UTF-8 or the unicode attack
   ## payloads show as mojibake -- and, critically, xterm/urxvt/st (Xwayland) SILENTLY EXIT under a
   ## non-UTF-8 locale (no window, no error), which is why the whole trio was lost. C.UTF-8 keeps C
   ## collation (deterministic) with UTF-8 encoding, and is built into glibc (always present).
   ## Native Wayland for the toolkit terminals (Qt QPA + GTK backend both set; each reads its own).
   ## Xwayland (a private DISPLAY, WAYLAND_DISPLAY unset) ONLY for the X11-only trio xterm/urxvt/st.
   wl=(env LC_ALL=C.UTF-8 QT_QPA_PLATFORM=wayland GDK_BACKEND=wayland)
   x=(env LC_ALL=C.UTF-8 --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}")
   sh=(bash --rcfile "${HOME}/.strc" -i)
   ## The tui-showcase board paints ~26 lines on the alternate screen; at the 24 rows
   ## the short cases use, its title bar scrolled off the top. Only that case gets the
   ## taller window, so the other cases' shots (and their committed on-page dimensions)
   ## are unchanged. kitty is sized in pixels, so it gets a matching taller height.
   ## rows/cols are the character GRID (unchanged by HiDPI). kh is kitty's window height in
   ## PIXELS, so it scales with SHOT_SCALE.
   rows=24; kh="$(px 430)"; cols=84
   if [ "${case}" = tui-showcase ]; then rows=32; kh="$(px 620)"; fi
   ## hero-compare: the window is pinned to the shared HERO_WIN_W_BASE width AFTER launch (in
   ## shoot()), so the initial column count here is not load-bearing for the final width -- the
   ## board is injected only once the window is at its final size. Keep the default grid.
   cmd=()
   case "${e}" in
      xterm)
         ## forceBoxChars: draw DEC line-drawing with xterm's own crisp integer
         ## line-drawing, not the AA'd font glyph. The font glyph rendered with a
         ## bistable 1px sub-pixel jitter run-to-run on the tui-showcase box border;
         ## the internal line-drawing is pixel-exact and deterministic.
         cmd=("${x[@]}" xterm -xrm 'XTerm.vt100.forceBoxChars: true' \
            -geometry "${cols}x${rows}" -fa 'Monospace' -fs 11 -e "${sh[@]}")
         ;;
      urxvt)
         cmd=("${x[@]}" urxvt -geometry "${cols}x${rows}" -fn 'xft:Monospace:size=11' -e "${sh[@]}")
         ;;
      st)
         cmd=("${x[@]}" st -g "${cols}x${rows}" -f 'Monospace:size=11' -e "${sh[@]}")
         ;;
      konsole)
         cmd=("${wl[@]}" konsole --nofork -p "TerminalColumns=${cols}" -p "TerminalRows=${rows}" -e "${sh[@]}")
         ;;
      qterminal)
         ## qterminal opens MAXIMIZED and ignores geometry; shoot() pins its size via a labwc
         ## windowRule before launch (the column count follows from the pinned pixels).
         cmd=("${wl[@]}" qterminal -e "${sh[@]}")
         ;;
      xfce4-terminal)
         cmd=("${wl[@]}" xfce4-terminal --disable-server --geometry "${cols}x${rows}" -x "${sh[@]}")
         ;;
      gnome-terminal)
         ## gnome-terminal is a thin client to gnome-terminal-server over D-Bus, with no
         ## flag to force a private server: give each launch a PRIVATE session bus so its
         ## server starts fresh and dies with the bus, and --wait so the launched process stays
         ## alive until the window closes. The private bus + server sit in the same session, so
         ## reaping the recorded PGID takes the whole thing down. VTE reads its profile from
         ## dconf; with no dconf daemon on the private bus it falls back to the built-in default
         ## profile -- the shipped default we want to show.
         ## gnome-terminal is a D-Bus-activated server whose GtkApplication startup can outlast
         ## D-Bus's 25s activation timeout on this image (slow/failing xdg-desktop-portal
         ## cascade), so a bare `gnome-terminal --wait` loses the activation race and no window
         ## opens. gnome-launch.sh pre-starts the server and waits for its bus name first. No
         ## inline sh -c / exec -- the pre-start + wait (and the hero font setup) live in the
         ## sibling helper, run inside the dbus session.
         if [ "${case}" = hero-compare ]; then
            ## --hero also matches secure-terminal's Hack 72-DPI cell metrics so the homepage
            ## slider's two windows share a cell size.
            cmd=("${wl[@]}" dbus-run-session -- \
               "${here}/gnome-launch.sh" --hero "${cols}x${rows}" -- "${sh[@]}")
         else
            cmd=("${wl[@]}" dbus-run-session -- \
               "${here}/gnome-launch.sh" "${cols}x${rows}" -- "${sh[@]}")
         fi
         ;;
      mate-terminal)
         cmd=("${wl[@]}" mate-terminal --disable-factory --geometry "${cols}x${rows}" -x "${sh[@]}")
         ;;
      alacritty)
         cmd=("${wl[@]}" alacritty -o "window.dimensions.columns=${cols}" -o "window.dimensions.lines=${rows}" -o 'font.size=11' -e "${sh[@]}")
         ;;
      kitty)
         ## kitty (native Wayland) computes its cell from font_size(pt) x the output scale; only
         ## its PIXEL window size is set here so the same column count fits the cells.
         cmd=("${wl[@]}" kitty -o 'remember_window_size=no' -o "initial_window_width=$(px 720)" -o "initial_window_height=${kh}" -o 'font_size=11' "${sh[@]}")
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

## Type a command into the focused terminal and run it, as if a user did. wtype drives the
## compositor's virtual keyboard, which labwc delivers to the FOCUSED window -- native Wayland
## and Xwayland alike -- and labwc focuses the single window we just mapped. No keymap dance
## (wtype sends the text directly, so the old xdotool '/'-becomes-'&' problem is gone).
inject() {  ## $1=window-id (unused: the mapped window has focus)  $2=command
   local run_cmd="$2"
   sleep 0.4
   ## wtype loses its FIRST keystroke(s) into a not-yet-ready readline (the slow
   ## gnome-terminal-server maps its chrome, so the window is non-blank, well before the interactive
   ## bash prints its prompt), so the injected `cat` arrives as `at` -- a corrupt shot. Erase+retype
   ## makes the typed line deterministic regardless of startup timing: type it, Ctrl-U to kill
   ## whatever landed (readline is active by now, having received that input), then type it AGAIN
   ## onto the now-ready empty line and run. No visible artifact (Ctrl-U erases in place).
   wtype -- "${run_cmd}" 2>/dev/null || true
   wtype -M ctrl -k u -m ctrl 2>/dev/null || true
   wtype -- "${run_cmd}" 2>/dev/null || true
   sleep 0.3
   wtype -k Return 2>/dev/null || true
}

## Screenshot the single visible window. grim grabs the whole wayland output; the pointer is
## hidden (blank Xcursor) and labwc draws no shadow, so a black-border trim crops exactly to the
## window's decorations -- no window geometry, no frame extents, no host X server.
capture_window() {  ## $1=output-path  $2=window-id (unused: one window on the output)
   wl_headless_capture_window "$1"
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
   local best_end top_h bot_y bot_h margin threshold scale
   ## margin/threshold/side are PIXEL tolerances -> scale with the HiDPI factor so the trim
   ## keeps the same visual behaviour (a "40-row void" is 40*SHOT_SCALE px at 2x). Read
   ## SHOT_SCALE directly (default 1) instead of px(), so the function stays SELF-CONTAINED for a
   ## caller that SOURCED this file (tighten_skip_test.sh): the top-level SHOT_SCALE parse and
   ## validation run only on a direct execution, so a sourced caller leaves it unset/unvalidated.
   scale="${SHOT_SCALE:-1}"
   ## Sanitize LOCALLY: a sourced caller has not run the top-level SHOT_SCALE validation, so a
   ## stray value must not reach the arithmetic below (a leading zero is octal -> 08/09 abort;
   ## a non-digit would be evaluated as a name/index).
   case "${scale}" in ''|*[!0-9]*|0*) scale=1 ;; esac
   margin=$(( 10 * scale ))
   threshold=$(( 40 * scale ))
   f="$1"
   [ -f "${f}" ] || return 0
   w="$(identify -format '%w' "${f}")"; h="$(identify -format '%h' "${f}")"
   side=$(( 40 * scale )); [ "${w}" -gt $(( 200 * scale )) ] || side=0
   mw=$(( w - 2 * side ))
   ## background = most-frequent colour of the lower half (skips the light top chrome;
   ## background dominates even a screen of garble). grep -m1 closes the pipe after the
   ## top colour; '|| true' keeps the upstream SIGPIPE from tripping errexit+pipefail.
   bg="$(convert "${f}" -gravity South -crop "${w}x50%+0+0" +repage \
           -depth 8 -format '%c' histogram:info:- \
         | sort -rn | grep -m1 -oiE '#[0-9A-F]{6}')" || true
   [ -n "${bg}" ] || bg="$(convert "${f}" -format "#%[hex:p{2,$(( h - 4 ))}]" info: | cut -c1-7 || true)"
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

## Compose the homepage before/after slider pair from the hero-compare shots: secure-terminal's
## SHOW-mode board and the gnome-terminal render of the SAME board. The site's CSS resize slider
## overlays them, so they must be identical size AND their terminal text must sit at the same
## coordinates. hero-slider-compose.py keeps the title bars aligned at the top, inserts a white band
## above the shallower-chrome terminal's text so both text tops line up (secure-terminal carries a
## toolbar + tab strip + a bottom notice a plain terminal lacks), then pads both to one shared canvas.
## Runs at the END of a single-lane run, from the two .png shots before webp optimization; a no-op
## (logged) if either is absent (e.g. an emulator-only or --jobs lane). gnome-terminal is the
## traditional side: it HONOURS the OSC-0 title hijack (the spoofed title shows in its title bar)
## where konsole resets it, and -- captured with secure-terminal's own Hack font at 72 DPI (see
## launch()) -- its text is cell-for-cell the same size, so the wipe reads as ONE session secured vs not.
compose_hero_slider() {  ## $1=out-dir
   local out sec trad
   out="$1"
   sec="${out}/secure-terminal.hero-compare-show.png"
   trad="${out}/gnome-terminal.hero-compare.png"
   if [ ! -f "${sec}" ] || [ ! -f "${trad}" ]; then
      printf '%s\n' 'compose_hero_slider: secure-terminal + gnome-terminal hero-compare shots not both present; skipping slider compose' >&2
      return 0
   fi
   "${here}/hero-slider-compose.py" "${sec}" "${trad}" "${out}/hero-secure.png" "${out}/hero-traditional.png"
   ## Drop the raw per-terminal hero-compare shots: only the composed pair is referenced by the
   ## site, so leaving the sources behind would land them in comparison/shots/ (the driver pulls
   ## every .webp) as ORPHANS that website-tests rejects. Removing them here keeps the site green on
   ## every regeneration with no step to remember. The honest per-terminal captures still exist
   ## mid-run; only the composed hero-secure/hero-traditional are published.
   safe-rm -f -- "${out}"/*.hero-compare.png "${out}"/*.hero-compare.webp \
      "${out}/secure-terminal.hero-compare-show.png" "${out}/secure-terminal.hero-compare-show.webp" 2>/dev/null || true
   printf '%s\n' 'composed hero slider pair: hero-secure.png, hero-traditional.png (raw hero-compare shots dropped)'
}

## Capture the window, then guard against a blank/black grab (the content had not finished
## rendering when the screenshot was taken -- more likely under the parallel --jobs CPU load).
## Re-grab a couple of times WITHOUT re-injecting (the command already ran; it just needs to
## finish painting), then tighten. A shot still blank after retries is warned, never silent.
capture_settled() {  ## $1=output-path  $2=window-id  [$3='skip-tighten']
   local dest wid skip_tighten tries
   dest="$1"; wid="$2"; skip_tighten="${3:-}"; tries=0
   while [ "${tries}" -lt 3 ]; do
      if ! capture_window "${dest}" "${wid}"; then
         ## Leave NO file on failure -- else a stale dest from a prior attempt survives and the
         ## caller's `[ -f dest ]` check accepts it as a fresh shot. (The still-blank path below
         ## discards too; this makes capture_settled leave a file ONLY on success, so every
         ## caller's file-existence guard is valid.)
         safe-rm --force -- "${dest}" 2>/dev/null || true
         printf '%s\n' "warn: screenshot failed for $(basename -- "${dest}")"
         return 1
      fi
      if ! shots_shot_is_blank "${dest}"; then
         ## skip-tighten: the pinned full-viewport colour boards fill the terminal, so there
         ## is no screenful of dead space to trim, and tighten's content/background boundary
         ## detection is non-deterministic on a board whose edge colour is close to the
         ## terminal background -- it drifts the crop height run-to-run. The raw grab is the
         ## pinned window geometry, so leaving it untightened keeps the dimensions deterministic.
         [ "${skip_tighten}" = 'skip-tighten' ] || tighten_deadspace "${dest}"
         return 0
      fi
      tries=$(( tries + 1 ))
      printf '%s\n' "warn: $(basename -- "${dest}") blank (attempt ${tries}); waiting to re-grab"
      sleep 2
   done
   ## Still blank: DISCARD it rather than emit a black shot. A missing PNG is not webp'd or
   ## pulled, so a previously-good published shot is left intact instead of being overwritten
   ## with black. The caller warns.
   safe-rm --force -- "${dest}" 2>/dev/null || true
   printf '%s\n' "warn: $(basename -- "${dest}") still blank after retries -- discarded (kept any prior good shot)"
   return 1
}

## Block until the window's rendering has SETTLED: grab throwaway frames until two consecutive
## grabs match within a jitter tolerance. capture_settled only rejects a BLANK frame, so a heavy
## still-painting TUI pyte grid would be grabbed half-drawn; a whole unpainted row band differs by
## thousands of pixels between grabs, while the known ~1px sub-pixel border jitter differs by only
## a handful, so a small AE tolerance settles once painting stops. Best-effort: a failed grab
## or a missing `compare` just returns and lets capture_settled proceed.
##
## The wait is WALL-CLOCK bounded, not a fixed iteration count: a full-viewport 24-bit board in
## SHOW/TUI mode paints ROW BY ROW over ~20s -- every cell carries a distinct truecolour format,
## which defeats the same-format run coalescing the grid renderer relies on, so the document is
## rebuilt one slow frame per read. A fixed 8s cap timed out mid-paint and the capture grabbed a
## half-drawn board (the bottom rows + the returning prompt missing). Wait for a REAL settle,
## capped just under the per-capture SHOT_DEADLINE so a never-settling window still falls through
## to capture_settled's blank/content retry rather than hanging.
st_wait_render_settled() {  ## $1=window-id
   local wid a b diff budget start deadline
   wid="$1"
   type -P compare >/dev/null || return 0
   ## Cap the wait under the watchdog's reap (SHOT_DEADLINE, default 90s), leaving margin so the
   ## group is not torn down mid-settle. A non-numeric deadline keeps the safe 75s default.
   ## Wall-clock cap for the settle, kept UNDER the watchdog's SHOT_DEADLINE reap (default 90s) so
   ## the window group is not torn down mid-settle. Validate the deadline as base-10 digits: a value
   ## like 09 must NOT be read as octal (bash arithmetic would error out under errexit), and a
   ## non-numeric or unset deadline keeps the 90s assumption. budget = deadline - 15 leaves margin,
   ## clamped to [1, 75] so it never exceeds a tiny deadline nor over-waits the default.
   case "${SHOT_DEADLINE:-}" in
      *[!0-9]*|'')
         deadline=90
         ;;
      *)
         deadline=$(( 10#${SHOT_DEADLINE} ))
         ;;
   esac
   budget=$(( deadline - 15 ))
   [ "${budget}" -gt 75 ] && budget=75
   [ "${budget}" -lt 1 ] && budget=1
   a="$(mktemp -- "${runtime_dir}/settle.XXXXXX.png")"
   b="$(mktemp -- "${runtime_dir}/settle.XXXXXX.png")"
   if ! capture_window "${a}" "${wid}" 2>/dev/null; then
      safe-rm --force -- "${a}" "${b}" 2>/dev/null || true
      return 0
   fi
   start=${SECONDS}
   while [ $(( SECONDS - start )) -lt "${budget}" ]; do
      sleep 0.8
      capture_window "${b}" "${wid}" 2>/dev/null || break
      diff="$(compare -metric AE "${a}" "${b}" null: 2>&1 || true)"
      ## compare -metric AE prints the differing-pixel count in SCIENTIFIC NOTATION once it
      ## exceeds ~1e6 (e.g. 2.1328e+06). Stripping at the first non-digit truncated that to "2"
      ## -> a still-painting full-viewport frame (art/gradient/tui-showcase, >1M px) read as
      ## settled and published a half-rendered shot. Normalize via printf %.0f (handles plain
      ## AND sci-notation); an empty (failed compare) or non-numeric value is NOT settled --
      ## printf '%.0f' '' yields 0, so those must be rejected BEFORE printf, not after.
      diff="${diff%% *}"
      case "${diff}" in
         ''|*[!0-9.eE+-]*)
            diff=999999
            ;;
         *)
            diff="$(printf '%.0f' "${diff}" 2>/dev/null)"
            [ -n "${diff}" ] || diff=999999
            ;;
      esac
      [ "${diff}" -lt 300 ] 2>/dev/null && break   # only jitter left -> settled
      ## Copy (not move) the newer frame to the baseline: mv would unlink ${b}, and the next
      ## capture_window would recreate that path OUTSIDE mktemp's protection. ${runtime_dir} is
      ## owner-only, so this is belt-and-braces, but it keeps ${b} a mktemp-created file.
      cp --force -- "${b}" "${a}"
   done
   safe-rm --force -- "${a}" "${b}" 2>/dev/null || true
}

## Create a throwaway privileged remote_control=true drop-in and echo its path (record it so
## cleanup() removes THIS one); return 1 (echo nothing) on failure. remote_control is
## PRIVILEGED_ONLY -- honoured only from a root-writable system drop-in, with no env relocation
## hook by design, so a user config cannot enable it. sudo is sandbox-only. Shared by the
## comparison and zoom-live lanes (both drive a running instance via `ctl`).
shots_rc_dropin_create() {  ## $1=filename prefix
   local rc_dir dropin
   rc_dir='/usr/local/etc/secure-terminal.d'
   sudo mkdir --parents -- "${rc_dir}" || return 1
   ## A UNIQUE root-owned drop-in (ending in .conf so settings.py's *.conf glob reads it); NEVER a
   ## fixed name -- that would TRUNCATE an admin file or a concurrent run's drop-in.
   dropin="$(sudo mktemp --tmpdir="${rc_dir}" "${1}.XXXXXX.conf")" || return 1
   [ -n "${dropin}" ] || return 1
   if ! printf 'remote_control=true\n' | sudo tee -- "${dropin}" >/dev/null; then
      sudo safe-rm --force -- "${dropin}" 2>/dev/null || true
      return 1
   fi
   ## sudo mktemp made it 0600 root:root, but secure-terminal launches UNPRIVILEGED and must READ
   ## it, or remote_control=true never applies and `ctl ls` finds no tab -- world-read a non-secret
   ## flag file (still root-OWNED for placement in the trusted dir).
   if ! sudo chmod 0644 -- "${dropin}"; then
      sudo safe-rm --force -- "${dropin}" 2>/dev/null || true
      return 1
   fi
   printf '%s' "${dropin}"
}

## Remove a throwaway privileged drop-in (root-owned, so sudo). LOUD on failure: a leaked drop-in
## keeps remote_control enabled system-wide, so NAME the leaked path rather than swallowing the
## error -- but return, never abort (it runs from the EXIT trap). A no-op on an empty path.
shots_rc_dropin_remove() {  ## $1=drop-in path
   [ -n "${1:-}" ] || return 0
   if ! sudo safe-rm --force -- "${1}"; then
      printf '%s\n' "WARNING: could not remove privileged remote_control drop-in '${1}'; remove it manually -- remote_control stays enabled system-wide until then" >&2
      return 1
   fi
   return 0
}

## zoom-live: the REAL-GUI white-band/scrollbar diagnostic. Launch secure-terminal ONCE as the
## group PRIMARY (so `secure-terminal ctl` can reach it), with a full-screen TUI board, then step
## the font zoom LIVE via `ctl zoom` against the SAME running instance -- NO restart between levels
## -- screenshotting the real decorated window at each. On the real app (unlike an offscreen widget
## grab) it proves the horizontal scrollbar stays suppressed on the grid and no mid-screen white
## band appears as the grid re-lays-out under a live zoom. Writes zoom-live-<pct>.png into ${out}.
zoom_live_capture() {  ## $@=zoom levels (percent); default band if none
   local level st_pgf st_flagf st_transcript st_wdog stwid st_win_w st_win_h st_cmd rc_dir dropin
   local st_tab_line st_tab_id failures shots level_padded zoom_out_file zoom_result reap_pgid
   local -a levels

   ## Levels arrive as ARGV (an array), never word-split from a string, so a glob-looking level
   ## (`*`) is a literal token here, not an expansion of the cwd. Empty argv -> the default band.
   if [ "$#" -eq 0 ]; then
      levels=(50 75 100 125 150 175 200)
   else
      levels=("$@")
   fi
   failures=0
   shots=0

   ## Enable remote_control for the capture via a throwaway privileged drop-in (removed on exit by
   ## cleanup()). Record the EXACT path in the shared rc_dropin so cleanup removes THIS one.
   rc_dropin="$(shots_rc_dropin_create zoom-live-rc)" || {
      printf '%s\n' 'zoom-live: cannot create the privileged remote_control drop-in (sudo?)' >&2
      return 1
   }

   ## A full-screen TUI to zoom: the tui-showcase board in TUI mode (alt screen, fills the
   ## viewport) -- the same real full-viewport payload the comparison TUI shots use, so the grid is
   ## genuinely full when the scrollbar / white-band bug would show. Build the with-prompt sibling
   ## that the TUI inject command cats (the plain one is stripped in place for CLI).
   ## errexit is SUPPRESSED inside this function (its call site is `zoom_live_capture ... || rc=$?`),
   ## so a bare failing command does NOT abort -- it silently continues to a misleading downstream
   ## error. Guard the top-level steps EXPLICITLY (same discipline as shots_generate_logs): a missing
   ## payload here means generation did not run, and must fail loud at its true source.
   if ! cp -- "${HOME}/tui-showcase.payload" "${HOME}/tui-showcase-withprompt.payload"; then
      printf '%s\n' "zoom-live: ${HOME}/tui-showcase.payload is missing -- payload generation did not run; cannot build the TUI board" >&2
      return 1
   fi
   st_cmd="$(shots_st_inject_cmd tui-showcase tui)" || return 1
   st_win_w="$(px 860)"
   st_win_h="$(px 820)"

   st_pgf="$(mktemp -- "${runtime_dir}/pgid.XXXXXX")" || return 1
   st_flagf="${st_pgf}.timeout"
   st_transcript="${st_pgf}.transcript"
   safe-rm -f -- "${st_transcript}" 2>/dev/null || true

   ## Launch ST as the group PRIMARY: NO --new-instance (a --new-instance window is standalone and
   ## never claims the ctl socket, so `ctl zoom` could not reach it). --tui opens full-screen. Native
   ## Wayland, same deterministic 72-DPI / SECURE_TERMINAL_SHOT env as the comparison ST pass (the
   ## output scale supplies 2x, so NO QT_SCALE_FACTOR); reaped by PGID. Size on map via a labwc
   ## windowRule keyed on the app_id (native Wayland has no external resize), set before the launch.
   set_window_rule secure-terminal "${st_win_w}" "${st_win_h}"
   shots_spawn_session "${st_pgf}" \
      env "SHOTS_RUN_MARKER=${run_marker}" QT_QPA_PLATFORM=wayland \
      QT_FONT_DPI=72 SECURE_TERMINAL_SHOT=1 SHELL=/bin/bash \
      "SECURE_TERMINAL_TRANSCRIPT_FILE=${st_transcript}" \
      PYTHONPATH="${st_pkg}" "${st_bin}" --tui >/dev/null 2>&1

   st_wdog="$(shots_watchdog_start "${SHOT_DEADLINE}" "${st_pgf}" "${st_flagf}")" || st_wdog=''
   stwid="$(find_window || true)"
   if [ -z "${stwid}" ]; then
      printf '%s\n' 'warn zoom-live: secure-terminal window never appeared' >&2
      shots_watchdog_cancel "${st_wdog}"
      shots_reap_group "$(cat "${st_pgf}" 2>/dev/null || true)"
      return 1
   fi
   ## Window is sized on map by the windowRule above; wait until it has painted before injecting.
   wait_window_ready "${stwid}"

   ## Warm the shell/board once so the first `ctl ls` + inject run against a settled prompt.
   inject "${stwid}" "${st_cmd}"
   sleep 1
   st_wait_render_settled "${stwid}"

   ## Discover the target tab id from `ctl ls` (its first tab-separated column). A fresh single-tab
   ## instance numbers tab ids from 0, so a hardcoded id would miss; parse the real one. A reachable
   ## `ctl ls` also confirms remote_control is on AND the socket was claimed -- else every level
   ## below would silently no-op and all shots would be the launch zoom.
   st_tab_line="$(env PYTHONPATH="${st_pkg}" "${st_bin}" ctl ls 2>/dev/null | head -1 || true)"
   st_tab_id="${st_tab_line%%	*}"
   if [ -n "${st_tab_id}" ]; then
      printf '%s\n' "zoom-live: ctl reachable (remote_control on, primary socket claimed); zooming tab id:${st_tab_id}"
   else
      printf '%s\n' 'warn zoom-live: secure-terminal ctl ls returned no tab (remote_control off, or not primary) -- NO shot reflects a live zoom' >&2
      st_tab_id='0'
      failures=$(( failures + 1 ))
   fi

   for level in "${levels[@]}"; do
      ## Validate BEFORE the arithmetic below: a non-numeric level aborts the `$(( 10#... ))` under
      ## errexit, collapsing the filename to `zoom-live-.png` (a silent overwrite). Accept only a
      ## non-negative integer -- otherwise skip it, warn, and count it as a failure.
      case "${level}" in
         ''|*[!0-9]*)
            printf '%s\n' "warn zoom-live: skipping non-numeric zoom level '${level}'" >&2
            failures=$(( failures + 1 ))
            continue
            ;;
      esac
      ## Step the zoom LIVE on the SAME instance -- no restart -- routed to the discovered tab.
      zoom_out_file="${runtime_dir}/zoom.${level}.out"
      if env PYTHONPATH="${st_pkg}" "${st_bin}" \
            ctl zoom --tab "id:${st_tab_id}" "${level}" >"${zoom_out_file}" 2>&1; then
         zoom_result="$(cat -- "${zoom_out_file}" 2>/dev/null || true)"
         printf '%s\n' "zoom-live: ctl zoom ${level} -> ${zoom_result}"
      else
         zoom_result="$(cat -- "${zoom_out_file}" 2>/dev/null || true)"
         printf '%s\n' "warn zoom-live: ctl zoom ${level} failed: ${zoom_result}" >&2
         failures=$(( failures + 1 ))
      fi
      ## The zoom resizes the pyte grid (SIGWINCH). A LIVE full-screen TUI redraws itself on that
      ## signal, filling the new grid; a STATIC cat'd board cannot, so it would scroll out and the
      ## shot would show empty rows -- an artifact of the payload, not the app. Re-inject the board
      ## AFTER the zoom so it redraws at the NEW grid dimensions, exactly as a SIGWINCH-aware TUI
      ## app would: every level is then a genuinely FULL grid, the state in which a stray horizontal
      ## scrollbar or a mid-screen white band would actually appear. skip-tighten keeps the pinned
      ## geometry (the board fills the viewport).
      sleep 0.6
      inject "${stwid}" "${st_cmd}"
      sleep 1
      st_wait_render_settled "${stwid}"
      ## Zero-pad the (validated) integer level for a stable filename; 10# forces base 10 so a
      ## value like 050 is not read as octal.
      level_padded="$(printf '%03d' "$(( 10#${level} ))")"
      if capture_settled "${out}/zoom-live-${level_padded}.png" "${stwid}" skip-tighten; then
         shots=$(( shots + 1 ))
      else
         failures=$(( failures + 1 ))
      fi
   done

   shots_watchdog_cancel "${st_wdog}"
   if [ -e "${st_flagf}" ]; then
      printf '%s\n' "warn zoom-live: capture exceeded ${SHOT_DEADLINE}s deadline, group reaped" >&2
      failures=$(( failures + 1 ))
   fi
   reap_pgid="$(cat "${st_pgf}" 2>/dev/null || true)"
   shots_reap_group "${reap_pgid}"
   safe-rm -f -- "${st_pgf}" "${st_flagf}" "${st_transcript}" 2>/dev/null || true
   printf '%s\n' "zoom-live: wrote ${shots} real-GUI zoom shot(s) to ${out}"
   ## A no-op sweep is NOT a pass: if ctl was unreachable (no tab), any zoom/capture failed, or the
   ## deadline was hit -- or zero valid shots were produced -- FAIL so the harness cannot false-green
   ## while claiming to verify "zoom changes live".
   if [ "${failures}" -gt 0 ] || [ "${shots}" -eq 0 ]; then
      printf '%s\n' "warn zoom-live: ${failures} failure(s), ${shots} valid shot(s) -- FAILED" >&2
      return 1
   fi
   return 0
}

## Wait until a freshly-launched window has actually RENDERED (its content is no longer a flat
## blank) before typing into it. The first secure-terminal launch is a Qt cold start that, under
## the parallel --jobs CPU load, can still be painting nothing when the fixed settle elapses --
## so the injected 'cat' is typed into a not-yet-ready app and never runs, leaving a black shot.
## Polls a light grab of the window; proceeds anyway on timeout (the capture's own blank-retry +
## warning is the backstop).
wait_window_ready() {  ## $1=window-id
   local wid tmp tries
   wid="$1"; tries=0
   tmp="$(mktemp --suffix=.png)"
   ## Generous ceiling: the first secure-terminal cold start under parallel --jobs contention can
   ## take tens of seconds (until the competing lane frees CPU). Each poll is a light grab.
   while [ "${tries}" -lt 30 ]; do
      if capture_window "${tmp}" "${wid}" 2>/dev/null && ! shots_shot_is_blank "${tmp}"; then
         safe-rm --force -- "${tmp}" 2>/dev/null || true
         return 0
      fi
      tries=$(( tries + 1 ))
      sleep 1
   done
   safe-rm --force -- "${tmp}" 2>/dev/null || true
   return 0
}

## Wait until the emulator's window has MAPPED. Native Wayland has no external window list
## (xdotool sees only Xwayland), so readiness is a non-degenerate grab -- the single window on
## the output produced a trimmable frame -- not a window search. Returns a placeholder id: with
## grim capture + wtype inject, nothing downstream needs a real window-id, only "it appeared".
find_window() {  ## $1=emulator
   local e tmp tries n
   e="${1:-}"
   ## gnome-terminal is a D-Bus-activated server whose portal-stalled startup (see
   ## gnome-launch.sh) delays its window ~26s -- past the direct-spawn emulators' 20s
   ## bringup budget -- so give it a longer one, still well under the per-capture
   ## SHOT_DEADLINE watchdog (default 90s) so a truly dead launch still fails, not hangs.
   tries=80
   [ "${e}" = gnome-terminal ] && tries=280
   tmp="$(mktemp --suffix=.png)"
   for (( n = 1; n <= tries; n++ )); do
      if ! kill -0 "${wm_pid}" 2>/dev/null; then
         safe-rm --force -- "${tmp}"
         return 1
      fi
      if wl_headless_capture_window "${tmp}" 2>/dev/null; then
         safe-rm --force -- "${tmp}"
         printf '%s' 'wl'
         return 0
      fi
      sleep 0.25
   done
   safe-rm --force -- "${tmp}"
   return 1
}

shoot() {  ## $1=emulator  $2=case
   local e case wid pgf flagf epgid wdog win_w win_h emu_err
   e="$1"; case="$2"; wid=''
   ## Window pixel size for the windowRule-sized emulators: qterminal opens MAXIMIZED and the
   ## GTK/VTE terminals (xfce4/mate/gnome) ignore --geometry on Wayland, so a labwc windowRule
   ## pins them on map. The grid-honouring ones (konsole -p, alacritty -o, kitty px, the
   ## Xwayland xterm/urxvt/st -geometry) size themselves from their launch flags and take no
   ## rule. tui-showcase needs a taller window (its board is ~32 rows); hero-compare pins the
   ## shared width so the homepage before/after slider overlays cleanly.
   win_w="$(px 760)"; win_h="$(px 500)"
   [ "${case}" = tui-showcase ] && win_h="$(px 680)"
   [ "${case}" = hero-compare ] && win_w="$(px "${HERO_WIN_W_BASE}")"
   case "${e}" in
      qterminal|xfce4-terminal|mate-terminal|gnome-terminal)
         set_window_rule "$(emu_window_id "${e}")" "${win_w}" "${win_h}"
         ;;
   esac
   pgf="$(mktemp -- "${runtime_dir}/pgid.XXXXXX")"
   flagf="${pgf}.timeout"
   ## Capture the emulator's OWN stderr to a per-shot file (the spawned child inherits this fd),
   ## so a launch that dies before mapping -- the Xwayland trio's failure mode under the full
   ## matrix -- is DIAGNOSABLE, not swallowed. Surfaced verbatim on the "window never appeared"
   ## warning below; a permanent diagnostic, not a throwaway.
   emu_err="${pgf}.err"
   ## launch the emulator in its own session (records its PGID into pgf); arm a per-capture
   ## watchdog that reaps that group if the render hangs past the deadline.
   launch "${e}" "${case}" "${pgf}" >/dev/null 2>"${emu_err}"
   ## A non-numeric SHOT_DEADLINE makes shots_watchdog_start refuse (return 1); under errexit
   ## that must NOT abort the whole capture -- run this shot unbounded (no watchdog) instead.
   wdog="$(shots_watchdog_start "${SHOT_DEADLINE}" "${pgf}" "${flagf}")" || wdog=''
   wid="$(find_window "${e}" || true)"
   if [ -z "${wid}" ]; then
      printf '%s\n' "warn ${e}.${case}: window never appeared, no shot"
      ## Surface the emulator's own stderr (a lost shot's cause shows here), so a failure is
      ## diagnosable instead of silent. Prefixed per line; empty file -> nothing printed.
      if [ -s "${emu_err}" ]; then
         sed "s/^/warn ${e}.${case} stderr: /" -- "${emu_err}" >&2 || true
      fi
      shots_watchdog_cancel "${wdog}"
      epgid="$(cat "${pgf}" 2>/dev/null || true)"
      shots_reap_group "${epgid}"
      safe-rm -f -- "${pgf}" "${flagf}" "${emu_err}" 2>/dev/null || true
      return 1
   fi
   ## The window is sized on map (launch flags or the windowRule above); native Wayland has no
   ## external post-launch resize and grim+trim crops to whatever the window is. Wait for the
   ## first content, inject the case payload as a user would, let it render, then capture.
   wait_window_ready "${wid}"
   inject "${wid}" "$(shots_payload_cmd "${case}")"
   sleep 3
   if ! capture_settled "${out}/${e}.${case}.png" "${wid}"; then
      printf '%s\n' "warn ${e}.${case}: screenshot failed"
      ## Surface the emulator's own stderr on ANY lost shot (a trio member that maps then dies
      ## shows here, not on the window-never-appeared path). Empty file -> nothing printed.
      if [ -s "${emu_err}" ]; then
         sed "s/^/warn ${e}.${case} stderr: /" -- "${emu_err}" >&2 || true
      fi
   fi
   shots_watchdog_cancel "${wdog}"
   [ -e "${flagf}" ] && printf '%s\n' "warn ${e}.${case}: capture exceeded ${SHOT_DEADLINE}s deadline, group reaped"
   epgid="$(cat "${pgf}" 2>/dev/null || true)"
   shots_reap_group "${epgid}"
   safe-rm -f -- "${pgf}" "${flagf}" "${emu_err}" 2>/dev/null || true
}

## Strict mode ONLY when executed, so sourcing this file (a test reusing the functions above)
## does not inherit errexit/nounset into the caller's shell.
if was_executed "${BASH_SOURCE[0]}"; then
   set -o errexit
   set -o nounset
   set -o pipefail
   set -o errtrace
   shopt -s inherit_errexit
   shopt -s shift_verbose
   export LC_ALL=C
fi

## SOURCE-SAFE boundary: the functions ABOVE are now defined; stop here when sourced so none of
## the capture set-up, orchestration or main loop BELOW runs. Everything below runs on a direct run.
was_executed "${BASH_SOURCE[0]}" || return 0

out="${here}/shots"
mkdir --parents -- "${out}"

## the throwaway privileged remote_control drop-in path (comparison or zoom-live), removed by
## cleanup(); empty until a lane writes one.
rc_dropin=''


## Fail BEFORE the expensive capture if the bundled webp optimizer is missing -- a direct
## run (not via the secure-terminal-shots wrapper) resolves it checkout-relative, not by PATH.
shots_require_image_optimize || exit 1

## Resolve the corpus NOW, while HOME is still the operator's -- the reassignment
## below would otherwise hide the documented ~/private-sources default from the
## resolver. Export it so shots_generate_logs (run after the reassign) reuses it.
CORPUS_REPO="$(shots_resolve_corpus "${here}/../../../../terminal-poc-corpus" || true)"
export CORPUS_REPO

runtime_dir="$(mktemp --directory)"
export XDG_RUNTIME_DIR="${runtime_dir}"
export HOME="${runtime_dir}/home"
export XDG_CONFIG_HOME="${runtime_dir}/config"
mkdir --parents -- "${HOME}" "${XDG_CONFIG_HOME}"

## The run's unique reaping MARKER: the mktemp runtime dir, which every spawned terminal / GUI
## carries in its argv (the emulators via `--rcfile ${HOME}/.strc`; secure-terminal via the
## `SHOTS_RUN_MARKER=` env, which env(1) places in the process argv but labwc ignores) plus the
## recorded pgid file, so a crashed run's orphans can be swept by exactly this string and nothing
## else. The marker is deliberately kept OFF ST's identity: labwc resolves the titlebar icon from
## the Wayland app-id, so a per-run temp path there breaks the favicon. The shots pass NO identity
## flag to secure-terminal -- it sets its own app-id (`secure-terminal`, via setDesktopFileName)
## idiomatically, which labwc resolves to the real icon; the shots only avoid sabotaging it.
run_marker="${runtime_dir}"
## Register the cleanup trap NOW -- the runtime dir + reaping marker exist and the first
## argument-validation `exit` is just below -- so an early exit (bad SHOT_SCALE / --jobs /
## --case / --only / unknown arg) removes the mktemp runtime dir instead of leaking it.
## cleanup reads wm_pid under `set -u`, so define it here; the window manager starts far below.
wm_pid=''
trap cleanup EXIT
## Per-capture deadline (seconds): a render that hangs longer than this has its process group
## reaped and the loop continues, so a wedged terminal cannot stall the whole grid.
SHOT_DEADLINE="${SHOT_DEADLINE:-90}"

## HiDPI capture: render every shot at SHOT_SCALE x device resolution so the published webp
## stays crisp when a browser upscales it on a HiDPI/Retina display (a 1x shot was blurry
## both on-page and opened fullscreen). The whole SITE already follows the 2x-source /
## display-1x convention (logo/icons/badges); the shots were the one 1x exception. It is applied
## ONCE, at the source: the labwc headless OUTPUT is set to scale SHOT_SCALE (wl_headless_start
## --output-scale), so native Wayland clients (secure-terminal, konsole, qterminal, alacritty,
## kitty, the VTE terminals) AND labwc's own SSD title bar render at SHOT_SCALE x device px for
## the SAME logical layout automatically, and labwc scales its Xwayland clients (xterm/urxvt/st)
## the same. grim grabs the physical (scaled) pixels. So all geometry here stays LOGICAL (px() is
## the identity); no per-client scale env. The character GRID (cols x rows) is unchanged -- only
## the pixels-per-cell doubles -- so payload sizing and the toolbar tier are preserved. On-page
## the shots keep their size (CSS width:100%); the committed <img> width/height become the new
## raster dims (= raster; the browser never upscales them).
SHOT_SCALE="${SHOT_SCALE:-2}"
## Reject empty, non-digit, AND any leading zero: a leading-zero value (0, 00, 08, 09) is
## read as OCTAL in bash arithmetic below -- 00 -> a 0 scale, 08/09 -> a fatal "value too
## great for base" abort. '0*' rejects the whole leading-zero class in one pattern.
case "${SHOT_SCALE}" in
   ''|*[!0-9]*|0*)
      printf '%s\n' "comparison-capture: SHOT_SCALE must be a positive integer with no leading zero, got '${SHOT_SCALE}'" >&2
      exit 2
      ;;
esac
## Force base 10: '08'/'09' pass the all-digit check above but the arithmetic
## below reads them as OCTAL and dies ('value too great for base'). An accepted
## value must not abort the run later.
SHOT_SCALE=$(( 10#${SHOT_SCALE} ))
## Exported so child scripts inherit the same factor: gnome-launch.sh --hero (hero cell size)
## and the --jobs lanes / re-capture net / ST pass (which re-exec this script).
export SHOT_SCALE
## Xft DPI for the Xwayland (X11-only) emulators. Base 96 (NOT x SHOT_SCALE): labwc applies the
## output SCALE to Xwayland clients too, so a base-DPI font is already rendered at SHOT_SCALE x
## device pixels -- multiplying here would double-scale (4x).
XFT_BASE_DPI=96
xft_dpi="${XFT_BASE_DPI}"

## Optional scope filters (a FAST PATH for iteration; the FULL matrix is the default, so a bare
## run never silently skips anything). --only NAME restricts the emulators (repeatable); --case C
## restricts the cases in BOTH loops (repeatable); --st-only skips the emulators; --quick is a
## smoke shortcut. The full case list is the single source of truth for both loops.
## notify is a secure-terminal-only case (emulators have no standard notify shot -- the page's
## kitty.notify popup is captured separately), so it is in the full matrix for the ST loop but
## skipped in the emulator loop below.
all_cases='escape contrast title random homoglyph bidi zerowidth altscreen notify art gradient unicode tui-showcase hero-compare'
CASES="${CASES:-${all_cases}}"
## The emulator set, single source of truth for BOTH the capture loop and the --jobs
## orchestrator's partition. lxterminal is omitted: its single-instance startup maps no
## window headless.
DEFAULT_TERMINALS='xterm urxvt st konsole gnome-terminal xfce4-terminal mate-terminal qterminal alacritty kitty'
only_terminals=''
cases_sel=''
st_only=''

## Reject an unknown --case/--only value (a typo, or a glob like '*' that would otherwise
## word-split-glob the $HOME payload files through the unquoted `for c in ${CASES}` loops).
## Literal membership: the known list holds only fixed names so `for k in $2` never globs, and
## `[ "$k" = "$1" ]` compares the user value verbatim (a '*' equals no real case name).
_known() {  ## $1=value $2=space-separated known list
   local k
   for k in ${2}; do
      [ "${k}" = "${1}" ] && return 0
   done
   return 1
}
## --zoom-live: the real-GUI live-zoom diagnostic sweep (see zoom_live_capture). Single-lane,
## secure-terminal-only; any trailing args are the zoom-level list (default band otherwise).
zoom_live=''
## Set when a colour board WRAPPED (board-wrap-check.py rejected it): the striped shot is
## discarded, but the whole capture must then exit NON-ZERO -- a discarded-but-green run reads as
## success with a required shot silently missing/stale. Carried to the final exit below.
board_wrap_failed=''
## Carried as an ARRAY (never a space-joined string) so a glob-looking level (`*`) reaches
## zoom_live_capture as a literal token instead of expanding against the cwd at the call site.
zoom_live_levels=()
## --jobs N (N>1): orchestrator mode -- partition the grid across N concurrent lanes, each with
## its OWN private headless labwc compositor (no host X; the per-lane bringup is flock-serialized
## in wl_headless_start so the shared Xwayland dir does not race), then optimize once. --no-st
## skips the secure-terminal pass (for an emulator-only lane); --optimize-only just webp-converts
## existing PNGs (the orchestrator's final merge step); --no-optimize leaves PNGs for that merge.
jobs=1
no_st=''
no_optimize=''
optimize_only=''
## --prep-dir DIR: a lane copies its payloads + icon theme from DIR (pre-generated ONCE by the
## orchestrator) instead of running reproduce.py + rasterising the icon itself. Removes the
## redundant, memory-spiking per-lane setup that OOM-killed a lane at higher --jobs.
prep_dir=''
while [ "$#" -gt 0 ]; do
   case "$1" in
      --only)
         [ "$#" -ge 2 ] || { printf '%s\n' 'comparison-capture: --only needs a terminal name' >&2; exit 2; }
         _known "$2" "${DEFAULT_TERMINALS}" || { printf '%s\n' "comparison-capture: --only: unknown terminal '${2}' (known: ${DEFAULT_TERMINALS})" >&2; exit 2; }
         only_terminals="${only_terminals:+${only_terminals} }$2"
         shift 2
         ;;
      --case)
         [ "$#" -ge 2 ] || { printf '%s\n' 'comparison-capture: --case needs a case name' >&2; exit 2; }
         _known "$2" "${all_cases}" || { printf '%s\n' "comparison-capture: --case: unknown case '${2}' (known: ${all_cases})" >&2; exit 2; }
         cases_sel="${cases_sel:+${cases_sel} }$2"
         shift 2
         ;;
      --st-only)
         st_only='true'
         shift
         ;;
      --zoom-live)
         ## Single-lane, secure-terminal-only real-GUI live-zoom sweep. st_only empties the
         ## emulator list, so only the zoom_live_capture branch runs. Any trailing args are the
         ## zoom levels; consume the rest and stop parsing.
         zoom_live='true'
         st_only='true'
         shift
         zoom_live_levels=("$@")
         break
         ;;
      --quick)
         only_terminals='kitty'
         cases_sel='escape'
         shift
         ;;
      --jobs)
         [ "$#" -ge 2 ] || { printf '%s\n' 'comparison-capture: --jobs needs a count' >&2; exit 2; }
         jobs="$2"
         shift 2
         ;;
      --no-st)
         no_st='true'
         shift
         ;;
      --no-optimize)
         no_optimize='true'
         shift
         ;;
      --optimize-only)
         optimize_only='true'
         shift
         ;;
      --prep-dir)
         [ "$#" -ge 2 ] || { printf '%s\n' 'comparison-capture: --prep-dir needs a directory' >&2; exit 2; }
         prep_dir="$2"
         shift 2
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

## Reject empty, non-digit, AND any leading zero: `0` divides by zero in `$(( idx % jobs ))`
## below, and a leading-zero value (08/09) is read as OCTAL by that arithmetic and aborts under
## errexit -- the same class the SHOT_SCALE validation rejects with `0*`.
case "${jobs}" in
   ''|*[!0-9]*|0*)
      printf '%s\n' "comparison-capture: --jobs must be a positive integer with no leading zero, got '${jobs}'" >&2
      exit 2
      ;;
esac

## --zoom-live is a single-lane real-GUI diagnostic (it drives ONE running instance over ctl) with
## no grid to partition, and its dispatch (far below) runs only after the --jobs orchestrator has
## already exited. --jobs parsed before --zoom-live on the command line leaves both set, which
## would silently run the full parallel matrix and ignore the requested zoom sweep. Reject it.
if [ -n "${zoom_live}" ] && [ "${jobs}" -gt 1 ]; then
   printf '%s\n' "comparison-capture: --zoom-live is single-lane; do not combine it with --jobs ${jobs}" >&2
   exit 2
fi

## --optimize-only: webp-convert the PNGs already in ${out} and stop (the orchestrator's
## single final merge, after its --no-optimize lanes finished). No capture, no runtime dir.
if [ -n "${optimize_only}" ]; then
   safe-rm --recursive --force -- "${runtime_dir}" 2>/dev/null || true
   shots_optimize_to_webp "${out}"/*.png
   printf '%s\n' "optimized; webp in ${out}"
   exit 0
fi

## --jobs N (N>1): orchestrator. Partition the grid across N concurrent lanes, each a full
## comparison-capture.sh run over a scope subset in its OWN private headless labwc compositor (no
## host X; the bringup + Xwayland-socket discovery is flock-serialized in wl_headless_start, so
## concurrent lanes do not race the shared X socket dir). The capture code is reused UNCHANGED;
## only the work is split. A final --optimize-only pass webp-converts
## once, so concurrent lanes never race on the shared shots dir's optimize step.
if [ "${jobs}" -gt 1 ]; then
   self="${here}/comparison-capture.sh"
   ## the runtime dir this orchestrator made is unused -- each lane makes its own.
   safe-rm --recursive --force -- "${runtime_dir}" 2>/dev/null || true
   fwd_case=()
   for fc in ${cases_sel}; do fwd_case+=(--case "${fc}"); done
   if [ -n "${st_only}" ]; then
      emu_set=''
   elif [ -n "${only_terminals}" ]; then
      emu_set="${only_terminals}"
   else
      emu_set="${DEFAULT_TERMINALS}"
   fi
   ## Pre-generate the payloads + icon theme ONCE into a shared dir; lanes copy from it via
   ## --prep-dir instead of each running reproduce.py + rasterising the icon (the concurrent,
   ## memory-spiking setup that OOM-killed a lane). Not in dry-run (no capture happens).
   orch_prep=''
   if [ -z "${SHOTS_LANE_DRY_RUN:-}" ]; then
      orch_prep="$(mktemp --directory)"
      export XDG_DATA_HOME="${orch_prep}/data"
      shots_generate_logs "${here}" "${orch_prep}" || exit "$?"
      shots_install_icon_theme "${orch_prep}/data"
   fi
   lane_dir="$(mktemp --directory)"
   lane_pids=()
   lane_logs=()
   lane_i=0
   ## Stagger emulator-lane startup so their (brief) compositor-bringup phases do not all peak at
   ## once; the long capture phase still overlaps fully.
   lane_stagger="${SHOTS_LANE_STAGGER:-6}"
   case "${lane_stagger}" in
      ''|*[!0-9]*)
         printf '%s\n' "comparison-capture: SHOTS_LANE_STAGGER must be a non-negative integer (got '${lane_stagger}')" >&2
         exit 2
         ;;
   esac
   spawn_lane() {  ## $@ = args forwarded to a comparison-capture.sh lane
      local log prep_args
      log="${lane_dir}/lane.${lane_i}.log"
      ## SHOTS_LANE_DRY_RUN: print the lane's scope instead of running it, to verify the
      ## partition (which emulators / ST / cases each lane gets) without a capture.
      if [ -n "${SHOTS_LANE_DRY_RUN:-}" ]; then
         printf '%s\n' "LANE ${lane_i}:$(printf ' %s' "$@") --no-optimize"
         lane_i=$(( lane_i + 1 ))
         return 0
      fi
      prep_args=()
      [ -n "${orch_prep}" ] && prep_args=(--prep-dir "${orch_prep}")
      [ "${lane_i}" -gt 0 ] && sleep "${lane_stagger}"
      ## Each lane brings up its OWN private headless labwc (no host X, no xvfb-run). Concurrent
      ## labwc share the protocol-fixed /tmp/.X11-unix; wl_headless_start serializes just the
      ## per-lane compositor bringup + Xwayland-socket discovery under a flock, so a lane's X11-only
      ## trio (xterm/urxvt/st) cannot bind another lane's compositor. Captures then run in parallel.
      "${self}" "$@" "${prep_args[@]}" --no-optimize >"${log}" 2>&1 &
      lane_pids+=("$!")
      lane_logs+=("${log}")
      lane_i=$(( lane_i + 1 ))
   }
   rc=0
   wait_lanes() {  ## wait for all currently-spawned lanes; echo their logs
      ## A lane's exit code is NOT folded into the run's rc: under --jobs load a lane can die
      ## transiently (labwc bringup racing) yet every shot it lost is re-shot by the sequential
      ## re-capture net below. The AUTHORITATIVE emulator-phase verdict is that net's final
      ## missing-check (a genuinely absent terminal is caught by the installed-check there), so a
      ## fully-recovered grid exits 0 and the shots are pulled -- a transient lane failure alone
      ## must not fail the whole run. A non-zero lane is noted for visibility only.
      local i lrc
      i=0
      while [ "${i}" -lt "${#lane_pids[@]}" ]; do
         lrc=0
         wait "${lane_pids[i]}" || lrc="$?"
         cat -- "${lane_logs[i]}" 2>/dev/null || true
         [ "${lrc}" -eq 0 ] || printf '%s\n' "note: an emulator lane exited ${lrc} (transient under --jobs load; the re-capture net backstops any missing shot)"
         i=$(( i + 1 ))
      done
      lane_pids=()
      lane_logs=()
   }
   ## PHASE 1: the emulators, in ${jobs} parallel lanes (they tolerate CPU contention).
   if [ -n "${emu_set}" ]; then
      bucket=()
      idx=0
      for e in ${emu_set}; do
         b=$(( idx % jobs ))
         bucket[b]="${bucket[b]:+${bucket[b]} }${e}"
         idx=$(( idx + 1 ))
      done
      b=0
      while [ "${b}" -lt "${jobs}" ]; do
         if [ -n "${bucket[b]:-}" ]; then
            only_args=()
            for e in ${bucket[b]}; do only_args+=(--only "${e}"); done
            spawn_lane "${only_args[@]}" --no-st "${fwd_case[@]}"
         fi
         b=$(( b + 1 ))
      done
      wait_lanes
   fi
   ## PHASE 1.5: sequential re-capture net for the emulator pass. Under parallel CPU load a lane
   ## can screenshot an emulator window before its content paints; capture_settled DISCARDS that
   ## blank (never publishes black), so a discarded shot leaves no file and a full reshoot would
   ## omit it -- the residual "manual per-emulator re-run" problem. With every parallel lane now
   ## finished (zero CPU contention -- the condition under which a sequential re-run reliably
   ## succeeds), re-shoot any still-missing emulator shot SEQUENTIALLY, one compositor at a time,
   ## like the ST pass. Bounded rounds; anything still missing after the net is a HARD failure
   ## (rc=1), never a silent stale shot.
   if [ -n "${emu_set}" ] && [ -z "${SHOTS_LANE_DRY_RUN:-}" ]; then
      ## only INSTALLED emulators are expected to yield shots. A genuinely ABSENT emulator is a
      ## hard error here (an incomplete grid misrepresents the comparison) unless ALLOW_SKIP
      ## authorizes it -- the same rule the per-lane loop enforces, restated here because lane
      ## exit codes are no longer folded into rc (a transient labwc failure must not fail the run,
      ## but a missing terminal must). Only the installed set is chased by the net below.
      emu_present=''
      for e in ${emu_set}; do
         e_path="$(type -P "${e}" 2>/dev/null || true)"
         if [ -n "${e_path}" ] && [ -x "${e_path}" ]; then
            emu_present="${emu_present:+${emu_present} }${e}"
         elif [ -n "${ALLOW_SKIP:-}" ]; then
            printf '%s\n' "SKIP ${e} (not installed/executable; ALLOW_SKIP authorized)" >&2
         else
            printf '%s\n' "ERROR: emulator ${e} is not installed/executable; install it or set ALLOW_SKIP=1" >&2
            rc=1
         fi
      done
      recap_prep=()
      [ -n "${orch_prep}" ] && recap_prep=(--prep-dir "${orch_prep}")
      recap_round=0
      while [ "${recap_round}" -lt 3 ]; do
         mapfile -t recap_missing < <(shots_missing_emulator_shots "${out}" "${emu_present}" "${CASES}")
         [ "${#recap_missing[@]}" -eq 0 ] && break
         printf '%s\n' "re-capture net (round $(( recap_round + 1 ))): ${#recap_missing[@]} emulator shot(s) missing after the parallel pass; re-shooting sequentially"
         for pair in "${recap_missing[@]}"; do
            read -r re_e re_c <<< "${pair}"
            ## A re-shoot may itself exit non-zero (labwc bringup can still flake) -- its rc is
            ## NOT folded into the run's rc. Whether the shot now exists is decided by the
            ## authoritative missing-check after the rounds; a shot still absent then fails hard.
            "${self}" --only "${re_e}" --case "${re_c}" --no-st "${recap_prep[@]}" --no-optimize \
               > "${lane_dir}/recap.${re_e}.${re_c}.log" 2>&1 || true
            cat -- "${lane_dir}/recap.${re_e}.${re_c}.log" 2>/dev/null || true
         done
         recap_round=$(( recap_round + 1 ))
      done
      mapfile -t recap_missing < <(shots_missing_emulator_shots "${out}" "${emu_present}" "${CASES}")
      if [ "${#recap_missing[@]}" -gt 0 ]; then
         printf '%s\n' "ERROR: ${#recap_missing[@]} emulator shot(s) STILL missing after the re-capture net:" >&2
         for pair in "${recap_missing[@]}"; do
            printf '%s\n' "   ${pair}" >&2
         done
         rc=1
      else
         printf '%s\n' "re-capture net: emulator grid complete, 0 shots missing"
      fi
   fi
   ## PHASE 2: the secure-terminal pass, run SEQUENTIALLY and ALONE. Each ST spec is a fresh Qt
   ## '--new-instance' cold start; when it competes with the emulator captures (or other ST
   ## launches) for CPU its render is starved and the shot comes out blank. Running ST after the
   ## emulator phase, one launch at a time, is what keeps it reliable. (A --st-only request skips
   ## phase 1 and runs only this.)
   if [ -z "${SHOTS_LANE_DRY_RUN:-}" ]; then
      st_prep=()
      [ -n "${orch_prep}" ] && st_prep=(--prep-dir "${orch_prep}")
      st_rc=0
      "${self}" --st-only "${fwd_case[@]}" "${st_prep[@]}" --no-optimize \
         > "${lane_dir}/st.log" 2>&1 || st_rc="$?"
      cat -- "${lane_dir}/st.log" 2>/dev/null || true
      [ "${st_rc}" -eq 0 ] || rc="${st_rc}"
   else
      printf '%s\n' "LANE st(sequential): --st-only$(printf ' %s' "${fwd_case[@]}") --no-optimize"
   fi
   safe-rm --recursive --force -- "${lane_dir}" 2>/dev/null || true
   if [ -n "${orch_prep}" ]; then
      safe-rm --recursive --force -- "${orch_prep}" 2>/dev/null || true
   fi
   "${self}" --optimize-only || true
   printf '%s\n' "done; emulators parallel + secure-terminal sequential; shots in ${out}"
   exit "${rc}"
fi

## Reliable reaping REQUIRES the safe-pgrep/safe-pkill wrappers -- fail loudly, never fall back.
shots_require_safe_ps || exit 1
## Pre-clean: reap orphaned groups left by any PRIOR crashed run (marker-scoped -- it can never
## touch a process lacking that run's unique marker), then register this run.
shots_reap_registered || true
shots_register_run "${run_marker}"

## Attack payloads come from the terminal-poc-corpus (single source of truth), decoded
## by its reproduce.py. shots_generate_logs resolves the checkout and returns
## non-zero when the corpus is absent or a payload-generation fails; propagated
## here as a hard failure so a missing corpus or broken reproduce.py is not a skip.
export XDG_DATA_HOME="${runtime_dir}/data"
mkdir --parents -- "${XDG_DATA_HOME}"
if [ -n "${prep_dir}" ]; then
   ## Lane: reuse the orchestrator's pre-generated payloads + icon theme. COPY (not symlink) the
   ## payloads so this lane can strip its own tui-showcase copy without mutating the shared one.
   cp -- "${prep_dir}"/*.payload "${HOME}/" || exit 1
   if [ -d "${prep_dir}/data" ]; then
      cp --recursive -- "${prep_dir}/data/." "${XDG_DATA_HOME}/" 2>/dev/null || true
   fi
else
   ## Attack payloads come from the terminal-poc-corpus (single source of truth), decoded by its
   ## reproduce.py; secure-terminal's icon is rasterised into the session icon theme so labwc
   ## shows the real title-bar logo.
   shots_generate_logs "${here}" "${HOME}" || exit "$?"
   shots_install_icon_theme "${XDG_DATA_HOME}"
fi
## The shell prompt for every shot. Single-sourced so the content-verify
## (shots_transcript_has_content) strips the EXACT prompt the shell prints when
## deciding whether an injected payload actually rendered.
SHOT_PROMPT='user@host:~$ '
cat > "${HOME}/.strc" <<RC
PS1='${SHOT_PROMPT}'
RC
## secure-terminal launches a clean `bash -i` (no ugly temp --rcfile path in its launch
## banner); a non-login interactive bash reads ~/.bashrc, so write the same prompt there.
## The emulators keep --rcfile ${HOME}/.strc (that path is their reaping marker); ST carries the
## marker via the SHOTS_RUN_MARKER env instead (see the ST launch), so its banner stays clean AND
## the shots never stamp a per-run temp path on ST's Wayland app-id. secure-terminal sets its own
## app-id (`secure-terminal`, via setDesktopFileName) idiomatically, so labwc resolves the real
## titlebar icon with no identity flag from the shots (a temp path there would force the fallback).
cat > "${HOME}/.bashrc" <<RC
PS1='${SHOT_PROMPT}'
RC

## launch each emulator FROM ${HOME} so a plain "cat escape.payload" finds it.
cd "${HOME}"

## start_labwc (wl_headless_start) sets these for real; init here so an early exit / the
## cleanup trap reads them safely under `set -u`. The compositor's SSD title bar (where an
## OSC-0 hijack shows) and its font are drawn at the output SCALE, so no per-font pt scaling.
xwl_display=''
## wm_pid + the cleanup trap are set far above (right after the runtime dir), so an early
## argument-validation exit cannot leak it; wm_pid is re-set for real when the WM starts.

## labwc intermittently fails to come up under the parallel --jobs load (its wlroots x11
## backend racing several nested compositors) -- the single dominant cause of lost shots in a
## full --jobs run. Retry its bringup a few times, killing a half-started instance first so the
## next attempt starts clean. The orchestrator's re-capture net is the outer backstop, but
## retrying here removes most of its work (and most of the transient lane failures).
labwc_started=''
for labwc_try in 1 2 3 4; do
   if start_labwc; then
      labwc_started=1
      break
   fi
   [ -z "${wm_pid}" ] || kill "${wm_pid}" 2>/dev/null || true
   [ -z "${wm_pid}" ] || wait "${wm_pid}" 2>/dev/null || true
   wm_pid=''
   printf '%s\n' "labwc bringup attempt ${labwc_try} failed; retrying" >&2
   sleep 1
done
if [ -z "${labwc_started}" ]; then
   printf '%s\n' 'labwc did not start after retries; log:'; tail -6 "${runtime_dir}/labwc.log"; exit 1
fi
## Name the discovered displays once, up front: a lost trio shot (xterm/urxvt/st, the only
## Xwayland clients) is almost always an empty/undiscovered WL_XWAYLAND_DISPLAY -- surface it so
## the failure is diagnosable rather than a bare "window never appeared".
printf '%s\n' "labwc up: WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-} WL_XWAYLAND_DISPLAY=[${xwl_display}]" >&2

## zoom-live: real-GUI live-zoom sweep -- one ST launch, zoom stepped via `ctl zoom` on the SAME
## instance. Runs here (labwc up, HOME/.strc + payloads + icon theme prepared, trap armed) and
## exits; the EXIT trap reaps the run + removes the throwaway remote_control drop-in. Skips the
## emulator grid and the multi-spec ST loop below entirely.
if [ -n "${zoom_live}" ]; then
   cd "${HOME}"
   st_bin="${ST_REPO:-}/usr/bin/secure-terminal"
   st_pkg="${ST_REPO:-}/usr/lib/python3/dist-packages"
   if [ -z "${ST_REPO:-}" ] || [ ! -f "${st_bin}" ]; then
      printf '%s\n' 'ERROR: zoom-live needs secure-terminal. Set ST_REPO=/path/to/checkout.' >&2
      exit 1
   fi
   ## Levels pass as a quoted array (no word-splitting/globbing). Propagate the lane's real verdict:
   ## a failed sweep (no-op zoom, unreachable ctl, zero shots) must exit NONZERO, not a hardcoded 0.
   zoom_live_rc=0
   zoom_live_capture "${zoom_live_levels[@]}" || zoom_live_rc="$?"
   exit "${zoom_live_rc}"
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
   TERMINALS="${TERMINALS:-${DEFAULT_TERMINALS}}"
fi
## read -ra splits on whitespace WITHOUT globbing, so an exported CASES='*' / TERMINALS='*'
## (the env path, which bypasses the --case/--only membership guard) stays literal here
## instead of glob-expanding the $HOME payload files through these unquoted loops.
read -ra _terminals_arr <<< "${TERMINALS}"
read -ra _cases_arr <<< "${CASES}"
for e in "${_terminals_arr[@]}"; do
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
   for c in "${_cases_arr[@]}"; do
      ## notify + art are secure-terminal showcases, not attack comparisons: notify has no
      ## standard emulator shot (kitty's popup is captured separately), and art is a capability
      ## demo of secure-terminal's own truecolor rendering across its modes. Skip both in the
      ## emulator loop even though they are in the full ST matrix. SHOTS_EMULATOR_SKIP_CASES
      ## (lib-capture.sh) is the single source of truth, shared with the re-capture net's
      ## expected-shot accounting so the two never drift.
      case "${SHOTS_EMULATOR_SKIP_CASES}" in *" ${c} "*) continue ;; esac
      shoot "${e}" "${c}" || true
   done
   printf '%s\n' "captured ${e}"
done

## tui-showcase board: its embedded 'cat tui-showcase.payload' line is what puts 'cat' at the
## top of an ALT-SCREEN shot (the alt screen hides the real typed command). secure-terminal in
## CLI mode renders the board INLINE and shows the REAL typed prompt, so there the embedded line
## would DUPLICATE it -- so tui-showcase.payload is stripped IN PLACE for the CLI specs (they cat
## it by its clean name, and the real echo reads 'cat tui-showcase.payload'). secure-terminal in
## TUI mode enters the alt screen just like the emulators, so it needs the WITH-prompt board:
## saved first as a sibling (tui-showcase-withprompt.payload). Its real echo (the sibling's name)
## is hidden by the alt screen; the board's EMBEDDED clean-name prompt is what shows at the top.
## shots_st_inject_cmd picks the right one per mode. An emulator-only lane (--no-st) skips both
## the strip and the whole secure-terminal pass. Strip via the dedicated sibling script (not
## inline scripting).
if [ -n "${no_st}" ]; then
   printf '%s\n' 'skipping secure-terminal pass (--no-st)'
else
cp -- "${HOME}/tui-showcase.payload" "${HOME}/tui-showcase-withprompt.payload"
"${here}/strip-tui-showcase-prompt.py" "${HOME}/tui-showcase.payload"

st_bin="${ST_REPO:-}/usr/bin/secure-terminal"
st_pkg="${ST_REPO:-}/usr/lib/python3/dist-packages"
if [ -n "${ST_REPO:-}" ] && [ -f "${st_bin}" ]; then
   ## Enable remote_control for the whole ST pass via a throwaway privileged drop-in (removed on
   ## exit by cleanup()), so each per-case window can be driven by `ctl send-text --submit` -- a
   ## real remote-control command run, not xdotool key-injection into a possibly-unfocused window.
   rc_dropin="$(shots_rc_dropin_create comparison-rc)" || {
      printf '%s\n' 'warn secure-terminal: cannot create the privileged remote_control drop-in (sudo?) -- ctl send-text will fail' >&2
   }
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
   ## Device px = logical 860 x SHOT_SCALE (re-set per-spec in the loop below).
   st_win_w="$(px 860)"
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
      'escape box escape'
      'escape detail escape-detail'
      'escape show escape-show'
      'escape box escape-tui tui'
      'escape show escape-tui-show tui'
      'contrast box contrast'
      'contrast detail contrast-detail'
      'contrast show contrast-show'
      'contrast box contrast-tui tui'
      'contrast show contrast-tui-show tui'
      'title box title'
      'title detail title-detail'
      'title show title-show'
      'title box title-tui tui'
      'title show title-tui-show tui'
      'notify box notify'
      'notify detail notify-detail'
      'notify show notify-show'
      'notify box notify-tui tui'
      'notify show notify-tui-show tui'
      ## art + gradient are full-viewport colour boards that differ ONLY in their colours,
      ## so the NEUTRALISED views (Box / Detail, CLI and TUI) reduce both to byte-identical
      ## output -- the colour that told them apart is exactly what those views strip. Capture
      ## those once as a shared, board-agnostic "colorboard" shot (from the art payload), not
      ## once per board (that committed two identical files). Only the SHOW views, which paint
      ## the real colours, differ, so keep those per board.
      'art box colorboard'
      'art detail colorboard-detail'
      'art box colorboard-tui tui'
      'art show art-show'
      'art show art-tui-show tui'
      'gradient show gradient-show'
      'gradient show gradient-tui-show tui'
      'unicode show unicode-show'
      'unicode show unicode-tui-show tui'
      'unicode detail unicode-detail'
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
      ## hero-compare: the homepage before/after slider. Captured in SHOW mode only (the
      ## page shows content AND flags danger) -- the one secure-terminal view the hero
      ## slider overlays against the traditional-emulator shot of the SAME board.
      'hero-compare show hero-compare-show'
   )
   ## Cold-start warmup: the FIRST secure-terminal launch in a lane, under parallel --jobs
   ## contention, has been observed to never paint the spec it captures (a black shot) even after
   ## a long wait -- the first launch pays for building fontconfig / Qt / icon caches. Prime the
   ## app with ONE throwaway launch (waited-on, then killed) so every real spec below is warm.
   warm_pgf="$(mktemp -- "${runtime_dir}/pgid.XXXXXX")"
   shots_spawn_session "${warm_pgf}" \
      env "SHOTS_RUN_MARKER=${run_marker}" QT_QPA_PLATFORM=wayland \
      QT_FONT_DPI=72 SECURE_TERMINAL_SHOT=1 SHELL=/bin/bash \
      PYTHONPATH="${st_pkg}" "${st_bin}" --new-instance --mode box >/dev/null 2>&1
   warm_wid="$(find_window || true)"
   [ -n "${warm_wid}" ] && wait_window_ready "${warm_wid}"
   shots_reap_group "$(cat "${warm_pgf}" 2>/dev/null || true)"
   safe-rm --force -- "${warm_pgf}" 2>/dev/null || true

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
      st_win_h="$(px 620)"; [ "${st_case}" = tui-showcase ] && st_win_h="$(px 820)"
      ## hero-compare: use the shared HERO_WIN_W_BASE width (narrower than the 860 comparison
      ## default) so the homepage slider shot scales to a ~390px phone with legible text and the
      ## board fills the frame. The SAME constant pins the gnome-terminal hero window (shoot()),
      ## so the two are identical horizontal length and overlay perfectly. This width still lands
      ## in the labeled toolbar tier (captioned chips, no ">>" overflow) at 72-DPI metrics;
      ## RE-MEASURE if the toolbar/chip CSS changes.
      st_win_w="$(px 860)"; [ "${st_case}" = hero-compare ] && st_win_w="$(px "${HERO_WIN_W_BASE}")"
      ## The GUI runs as `python3 .../secure-terminal` -- process name `python3` -- so it MUST
      ## be reaped by its session PGID, never by name. Launch it in its own session and arm the
      ## per-capture watchdog, exactly like the emulator shots.
      st_pgf="$(mktemp -- "${runtime_dir}/pgid.XXXXXX")"
      st_flagf="${st_pgf}.timeout"
      ## secure-terminal writes its live transcript here (fresh per spec) via the generic
      ## SECURE_TERMINAL_TRANSCRIPT_FILE config. Read after the grab to VERIFY the injected
      ## payload actually rendered -- a screenshot cannot tell an empty terminal from a
      ## full one (the window chrome paints either way).
      st_transcript="${st_pgf}.transcript"
      safe-rm -f -- "${st_transcript}" 2>/dev/null || true
      ## A UNIQUE instance group per launch (from the unique pgid file) so this window is the group
      ## PRIMARY and claims its OWN ctl socket: `ctl send-text --submit` (below) drives THIS window.
      ## A --new-instance standalone claims no socket (ctl could not reach it); a unique group also
      ## avoids socket reuse across the sequential captures.
      st_group="cmp-$(basename -- "${st_pgf}")"
      ## Pin the font DPI to 72 so the render is deterministic. The responsive toolbar's 860
      ## default (st_win_w) is calibrated to the compositor's ~9pt/72-DPI metrics (labeled tier:
      ## captioned chips, no ">>" overflow) -- the same font-metric determinism the test runner
      ## pins for the tier assertions. SECURE_TERMINAL_SHOT=1: deterministic screenshot mode (caret
      ## hidden + synchronous render) so the shot is byte-reproducible run-to-run; set on the
      ## secure-terminal GUI launch ONLY, never on the competitor terminals. NO QT_SCALE_FACTOR: the
      ## compositor OUTPUT SCALE (SHOT_SCALE) already renders the whole Qt UI at 2x device px for the
      ## SAME logical layout, so st_win_w stays LOGICAL and still lands in the labeled toolbar tier.
      ## Size the window on MAP via a labwc windowRule keyed on secure-terminal's Wayland app_id
      ## (native Wayland has no external post-launch resize); reconfigures labwc before the launch.
      set_window_rule secure-terminal "${st_win_w}" "${st_win_h}"
      shots_spawn_session "${st_pgf}" \
         env "SHOTS_RUN_MARKER=${run_marker}" QT_QPA_PLATFORM=wayland \
         QT_FONT_DPI=72 SECURE_TERMINAL_SHOT=1 SHELL=/bin/bash \
         "SECURE_TERMINAL_TRANSCRIPT_FILE=${st_transcript}" \
         PYTHONPATH="${st_pkg}" "${st_bin}" --instance-group "${st_group}" "${st_mode_flags[@]}" >/dev/null 2>&1
      ## same guard as the emulator shots: an invalid SHOT_DEADLINE must not errexit-abort.
      st_wdog="$(shots_watchdog_start "${SHOT_DEADLINE}" "${st_pgf}" "${st_flagf}")" || st_wdog=''
      stwid="$(find_window || true)"
      if [ -n "${stwid}" ]; then
         ## Window is sized on map by the windowRule above. Qt cold start: wait until the app has
         ## actually painted its prompt before typing, or the 'cat' is injected into a not-yet-ready
         ## window and never runs (a black shot, seen on the FIRST launch under parallel --jobs load).
         wait_window_ready "${stwid}"
         ## The command to inject (mode-aware; see shots_st_inject_cmd). secure-terminal now
         ## pins the alternate screen to the top (as a real terminal does), so a short
         ## alt-screen frame (the altscreen demo's one line) stays visible even when the
         ## shell's prompt returns below it.
         st_cmd="$(shots_st_inject_cmd "${st_case}" "${st_tui:-}")"
         ## Discover the target tab id via `ctl ls` (first tab-separated field), retrying briefly
         ## until ctl is reachable (remote_control on + the primary socket claimed). No tab means
         ## the drop-in did not apply; the verify loop then discards the empty shot and warns.
         st_tab_id=''
         for _ct_try in 1 2 3 4 5; do
            st_tab_line="$(env PYTHONPATH="${st_pkg}" "${st_bin}" \
               ctl --instance-group "${st_group}" ls 2>/dev/null | head -1 || true)"
            st_tab_id="$(printf '%s' "${st_tab_line}" | cut -f1)"
            [ -n "${st_tab_id}" ] && break
            sleep 0.6
         done
         [ -n "${st_tab_id}" ] || printf '%s\n' "warn secure-terminal.${st_suffix}: ctl ls found no tab (remote_control off / not primary) -- shot may be empty" >&2
         ## Inject, grab, and VERIFY via the transcript file that the payload actually
         ## rendered; re-inject + re-grab on an empty transcript, and DISCARD (never
         ## publish an empty shot) if it never lands. The transcript catches an injection
         ## that never reached the window (a focus race under --jobs load) -- the shell is
         ## back at its prompt in that case, so a re-inject runs cleanly.
         st_verify_tries=0
         while : ; do
            ## Clear the transcript at the START of each attempt so the content check reflects
            ## THIS injection only -- else a prior attempt that rendered content but whose grab
            ## was discarded could leave stale content that validates a later empty grab.
            safe-rm -f -- "${st_transcript}" 2>/dev/null || true
            ## Run the demo command via REMOTE CONTROL: ctl send-text --submit types it AND presses
            ## Enter on the discovered tab (a real command run), replacing xdotool key-injection into
            ## a possibly-unfocused window. Single-line `cat X.payload`, so --submit accepts it.
            env PYTHONPATH="${st_pkg}" "${st_bin}" \
               ctl --instance-group "${st_group}" send-text --tab "id:${st_tab_id:-0}" --submit "${st_cmd}" \
               >/dev/null 2>&1 || true
            ## SECURE_TERMINAL_SHOT=1 renders synchronously, so a long fixed settle is unneeded.
            sleep 1
            ## The full-viewport colour boards paint a large grid (rows x cols cells rebuilt into the
            ## document) -- much heavier than a short attack payload, and capture_settled only rejects
            ## a BLANK frame, not a half-drawn one. In BOTH CLI and TUI, wait until the frame stops
            ## changing before the grab. (CLI too: it also grabs a partially-painted board otherwise.)
            ## These boards fill the viewport, so there is nothing for tighten_deadspace to trim, and
            ## its content/background boundary detection is non-deterministic on a board whose edge
            ## colour is near the terminal background (the gradient's near-white greyscale ramp on the
            ## light theme drifts the crop height by a row run-to-run). Skip tighten so the shot is the
            ## pinned window geometry -- deterministic dimensions, mode-agnostic (box/detail too).
            st_tighten_arg=''
            if [ "${st_case}" = art ] || [ "${st_case}" = gradient ]; then
               st_wait_render_settled "${stwid}"
               st_tighten_arg='skip-tighten'
            fi
            capture_settled "${out}/secure-terminal.${st_suffix}.png" "${stwid}" "${st_tighten_arg}"
            ## A shot passes once it exists AND the transcript carries real content (capture_settled
            ## discards a blank grab, leaving no file -- also a miss).
            if [ -f "${out}/secure-terminal.${st_suffix}.png" ] \
                  && shots_transcript_has_content "${st_transcript}" "${SHOT_PROMPT}"; then
               ## Colour boards (art/gradient) must fill the grid with NO hard-wrap: a board pinned
               ## wider than the live grid overflows into short continuation rows -- the striped
               ## shot. board-wrap-check.py reads the same transcript and fails (non-zero) if the
               ## board rendered ragged. Run in SHOW and BOX (the width-preserving modes) so BOTH
               ## the truecolour board AND the neutralised colorboard are covered -- each is a
               ## separate capture, so each striped shot is caught on its own; Detail expands each
               ## cell and flows by design, so it is not checked. Deterministic, so a wrap is NOT
               ## retried: discard + warn (the missing shot then trips the pages shot-inventory
               ## guard) and break.
               if { [ "${st_case}" = art ] || [ "${st_case}" = gradient ]; } \
                     && { [ "${st_mode}" = show ] || [ "${st_mode}" = box ]; } \
                     && ! "${here}/board-wrap-check.py" "${st_transcript}" \
                           --cols "${ST_BOARD_COLS}" --prompt "${SHOT_PROMPT}"; then
                  safe-rm --force -- "${out}/secure-terminal.${st_suffix}.png" 2>/dev/null || true
                  printf '%s\n' "warn secure-terminal.${st_suffix}: colour board WRAPPED (pinned ST_BOARD_COLS=${ST_BOARD_COLS} exceeds the live grid) -- discarded, not published; re-derive ST_BOARD_COLS in lib-capture.sh" >&2
                  board_wrap_failed=1
               fi
               break
            fi
            st_verify_tries=$(( st_verify_tries + 1 ))
            if [ "${st_verify_tries}" -ge 3 ]; then
               safe-rm --force -- "${out}/secure-terminal.${st_suffix}.png" 2>/dev/null || true
               printf '%s\n' "warn secure-terminal.${st_suffix}: injected content never rendered (transcript empty after ${st_verify_tries} tries) -- discarded, not published"
               break
            fi
            printf '%s\n' "warn secure-terminal.${st_suffix}: transcript still empty (attempt ${st_verify_tries}); re-injecting"
            sleep 1
         done
      else
         printf '%s\n' "warn secure-terminal.${st_suffix}: window never appeared"
      fi
      shots_watchdog_cancel "${st_wdog}"
      [ -e "${st_flagf}" ] && printf '%s\n' "warn secure-terminal.${st_suffix}: capture exceeded ${SHOT_DEADLINE}s deadline, group reaped"
      st_epgid="$(cat "${st_pgf}" 2>/dev/null || true)"
      shots_reap_group "${st_epgid}"
      safe-rm -f -- "${st_pgf}" "${st_flagf}" "${st_transcript}" 2>/dev/null || true
   done
   printf '%s\n' 'captured secure-terminal (real GUI)'
elif [ -n "${ALLOW_SKIP:-}" ]; then
   printf '%s\n' 'SKIP secure-terminal (ST_REPO not set/found; ALLOW_SKIP authorized)' >&2
else
   printf '%s\n' 'ERROR: secure-terminal not found. Set ST_REPO=/path/to/checkout, or set ALLOW_SKIP=1 to authorize skipping.' >&2
   exit 1
fi
fi

## Homepage hero slider: pad the secure-terminal + gnome-terminal hero-compare shots to one shared
## canvas so the site's CSS resize slider overlays them at identical dimensions. Before optimize, so
## the produced PNGs are webp-converted with the rest. Only when hero-compare was actually captured.
case " ${CASES} " in
   *' hero-compare '*)
      compose_hero_slider "${out}"
      ;;
esac

## Convert the captured PNGs to webp (the site references them as .webp). A lane run with
## --no-optimize leaves the PNGs for the orchestrator's single final --optimize-only merge.
if [ -z "${no_optimize}" ]; then
   shots_optimize_to_webp "${out}"/*.png
fi

## A wrapped colour board is a HARD failure of the run, not a warn: the striped shot was
## discarded (never published), so exiting 0 here would report success while a required shot is
## missing/stale. Fail loud so the pin gets re-derived and the shots regenerated.
if [ -n "${board_wrap_failed}" ]; then
   printf '%s\n' 'ERROR: colour board(s) WRAPPED -- pinned ST_BOARD_COLS exceeds the live secure-terminal grid; the striped shot(s) were discarded. Re-derive ST_BOARD_COLS in lib-capture.sh and re-run.' >&2
   exit 1
fi

printf '%s\n' "done; shots in ${out}"

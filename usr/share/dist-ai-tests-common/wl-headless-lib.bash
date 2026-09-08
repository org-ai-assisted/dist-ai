#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sourced-only fragment; a top-level strict-mode block would leak
## set -o errexit/nounset into the consumer (every caller already sets it).

## Single source for bringing up a private, headless Wayland compositor for tests and
## screenshot capture. SOURCE this file; it defines functions, sets nothing on load.
##
## The one idiomatic recipe: labwc (wlroots) on WLR_BACKENDS=headless + WLR_RENDERER=pixman
## (software, no GPU). Real compositor rendering -- unlike QT_QPA_PLATFORM=offscreen it has
## the full activation/decoration/input path -- so Qt/GTK clients render exactly as onscreen.
## Native Wayland clients connect to WAYLAND_DISPLAY; X11-only clients (xterm/urxvt/st) reach
## labwc's own Xwayland at WL_XWAYLAND_DISPLAY. grim (wlr-screencopy) captures the output.
##
## Callers:
##   wl-headless-run                 -- run one command against the compositor (Qt suites)
##   secure-terminal-shots capture   -- one compositor, many per-window grabs
##   setup-wizard / sdwdate-gui / private-ai-config headless-capture
##
## API (all set/export into the SOURCING shell):
##   wl_headless_start [--runtime DIR] [--icon-theme NAME]
##       Bring up labwc; export XDG_RUNTIME_DIR, WLR_BACKENDS, WLR_RENDERER, WAYLAND_DISPLAY,
##       WL_XWAYLAND_DISPLAY, XCURSOR_PATH/THEME/SIZE. Set WL_HEADLESS_LABWC_PID and
##       WL_HEADLESS_RUNTIME (+ WL_HEADLESS_RUNTIME_MINTED=1 if it minted the dir). The pointer
##       is hidden (transparent Xcursor) so a per-window trim crop is exact. With --icon-theme,
##       labwc resolves each window's titlebar favicon via that theme (app-id -> .desktop ->
##       Icon= -> theme). Returns non-zero (compositor log dumped to stderr) if no socket.
##   wl_headless_stop
##       Kill labwc; remove the runtime dir only if wl_headless_start minted it. Idempotent.
##   wl_headless_capture_window <outfile.png>
##       grim the whole output, trim the black field to the single visible window. Returns 2 if
##       the trimmed result is degenerate (no window rendered).
##   wl_headless_capture_settled <outfile.png> [tries] [max-diff-px]
##       As capture_window, but grab until two consecutive frames match (rendering settled), then
##       write the stable frame. Returns non-zero WITHOUT writing the output if it never
##       stabilises within tries -- so a mid-paint frame is never published.
##
## helper-scripts 'has' for command-presence checks (R-090).
# shellcheck disable=SC1091
source /usr/libexec/helper-scripts/has.bsh

## Directory holding this lib + its wl-blank-cursor.py sibling.
_wl_headless_lib_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

## The X socket dir is fixed by the X protocol; libX11/wlroots look here and ignore TMPDIR.
## style-ok: no-tmp-hardcode -- protocol-fixed X socket directory, cannot be relocated to ${TMP}
_wl_x11_socket_dir='/tmp/.X11-unix'

wl_headless_start() {
   local runtime='' icon_theme='' output_scale=1
   while [ "$#" -gt 0 ]; do
      ## Every option here takes a value; guard the value so a missing one is a clean usage
      ## error, not an unbound-variable abort (nounset caller) or a shift-past-end spin.
      case "$1" in
         --runtime|--icon-theme|--output-scale)
            if [ "$#" -lt 2 ]; then
               printf '%s\n' "wl_headless_start: ${1} needs a value" >&2
               return 2
            fi
            ;;
      esac
      case "$1" in
         --runtime)
            runtime="$2"
            shift 2
            ;;
         --icon-theme)
            icon_theme="$2"
            shift 2
            ;;
         --output-scale)
            output_scale="$2"
            shift 2
            ;;
         *)
            printf '%s\n' "wl_headless_start: unknown option '$1'" >&2
            return 2
            ;;
      esac
   done
   ## icon-theme is interpolated into rc.xml; keep it a plain theme name so a stray '&' or '<'
   ## cannot break (or inject into) the XML and silently disable the whole config.
   case "${icon_theme}" in
      *[!A-Za-z0-9._-]*)
         printf '%s\n' "wl_headless_start: --icon-theme must be a plain theme name, got '${icon_theme}'" >&2
         return 2
         ;;
   esac

   if ! has labwc; then
      printf '%s\n' 'wl_headless_start: labwc not installed (Debian: labwc); cannot start a headless Wayland compositor.' >&2
      return 127
   fi

   ## Save the caller's runtime/display env so wl_headless_stop can restore it -- a long-lived
   ## sourcing shell must not be left pointing at the (removed) private runtime dir.
   WL_HEADLESS_SAVED_XDG_SET="${XDG_RUNTIME_DIR+1}"; WL_HEADLESS_SAVED_XDG="${XDG_RUNTIME_DIR:-}"
   WL_HEADLESS_SAVED_WL_SET="${WAYLAND_DISPLAY+1}"; WL_HEADLESS_SAVED_WL="${WAYLAND_DISPLAY:-}"

   WL_HEADLESS_RUNTIME_MINTED=''
   if [ -z "${runtime}" ]; then
      runtime="$(mktemp --directory)"
      WL_HEADLESS_RUNTIME_MINTED=1
   fi
   chmod 700 -- "${runtime}"
   WL_HEADLESS_RUNTIME="${runtime}"
   export XDG_RUNTIME_DIR="${runtime}"
   export WLR_BACKENDS='headless'
   export WLR_RENDERER='pixman'

   ## Invisible pointer: labwc software-composites its cursor into the pixman output, so grim
   ## captures it (overlay-cursor-off does not drop it) and a stray pointer on the black field
   ## defeats the trim crop. A transparent Xcursor theme removes it.
   local icons_dir="${runtime}/icons" cursor_theme=''
   cursor_theme="$("${_wl_headless_lib_dir}/wl-blank-cursor.py" "${icons_dir}" blank)" || cursor_theme=''
   if [ -n "${cursor_theme}" ]; then
      export XCURSOR_PATH="${icons_dir}"
      export XCURSOR_THEME="${cursor_theme}"
      export XCURSOR_SIZE=24
   fi

   ## labwc config: the icon theme (for honest per-window favicons) when asked. rc.xml lives in
   ## its own dir so labwc -C reads exactly this and nothing from a real user config.
   local cfg="${runtime}/labwc-config"
   mkdir --parents -- "${cfg}"
   {
      printf '%s\n' '<?xml version="1.0"?>'
      printf '%s\n' '<labwc_config>'
      if [ -n "${icon_theme}" ]; then
         printf '  %s\n' "<theme><icon>${icon_theme}</icon></theme>"
      fi
      printf '%s\n' '</labwc_config>'
   } > "${cfg}/rc.xml"

   ## Sockets present BEFORE labwc, so the ones it creates are those that appear after. Snapshot
   ## BOTH the X sockets (its Xwayland display) and the wayland-N sockets: a caller-supplied
   ## --runtime may already hold a live wayland socket (a prior compositor / the user session),
   ## and picking that one would attach clients to the wrong compositor.
   local before_x=' ' before_wl=' ' s
   if [ -d "${_wl_x11_socket_dir}" ]; then
      for s in "${_wl_x11_socket_dir}"/X*; do
         [ -S "${s}" ] || continue
         before_x+="${s##*/X} "
      done
   fi
   for s in "${runtime}"/wayland-[0-9]*; do
      [ -S "${s}" ] || continue
      before_wl+="$(basename -- "${s}") "
   done

   labwc -C "${cfg}" >"${runtime}/labwc.log" 2>&1 &
   WL_HEADLESS_LABWC_PID="$!"

   ## Discover the NEW wayland-N socket labwc creates (its .lock companion is not a socket;
   ## a pre-existing socket from the snapshot above is skipped).
   local socket='' candidate cand_base
   for _ in $(seq 1 100); do
      for candidate in "${runtime}"/wayland-[0-9]*; do
         [ -S "${candidate}" ] || continue
         cand_base="$(basename -- "${candidate}")"
         case "${before_wl}" in *" ${cand_base} "*) continue ;; esac
         socket="${cand_base}"
         break
      done
      [ -n "${socket}" ] && break
      sleep 0.1
   done
   if [ -z "${socket}" ]; then
      printf '%s\n' 'wl_headless_start: labwc did not create a Wayland socket.' >&2
      cat -- "${runtime}/labwc.log" >&2 || true
      wl_headless_stop
      return 1
   fi
   export WAYLAND_DISPLAY="${socket}"

   ## Discover labwc's Xwayland display (the X socket that appeared after labwc started). Absent
   ## is fine -- only the X11-only emulators need it; a caller that uses none can ignore it.
   WL_XWAYLAND_DISPLAY=''
   local n
   for _ in $(seq 1 50); do
      if [ -d "${_wl_x11_socket_dir}" ]; then
         for s in "${_wl_x11_socket_dir}"/X*; do
            [ -S "${s}" ] || continue
            n="${s##*/X}"
            case "${n}" in ''|*[!0-9]*) continue ;; esac
            case "${before_x}" in *" ${n} "*) continue ;; esac
            WL_XWAYLAND_DISPLAY=":${n}"
            break
         done
      fi
      [ -n "${WL_XWAYLAND_DISPLAY}" ] && break
      sleep 0.1
   done
   export WL_XWAYLAND_DISPLAY

   ## HiDPI: raise the single headless output to `output_scale`, sized to a generous logical
   ## area so any shot window fits. Native Wayland clients then render at that scale automatically
   ## (the wl_output scale), and labwc applies the same scale to Xwayland clients -- so a 2x
   ## capture is crisp for both without any per-client scale env. grim grabs the physical
   ## (scaled) pixels. Geometry stays in LOGICAL units; the scale supplies the device pixels.
   case "${output_scale}" in ''|*[!0-9]*) output_scale=1 ;; esac
   if [ "${output_scale}" -gt 1 ]; then
      if ! has wlr-randr; then
         printf '%s\n' "wl_headless_start: wlr-randr not installed (Debian: wlr-randr); cannot set output scale ${output_scale}." >&2
         wl_headless_stop
         return 1
      fi
      local out_name lw=1600 lh=1000
      out_name="$(wlr-randr 2>/dev/null | awk 'NR==1{print $1; exit}')"
      [ -n "${out_name}" ] || out_name='HEADLESS-1'
      wlr-randr --output "${out_name}" \
         --custom-mode "$(( lw * output_scale ))x$(( lh * output_scale ))" \
         --scale "${output_scale}" 2>/dev/null \
         || printf '%s\n' "wl_headless_start: wlr-randr failed to set ${out_name} scale ${output_scale}" >&2
      sleep 0.5
   fi
   return 0
}

wl_headless_stop() {
   if [ -n "${WL_HEADLESS_LABWC_PID:-}" ]; then
      kill "${WL_HEADLESS_LABWC_PID}" 2>/dev/null || true
      wait "${WL_HEADLESS_LABWC_PID}" 2>/dev/null || true
      WL_HEADLESS_LABWC_PID=''
   fi
   if [ "${WL_HEADLESS_RUNTIME_MINTED:-}" = '1' ] && [ -n "${WL_HEADLESS_RUNTIME:-}" ]; then
      safe-rm --recursive --force -- "${WL_HEADLESS_RUNTIME}"
      WL_HEADLESS_RUNTIME_MINTED=''
   fi
   ## Restore the caller's runtime/display env (wl_headless_start overwrote it) so a long-lived
   ## sourcing shell is not left pointing at the removed private runtime dir. Only if start ran.
   if [ -n "${WL_HEADLESS_SAVED_XDG_SET+x}" ]; then
      if [ "${WL_HEADLESS_SAVED_XDG_SET}" = 1 ]; then export XDG_RUNTIME_DIR="${WL_HEADLESS_SAVED_XDG}"; else unset XDG_RUNTIME_DIR; fi
      if [ "${WL_HEADLESS_SAVED_WL_SET}" = 1 ]; then export WAYLAND_DISPLAY="${WL_HEADLESS_SAVED_WL}"; else unset WAYLAND_DISPLAY; fi
      unset WL_HEADLESS_SAVED_XDG_SET WL_HEADLESS_SAVED_XDG WL_HEADLESS_SAVED_WL_SET WL_HEADLESS_SAVED_WL
   fi
}

wl_headless_capture_window() {
   local outfile="$1" full
   if [ -z "${outfile}" ]; then
      printf '%s\n' 'wl_headless_capture_window: no output file' >&2
      return 2
   fi
   if ! has grim; then
      printf '%s\n' 'wl_headless_capture_window: grim not installed (Debian: grim); cannot screenshot a Wayland output.' >&2
      return 127
   fi
   full="$(mktemp --suffix=.png)"
   if ! grim -t png "${full}" 2>/dev/null; then
      safe-rm --force -- "${full}"
      return 1
   fi
   ## One window on the black output: a 1px black border gives trim a uniform edge to remove,
   ## so it crops exactly to the window's decorations (labwc's default theme draws no shadow).
   convert "${full}" -bordercolor black -border 1 -trim +repage "${outfile}" 2>/dev/null || {
      safe-rm --force -- "${full}"
      return 1
   }
   safe-rm --force -- "${full}"
   ## Degenerate (a few px in either dimension) means nothing mapped -- report it.
   local dims w h
   dims="$(identify -format '%w %h' "${outfile}" 2>/dev/null || printf '0 0')"
   w="${dims% *}"; h="${dims#* }"
   if [ "${w:-0}" -lt 20 ] || [ "${h:-0}" -lt 20 ]; then
      return 2
   fi
   return 0
}

## Grab repeatedly until the window stops painting, then write the STABLE frame. Two
## consecutive trim-to-window grabs that match (<= max-diff pixels) mean rendering settled --
## the pixman software renderer is deterministic, so a settled frame reprints identically while
## a still-painting one differs (or changes size). Use it for content that maps then fills in
## (a truecolor board, a tooltip popup, an app still laying out). Returns non-zero WITHOUT
## writing the output if it never stabilises within `tries`, so the caller fails loud rather
## than publishing a mid-paint frame.
wl_headless_capture_settled() {  ## $1=outfile  $2=max-tries(default 12)  $3=max-diff-pixels(default 0)
   local outfile="$1" tries="${2:-12}" maxdiff="${3:-0}" prev cur ae n rc=1
   if [ -z "${outfile}" ]; then
      printf '%s\n' 'wl_headless_capture_settled: no output file' >&2
      return 2
   fi
   if ! has compare; then
      printf '%s\n' 'wl_headless_capture_settled: compare (Debian: imagemagick) not installed; cannot detect a settled frame.' >&2
      return 127
   fi
   prev="$(mktemp --suffix=.png)"
   cur="$(mktemp --suffix=.png)"
   if wl_headless_capture_window "${prev}"; then
      for (( n = 1; n <= tries; n++ )); do
         sleep 0.4
         wl_headless_capture_window "${cur}" || continue
         ## AE = count of differing pixels (to stderr). A SIZE mismatch (window still resizing)
         ## makes compare print an error string, not a number -- taken as not-yet-settled.
         ae="$(compare -metric AE "${prev}" "${cur}" null: 2>&1)"
         ae="${ae%%[!0-9]*}"
         if [ -n "${ae}" ] && [ "${ae}" -le "${maxdiff}" ]; then
            cp -- "${cur}" "${outfile}"
            rc=0
            break
         fi
         cp -- "${cur}" "${prev}"
      done
   fi
   safe-rm --force -- "${prev}" "${cur}"
   return "${rc}"
}

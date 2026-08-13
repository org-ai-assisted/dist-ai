#!/bin/bash
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
## AI-Assisted

## Native-Wayland comparison capture. labwc runs on the X11 backend (nested in an
## Xvfb -- a fully headless Wayland compositor cannot start in a Qubes qube: its
## Xwayland collides with Qubes' Xorg on :0). The TERMINALS run as NATIVE WAYLAND
## clients (the X11-only ones via labwc's own Xwayland) and the screenshot is taken
## with grim (wlr-screencopy). Each terminal keeps whatever decoration it draws.
##
## THREAT MODEL: a terminal cannot protect you from running hostile CODE, only from
## DISPLAYING hostile DATA. So every case DISPLAYS data -- `cat crafted.payload`,
## `cat homoglyph.payload`, `head -c 1200 /dev/random` -- and NEVER runs a script. The
## attack payloads are reproduced from the terminal-poc-corpus (single source of truth).
##
## Terminal-set flags (mainly for fast development):
##   --wayland-terminals   the native-Wayland set
##   --x11-terminals       only xterm/urxvt/st (via labwc's Xwayland)
##   --all-terminals       both sets (default)
##   --only NAME           just this terminal (repeatable)
##   --case C              only crafted | homoglyph | random (repeatable)
##   --quick               == --only kitty --case crafted
## Other: --keep-running  --settle S  --out DIR  --st-repo DIR

## style-ok: no-tmp-hardcode -- /tmp/.X11-unix is the X11 socket directory fixed by
## the protocol; libX11 looks there and nowhere else, so it cannot follow TMPDIR.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## Run the whole pipeline inside a rootless user+net+mount namespace so Xvfb AND
## labwc's own Xwayland each get a PRIVATE X display -- outside, Qubes' Xorg holds
## :0 and labwc's Xwayland cannot bind it (breaks the X11-only terminals). Re-run
## self as a CHILD in the namespace (not exec, to keep a clean rc chain).
if [ -z "${WLCAP_NS:-}" ]; then
   ## --map-root-user makes `id -u` return 0 inside, so capture the REAL runtime
   ## dir now and carry it through (else XDG_RUNTIME_DIR becomes /run/user/0).
   unshare --user --map-root-user --net --mount \
      env WLCAP_NS=1 "WLCAP_XDG=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" "$0" "$@"
   exit "$?"
fi
export XDG_RUNTIME_DIR="${WLCAP_XDG}"
{ mount -t tmpfs none /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix ; } 2>/dev/null || true
ip link set lo up 2>/dev/null || true

only=()
cases=()
settle=3
keep=0
set_choice=all
out_dir="$(pwd)/shots-wayland"
st_repo="${ST_REPO:-${HOME}/private-sources/secure-terminal}"
while [ "$#" -gt 0 ]; do
   case "$1" in
      --wayland-terminals)
         set_choice=wayland
         shift
         ;;
      --x11-terminals)
         set_choice=x11
         shift
         ;;
      --all-terminals)
         set_choice=all
         shift
         ;;
      --only)
         only+=("$2")
         shift 2
         ;;
      --case)
         cases+=("$2")
         shift 2
         ;;
      --quick)
         only=(kitty)
         cases=(crafted)
         shift
         ;;
      --keep-running)
         keep=1
         shift
         ;;
      --settle)
         settle="$2"
         shift 2
         ;;
      --out)
         out_dir="$2"
         shift 2
         ;;
      --st-repo)
         st_repo="$2"
         shift 2
         ;;
      *)
         printf '%s\n' "unknown option: $1" >&2
         exit 2
         ;;
   esac
done
[ "${#cases[@]}" -eq 0 ] && cases=(crafted homoglyph random)

## native-Wayland set (drops xterm/urxvt/st -- no Wayland support) + secure-terminal
wayland_terminals=(konsole qterminal xfce4-terminal mate-terminal alacritty kitty secure-terminal)
## X11-only set, run via labwc's nested Xwayland. NOTE: xterm and urxvt do NOT map
## reliably here -- labwc's wlroots XWM fails to read their window properties in this
## double-nested headless setup (Xvfb -> labwc-X11-backend -> Xwayland), so grim
## captures an empty frame (the run flags it: "window did not render"). st is minimal
## and maps fine, so it is the reliable X11 representative. An X11-only terminal's
## hostile-DATA rendering is display-server-independent, so for production xterm/urxvt
## comparison shots use the pure-X11 path (comparison-capture.sh), not this tool.
x11_terminals=(xterm urxvt st)

mkdir --parents -- "${out_dir}"
here="$(cd -- "$(dirname -- "$0")" && pwd)"

## the shared hostile-DATA contract (payload command + log generation).
# shellcheck source=./lib-capture.sh
source "${here}/lib-capture.sh"

## Fail BEFORE the expensive capture if the bundled webp optimizer is missing -- a direct
## run (not via the secure-terminal-shots wrapper) resolves it checkout-relative, not by PATH.
shots_require_image_optimize || exit 1

## ---- reproduce the corpus payloads once; the demo CATs them ---------------------
work="$(mktemp -d)"
## The run's unique reaping MARKER: the mktemp work dir, which every launched terminal / GUI
## carries in its argv (each runs `sh -c 'cd ${work}; ...'`). Reaping is by session PGID, with
## this marker as the orphan-sweep key -- so it can never touch a process lacking exactly it.
run_marker="${work}"
## Per-capture deadline (seconds): a hung render has its process group reaped, loop continues.
SHOT_DEADLINE="${SHOT_DEADLINE:-90}"
## Reliable reaping REQUIRES safe-pgrep/safe-pkill -- fail loudly, never fall back.
shots_require_safe_ps || exit 1
## Pre-clean orphans from a prior crashed run (marker-scoped), then register this run.
shots_reap_registered || true
shots_register_run "${run_marker}"
## propagate the real code: 77 is the missing-corpus SKIP, any other non-zero is a
## genuine payload-generation failure that must not read as a skip.
shots_generate_logs "${here}" "${work}" || exit "$?"

## ---- labwc on the X11 backend (also gives us an Xwayland for the X11 set) -----
xvfb_pid=''
labwc_pid=''
xdisplay=':121'
xwl_display=''
start_compositor() {
   Xvfb "${xdisplay}" -screen 0 1400x900x24 >"${out_dir}/.xvfb.log" 2>&1 &
   xvfb_pid=$!
   sleep 1.5
   local before s i n
   before=' '
   for s in "${XDG_RUNTIME_DIR}"/wayland-*; do
      [ -S "${s}" ] && before="${before}${s} "
   done
   DISPLAY="${xdisplay}" WLR_BACKENDS=x11 WLR_X11_OUTPUTS=1 labwc >"${out_dir}/.labwc.log" 2>&1 &
   labwc_pid=$!
   for i in $(seq 1 40); do
      for s in "${XDG_RUNTIME_DIR}"/wayland-*; do
         [ -S "${s}" ] || continue
         case "${s}" in
            *.lock)
               continue
               ;;
         esac
         case "${before}" in
            *" ${s} "*)
               continue                 ## a socket that existed before labwc
               ;;
         esac
         WAYLAND_DISPLAY="$(basename -- "${s}")"
         export WAYLAND_DISPLAY
      done
      [ -n "${WAYLAND_DISPLAY:-}" ] && break
      sleep 0.2
   done
   if [ -z "${WAYLAND_DISPLAY:-}" ]; then
      printf '%s\n' 'labwc: no wayland socket' >&2
      tail -8 "${out_dir}/.labwc.log" >&2 || true
      return 1
   fi
   ## labwc's Xwayland display (for the X11-only terminals): the X socket that is
   ## NOT our Xvfb output. wlroots reserves it at startup even though Xwayland is
   ## exec'd lazily on the first X client.
   for i in $(seq 1 25); do
      for s in /tmp/.X11-unix/X*; do
         [ -S "${s}" ] || continue
         n="${s##*/X}"
         [ "${n}" = "${xdisplay#:}" ] && continue
         xwl_display=":${n}"
      done
      [ -n "${xwl_display}" ] && break
      sleep 0.3
   done
   printf '%s\n' \
      "labwc up on ${xdisplay}: WAYLAND_DISPLAY=${WAYLAND_DISPLAY} xwayland=${xwl_display:-none}"
}

## ---- launch one terminal running `sh -c` from the log dir, in its OWN session ----
## so the whole tree can be reaped by the recorded PGID (the secure-terminal GUI runs as
## `python3 .../secure-terminal`, process name `python3`, so a name kill never reaches it).
launch_terminal() {  ## $1=name  $2=payload-command  $3=pgid-file
   local name="$1" cmd="$2" pgf="$3" tcmd
   local sh="cd ${work}; printf 'user@host:~\$ %s\n' \"${cmd}\"; ${cmd}; sleep 600"
   local wl=(env -u DISPLAY GDK_BACKEND=wayland QT_QPA_PLATFORM=wayland
             "WAYLAND_DISPLAY=${WAYLAND_DISPLAY}" "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR}")
   local x=(env -u WAYLAND_DISPLAY "DISPLAY=${xwl_display}")
   tcmd=()
   case "${name}" in
      konsole)
         tcmd=("${wl[@]}" konsole --separate --hide-menubar --hide-tabbar -e sh -c "${sh}")
         ;;
      qterminal)
         tcmd=("${wl[@]}" qterminal --hide-menu-bar -e "sh -c '${sh}'")
         ;;
      xfce4-terminal)
         tcmd=("${wl[@]}" xfce4-terminal --disable-server --hide-menubar -x sh -c "${sh}")
         ;;
      mate-terminal)
         tcmd=("${wl[@]}" mate-terminal --disable-factory --hide-menubar -x sh -c "${sh}")
         ;;
      alacritty)
         tcmd=("${wl[@]}" alacritty -o 'window.dimensions.columns=84' -o 'window.dimensions.lines=24' -e sh -c "${sh}")
         ;;
      kitty)
         tcmd=("${wl[@]}" kitty -o remember_window_size=no -o initial_window_width=780 -o initial_window_height=520 sh -c "${sh}")
         ;;
      secure-terminal)
         tcmd=("${wl[@]}" PYTHONPATH="${st_repo}/usr/lib/python3/dist-packages" \
            python3 "${st_repo}/usr/bin/secure-terminal" -- bash -c "${sh}")
         ;;
      xterm)
         tcmd=("${x[@]}" xterm -geometry 84x24 -e sh -c "${sh}")
         ;;
      urxvt)
         tcmd=("${x[@]}" urxvt -geometry 84x24 -e sh -c "${sh}")
         ;;
      st)
         tcmd=("${x[@]}" st -g 84x24 -e sh -c "${sh}")
         ;;
   esac
   [ "${#tcmd[@]}" -gt 0 ] && shots_spawn_session "${pgf}" "${tcmd[@]}" >/dev/null 2>&1
}

## ---- capture: grim whole output, trim black margin to the window -------------
capture_one() {
   local outfile="$1" dim
   grim -t png "${outfile}.full.png" 2>>"${out_dir}/.grim.log" || return 1
   if [ -z "$(type -P convert)" ]; then
      mv -- "${outfile}.full.png" "${outfile}"
      return 0
   fi
   convert "${outfile}.full.png" -bordercolor black -border 1 -trim +repage "${outfile}" 2>>"${out_dir}/.grim.log" || true
   ## a degenerate trim (all one colour -> ~1x1) means the window never rendered;
   ## keep the FULL frame and flag it rather than shipping a broken 1x1.
   dim="$(identify -format '%w %h' "${outfile}" 2>/dev/null || true)"
   if [ -z "${dim}" ] || [ "${dim%% *}" -lt 20 ] || [ "${dim##* }" -lt 20 ]; then
      mv -- "${outfile}.full.png" "${outfile}"
      return 2
   fi
   safe-rm --force -- "${outfile}.full.png"
}

cleanup() {
   ## reap any capture group that leaked (marker-scoped safety net), then drop this run from the
   ## registry before the work dir -- the marker -- is removed.
   shots_reap_run "${run_marker}" 2>/dev/null || true
   shots_deregister_run "${run_marker}" 2>/dev/null || true
   safe-rm --recursive --force -- "${work}" || true
   [ "${keep}" = 1 ] && return 0
   ## labwc + Xvfb are our own recorded children; kill them by PID (no name kill, which could
   ## hit another session's labwc).
   kill "${labwc_pid}" "${xvfb_pid}" 2>/dev/null || true
}
trap cleanup EXIT

## ---- select the terminal set + run -------------------------------------------
start_compositor
sleep 1
case "${set_choice}" in
   wayland)
      term_list=("${wayland_terminals[@]}")
      ;;
   x11)
      term_list=("${x11_terminals[@]}")
      ;;
   all)
      term_list=("${wayland_terminals[@]}" "${x11_terminals[@]}")
      ;;
esac
[ "${#only[@]}" -gt 0 ] && term_list=("${only[@]}")

rc=0
for name in "${term_list[@]}"; do
   for c in "${cases[@]}"; do
      pgf="$(mktemp)"
      flagf="${pgf}.timeout"
      ## launch in its own session (records PGID into pgf); arm the per-capture watchdog so a
      ## hung terminal is reaped rather than stalling the grid.
      launch_terminal "${name}" "$(shots_payload_cmd "${c}")" "${pgf}"
      wdog="$(shots_watchdog_start "${SHOT_DEADLINE}" "${pgf}" "${flagf}")"
      sleep "${settle}"
      capture_one "${out_dir}/${name}.${c}.png" && rc=0 || rc=$?
      shots_watchdog_cancel "${wdog}"
      [ -e "${flagf}" ] && printf '%s\n' "WARN ${name}.${c}: capture exceeded ${SHOT_DEADLINE}s deadline, group reaped" >&2
      case "${rc}" in
         0)
            printf '%s\n' "captured ${name}.${c}"
            ;;
         2)
            printf '%s\n' "captured ${name}.${c} (WARN: window did not render -- full frame kept)"
            ;;
         *)
            printf '%s\n' "FAILED ${name}.${c}" >&2
            ;;
      esac
      ## reap the terminal by its recorded session PGID (NOT `pkill -x ${name}`, which never
      ## matched the `python3` GUI and could hit other sessions' same-named processes).
      term_pgid="$(cat "${pgf}" 2>/dev/null || true)"
      shots_reap_group "${term_pgid}"
      safe-rm -f -- "${pgf}" "${flagf}" 2>/dev/null || true
      sleep 0.5
   done
done
## Convert the captured PNGs to webp (the site references them as .webp).
shots_optimize_to_webp "${out_dir}"/*.png

printf '%s\n' "done; shots in ${out_dir}"

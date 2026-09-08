#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## RENDERED favicon regression (opt-in e2e). The static favicon_appid_test.sh guards the shot
## SOURCE (no --name/--class, run the ST bin directly, marker via env). This one renders the real
## secure-terminal GUI through the real headless compositor and asserts, on PIXELS, that the shot
## pipeline is honest. It exists because the failure modes it catches are invisible to source
## greps and to the display-free suite:
##   1. WRONG / cross-app titlebar icon, or the labwc/python FALLBACK icon (the app-id bug):
##      the titlebar must carry secure-terminal's OWN icon, matched against the real svg.
##   2. TRIO-EMPTY (the LC_ALL regression): xterm/urxvt/st SILENTLY EXIT under a non-UTF-8 locale
##      (no window, no error) -- the whole X11-only trio was once lost this way. An xterm launched
##      the way the generator launches it must actually MAP and render its unicode payload.
##   3. BLACK MARGIN: the migration's whole point was dropping the black space around each window;
##      a correctly trimmed shot has almost no pure-black area.
##
## OPT-IN: a rendered compositor is not present in the display-free CI container, so this SKIPs
## (exit 77) there and RUNS in the temp-claude sandbox. It needs labwc + grim + compare + convert
## + ST_REPO (the real secure-terminal checkout).
##
## Subjects: wl-headless-lib.bash (bringup/capture), lib-capture.sh (shots_install_icon_theme),
## comparison-capture.sh (launch() LC_ALL source guard), and the real secure-terminal GUI.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## --- calibrated constants (measured against a real 2x shot) -----------------------------------
## The titlebar favicon sits at the window's top-left, and the capture is trimmed to the window,
## so the icon is at the shot's top-left corner. secure-terminal's icon carries a DISTINCTIVE
## green check badge (svg colour #1F8A54 = rgb 31,138,84, ~100 px in a real shot); a fallback
## (python/labwc) or cross-app icon does NOT, so counting that signature green in the corner box
## cleanly separates the real icon from a wrong one -- far more robust than a background-sensitive
## whole-icon image match (the titlebar grey behind a transparent icon dominates an RMSE compare).
ICON_REGION='64x64+0+0'    ## top-left corner box that contains the titlebar favicon
FAVICON_GREEN=(31 138 84)  ## the check-badge green (svg #1F8A54)
FAVICON_GREEN_TOL=45       ## per-channel match tolerance
FAVICON_GREEN_MIN=25       ## min signature-green px for "the real favicon is present" (real ~100)
BLACK_FRAC_MAX='0.10'      ## max fraction of pure-#000000 pixels (a trimmed ST window is ~0.5%)

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

resolve() {  ## $1=env-override $2..=candidate paths -> echo first existing, else empty
   local cand
   for cand in "$@"; do
      if [ -n "${cand}" ] && [ -e "${cand}" ]; then
         readlink --canonicalize -- "${cand}"
         return 0
      fi
   done
   return 0
}

wl_lib="$(resolve "${WL_HEADLESS_LIB:-}" \
   "${script_dir}/../dist-ai-tests-common/wl-headless-lib.bash" \
   '/usr/share/dist-ai-tests-common/wl-headless-lib.bash')"
lib_capture="$(resolve "${SECURE_TERMINAL_SHOTS_DIR:-}/lib-capture.sh" \
   "${script_dir}/../secure-terminal-shots/lib-capture.sh" \
   '/usr/share/secure-terminal-shots/lib-capture.sh')"
cmp_capture="$(resolve "${SECURE_TERMINAL_SHOTS_DIR:-}/comparison-capture.sh" \
   "${script_dir}/../secure-terminal-shots/comparison-capture.sh" \
   '/usr/share/secure-terminal-shots/comparison-capture.sh')"
st_repo="$(resolve "${ST_REPO:-}" "${SECURE_TERMINAL_REPO:-}" \
   "${HOME}/private-sources/secure-terminal")"

## OPT-IN gate: without a live compositor + capture stack + ST checkout there is nothing to
## render, so SKIP (this target is genuinely optional -- it runs in the sandbox, not display-free CI).
missing=''
for tool in labwc grim compare convert wlr-randr; do
   type -P "${tool}" >/dev/null 2>&1 || missing="${missing} ${tool}"
done
st_bin="${st_repo}/usr/bin/secure-terminal"
st_pkg="${st_repo}/usr/lib/python3/dist-packages"
if [ -n "${missing}" ] || [ -z "${wl_lib}" ] || [ -z "${lib_capture}" ] || [ ! -x "${st_bin}" ]; then
   printf '%s\n' "SKIP: rendered favicon e2e needs a compositor + ST checkout (missing:${missing:- } wl_lib=${wl_lib:-none} st_bin=${st_bin})" >&2
   ## style-ok: allow-skip: rendered favicon e2e needs a live wayland compositor (labwc+grim) + ST_REPO; absent in display-free CI, runs in temp-claude
   exit 77
fi

## Everything below needs the compositor, so failures are REAL failures (exit 1), never skips.
work="$(mktemp --directory)"
st_pid=''
xt_pid=''
cleanup() {
   [ -n "${st_pid}" ] && kill "${st_pid}" 2>/dev/null || true
   [ -n "${xt_pid}" ] && kill "${xt_pid}" 2>/dev/null || true
   ## wl_headless_stop is defined once the lib is sourced; guard for an early failure.
   declare -F wl_headless_stop >/dev/null 2>&1 && wl_headless_stop || true
   safe-rm --recursive --force -- "${work}" 2>/dev/null || true
}
trap cleanup EXIT

# shellcheck source=../dist-ai-tests-common/wl-headless-lib.bash
source "${wl_lib}"
export ST_REPO="${st_repo}"   ## shots_install_icon_theme reads ST_REPO
# shellcheck source=../secure-terminal-shots/lib-capture.sh
source "${lib_capture}"

pass=0
fail=0
check() {  ## $1=label $2=ok?(non-empty=pass)
   if [ -n "$2" ]; then
      printf '%s\n' "PASS: $1"; pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"; fail=$(( fail + 1 ))
   fi
}

## Bring up the SAME compositor the shots use (Papirus icon theme, 2x output scale).
runtime_dir="${work}/rt"; mkdir --parents -- "${runtime_dir}"
# shellcheck disable=SC2119
if ! wl_headless_start --runtime "${runtime_dir}" --icon-theme Papirus --output-scale 2; then
   printf '%s\n' 'FAIL: wl_headless_start did not bring up labwc' >&2
   printf '%s\n' '' '0 pass, 1 fail, 0 skip'
   exit 1
fi

## Install secure-terminal's own icon + .desktop into the session (labwc maps app-id -> .desktop
## Icon= -> theme), exactly as the shots do.
export XDG_DATA_HOME="${work}/data"; mkdir --parents -- "${XDG_DATA_HOME}"
shots_install_icon_theme "${XDG_DATA_HOME}"

## Pixel math lives in a standalone helper (dist-ai style forbids stdin-heredoc python).
pixel_probe="${script_dir}/favicon_pixel_probe.py"
if [ ! -x "${pixel_probe}" ]; then
   printf '%s\n' "FATAL: ${pixel_probe} not found/executable (required pixel probe)" >&2
   exit 1
fi

## pure-#000000 fraction of a PNG (0..1) -- a black margin around the window shows up here.
black_fraction() {  ## $1=png
   "${pixel_probe}" black "$1"
}

## count pixels matching the favicon signature green (within tolerance) in a PNG region.
signature_green_count() {  ## $1=png
   "${pixel_probe}" green "$1" \
      "${FAVICON_GREEN[0]}" "${FAVICON_GREEN[1]}" "${FAVICON_GREEN[2]}" "${FAVICON_GREEN_TOL}"
}

## -------- ARM 1: the real ST window renders with its honest favicon + no black margin --------
run_marker="${runtime_dir}"
st_group="favicon-e2e-$$"
env "SHOTS_RUN_MARKER=${run_marker}" QT_QPA_PLATFORM=wayland QT_FONT_DPI=72 \
   SECURE_TERMINAL_SHOT=1 SHELL=/bin/bash PYTHONPATH="${st_pkg}" \
   "${st_bin}" --instance-group "${st_group}" >/dev/null 2>&1 &
st_pid=$!

## Wait for the window to map (a non-degenerate grab), then settle it.
probe="${work}/probe.png"
mapped=''
for _ in $(seq 1 40); do
   if wl_headless_capture_window "${probe}" 2>/dev/null; then
      mapped='1'
      break
   fi
   sleep 0.5
done
shot="${work}/st.png"
if [ -n "${mapped}" ] && wl_headless_capture_settled "${shot}" 15 0; then
   check 'the secure-terminal window renders (non-degenerate capture)' '1'
else
   check 'the secure-terminal window renders (non-degenerate capture)' ''
   shot=''
fi

if [ -n "${shot}" ]; then
   bf="$(black_fraction "${shot}")"
   awk -v b="${bf}" -v m="${BLACK_FRAC_MAX}" 'BEGIN { exit !(b <= m) }' \
      && check "no black margin around the window (pure-black ${bf} <= ${BLACK_FRAC_MAX})" '1' \
      || check "no black margin around the window (pure-black ${bf} <= ${BLACK_FRAC_MAX})" ''

   ## Favicon: the titlebar-left corner must carry secure-terminal's OWN icon, detected by its
   ## distinctive green check badge. A fallback/python/cross-app icon lacks that signature green.
   iconbox="${work}/iconbox.png"
   convert "${shot}" -crop "${ICON_REGION}" +repage "${iconbox}"
   green="$(signature_green_count "${iconbox}")"
   if [ -n "${green}" ] && [ "${green}" -ge "${FAVICON_GREEN_MIN}" ]; then
      check "titlebar carries the real secure-terminal favicon (green-check px ${green} >= ${FAVICON_GREEN_MIN})" '1'
   else
      check "titlebar carries the real secure-terminal favicon (green-check px ${green:-0} >= ${FAVICON_GREEN_MIN})" ''
   fi
fi
kill "${st_pid}" 2>/dev/null || true
st_pid=''

## -------- ARM 2: the X11-only trio MAPS under C.UTF-8 (guards the LC_ALL regression) ---------
## xterm launched the way the generator's launch() launches it: Xwayland, LC_ALL=C.UTF-8, a
## unicode payload. Under a regression to bare LC_ALL=C, xterm silently exits -> no window ->
## a degenerate/failed grab -> this fails, which is exactly the trio-empty signal.
if [ -n "${WL_XWAYLAND_DISPLAY:-}" ] && type -P xterm >/dev/null 2>&1; then
   env LC_ALL=C.UTF-8 --unset=WAYLAND_DISPLAY "DISPLAY=${WL_XWAYLAND_DISPLAY}" \
      xterm -geometry 40x6 -fa 'Monospace' -fs 11 \
      -e bash -c "printf 'unicode: \xe4\xb8\xad\xe6\x96\x87 \xc3\xbc\xc3\xa9\n'; sleep 30" >/dev/null 2>&1 &
   xt_pid=$!
   xshot="${work}/xterm.png"
   xmapped=''
   for _ in $(seq 1 30); do
      if wl_headless_capture_window "${xshot}" 2>/dev/null; then
         xmapped='1'
         break
      fi
      sleep 0.5
   done
   check 'xterm (Xwayland) maps + renders under LC_ALL=C.UTF-8 (trio not silently empty)' "${xmapped}"
   kill "${xt_pid}" 2>/dev/null || true
   xt_pid=''
else
   ## No Xwayland means the trio cannot be exercised at all -- surface it, do not silently pass.
   printf '%s\n' 'note: WL_XWAYLAND_DISPLAY empty or xterm absent; trio LC_ALL arm not exercised' >&2
fi

## -------- ARM 3 (source guard): launch() must launch the trio under LC_ALL=C.UTF-8 -----------
## Cheap backstop for the exact regression, independent of rendering: the generator's x= and wl=
## env arrays must carry C.UTF-8, never bare C.
if [ -n "${cmp_capture}" ]; then
   if grep --extended-regexp --quiet 'x=\(env LC_ALL=C\.UTF-8' "${cmp_capture}" \
      && grep --extended-regexp --quiet 'wl=\(env LC_ALL=C\.UTF-8' "${cmp_capture}"; then
      check 'comparison-capture launch() uses LC_ALL=C.UTF-8 for the trio (source guard)' '1'
   else
      check 'comparison-capture launch() uses LC_ALL=C.UTF-8 for the trio (source guard)' ''
   fi
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: rendered favicon honest, no black margin, trio maps under C.UTF-8'

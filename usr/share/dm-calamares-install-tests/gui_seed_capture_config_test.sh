#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins gui_seed_capture_config -- the deterministic/clean capture-config seeder in
## dm-calamares-install. It builds a dedicated XDG_CONFIG_HOME (copied from the account's real
## ~/.config, so wallpaper/icons stay faithful) and applies three edits to the COPY only:
##   - the `volume` panel plugin is dropped (false no-audio red "!" on the headless host);
##   - the worldclock is frozen to a token-free literal (formatType=custom) for reproducible frames;
##   - a labwc windowRule maximizes the VM window.
## The account's real ~/.config MUST stay byte-identical (non-destructive). Drives the REAL function
## (sourced define-only) with a fake HOME -- no root, no labwc, no VM.
##
## Exit: 0 pass | 1 fail.

## gui_cfg_dir/XDG_CONFIG_HOME are SET by the sourced subject, and vars below are read by it;
## shellcheck cannot see across the source (SC2034 assigned-unused, SC2154 referenced-unassigned).
# shellcheck disable=SC2034,SC2154

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
subject=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${subject}" ] || { printf '%s\n' "FATAL: dm-calamares-install not found" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

# shellcheck disable=SC1090
source "${subject}"

pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }

## Write a branded-style panel.conf (kicksecure plugin set: volume present, live clock) to $1.
write_panel() {
   printf '%s\n' \
      '[panel1]' \
      "plugins=${2:-fancymenu2, quicklaunch, taskbar, tray, statusnotifier, mount, volume, worldclock}" \
      'position=Top' \
      '' \
      '[worldclock]' \
      'alignment=Right' \
      'type=worldclock' \
      'timeShowSeconds=true' \
      > "$1"
}

## Run gui_seed_capture_config for a fresh fake HOME + fresh gui_xdg_dir; leaves XDG_CONFIG_HOME set.
## $1 = plugins line override (optional). Seeds a faithful sentinel + a user rc.xml to clobber.
seed_case() {
   home="$(mktemp --directory "${work}/home.XXXXXX")"
   mkdir -p -- "${home}/.config/lxqt" "${home}/.config/pcmanfm-qt/lxqt" "${home}/.config/labwc"
   write_panel "${home}/.config/lxqt/panel.conf" "${1:-}"
   printf '%s\n' 'Wallpaper=/usr/share/wallpaper/kicksecure.png' > "${home}/.config/pcmanfm-qt/lxqt/settings.conf"
   printf '%s\n' '<labwc_config><keyboard/></labwc_config>' > "${home}/.config/labwc/rc.xml"
   gui_xdg_dir="$(mktemp --directory "${work}/xdg.XXXXXX")"
   HOME="${home}" gui_seed_capture_config
}

## Read the plugins line / worldclock section into a STRING (no pipe into a quiet grep, R-161): the
## assertions then grep the captured string via a here-string.
plugins_line() { grep -m1 '^plugins=' "$1" || true; }
worldclock_section() { awk '/^\[worldclock\]/{f=1;print;next} f&&/^\[/{f=0} f{print}' "$1"; }

## --- case 1: volume dropped, other plugins kept, worldclock frozen (no dup), rc.xml maximized -----
seed_case
panel="${gui_cfg_dir}/lxqt/panel.conf"
pl="$(plugins_line "${panel}")"
wc="$(worldclock_section "${panel}")"
got=0
{ [ "${XDG_CONFIG_HOME}" = "${gui_cfg_dir}" ] \
  && [[ "${pl}" != *volume* ]] \
  && [[ "${pl}" == *worldclock* ]] \
  && [[ "${pl}" == *mount* ]] \
  && [[ "${pl}" == *statusnotifier* ]]; } || got=1
check "volume plugin dropped; worldclock/mount/statusnotifier kept; XDG_CONFIG_HOME set" "${got}"

got=0
dup_seconds="$(grep -c '^timeShowSeconds=' <<< "${wc}")"
{ grep --quiet --line-regexp 'formatType=custom' <<< "${wc}" \
  && grep --quiet --line-regexp 'customFormat=00:00' <<< "${wc}" \
  && grep --quiet --line-regexp 'timeShowSeconds=false' <<< "${wc}" \
  && [ "${dup_seconds}" -eq 1 ] \
  && [[ "${wc}" != *$'\n'timeShowSeconds=true* ]]; } || got=1
check "worldclock frozen (formatType=custom + customFormat + timeShowSeconds=false, no dup key)" "${got}"

got=0
{ [ -f "${gui_cfg_dir}/labwc/rc.xml" ] && grep --quiet 'Maximize' "${gui_cfg_dir}/labwc/rc.xml"; } || got=1
check "labwc rc.xml written with a Maximize windowRule" "${got}"

## --- case 2: faithful copy (wallpaper sentinel present) + real ~/.config UNTOUCHED ---------------
got=0
{ [ -f "${gui_cfg_dir}/pcmanfm-qt/lxqt/settings.conf" ] \
  && grep --quiet 'kicksecure.png' "${gui_cfg_dir}/pcmanfm-qt/lxqt/settings.conf"; } || got=1
check "account config copied faithfully (pcmanfm-qt wallpaper sentinel present)" "${got}"

real_pl="$(plugins_line "${home}/.config/lxqt/panel.conf")"
got=0
{ [[ "${real_pl}" == *volume* ]] \
  && grep --quiet --line-regexp 'timeShowSeconds=true' "${home}/.config/lxqt/panel.conf"; } || got=1
check "real ~/.config/lxqt/panel.conf left UNTOUCHED (still has volume + live clock)" "${got}"

## --- case 3: volume removal across no-space, trailing, and prefix-collision positions --------------
seed_case 'fancymenu,desktopswitch,quicklaunch,taskbar,statusnotifier,tray,mount,volume,worldclock,showdesktop'
pl="$(plugins_line "${gui_cfg_dir}/lxqt/panel.conf")"
got=0; { [[ "${pl}" != *volume* ]] && [[ "${pl}" == *worldclock* ]] && [[ "${pl}" == *showdesktop* ]]; } || got=1
check "volume dropped from a no-space mid-list plugins line (neighbours intact)" "${got}"

seed_case 'fancymenu2, quicklaunch, taskbar, mount, worldclock, volume'
pl="$(plugins_line "${gui_cfg_dir}/lxqt/panel.conf")"
got=0; { [[ "${pl}" != *volume* ]] && [[ "${pl}" == *worldclock* ]]; } || got=1
check "volume dropped when it is the TRAILING plugin" "${got}"

## EXACT-token removal: a 'volumecontrol' plugin must NOT be prefix-mangled; only the lone 'volume'
## token is dropped. (reviewer finding 2)
## 'volumecontrol' placed AFTER the standalone volume so a greedy prefix-matching sed would mangle
## it (and miss the real volume) -- the exact-token awk must drop only the lone volume.
seed_case 'fancymenu2, quicklaunch, mount, volume, worldclock, volumecontrol'
pl="$(plugins_line "${gui_cfg_dir}/lxqt/panel.conf")"
got=0; { [[ "${pl}" == *volumecontrol* ]] && ! grep --quiet --extended-regexp '(=|, )volume(,|$)' <<< "${pl}"; } || got=1
check "exact-token removal: standalone volume dropped, 'volumecontrol' preserved" "${got}"

## --- case 4: DM_STORY_CLOCK_TEXT overrides the frozen literal -------------------------------------
DM_STORY_CLOCK_TEXT='CI-SNAPSHOT' seed_case
wc="$(worldclock_section "${gui_cfg_dir}/lxqt/panel.conf")"
got=0; grep --quiet --line-regexp 'customFormat=CI-SNAPSHOT' <<< "${wc}" || got=1
check "DM_STORY_CLOCK_TEXT overrides the frozen clock literal" "${got}"

## --- case 5: no account ~/.config -> seed panel.conf from DM_STORY_PANEL_CONF_SRC -----------------
src_panel="${work}/branded-panel.conf"; write_panel "${src_panel}"
home="$(mktemp --directory "${work}/home-bare.XXXXXX")"   ## HOME with NO .config
gui_xdg_dir="$(mktemp --directory "${work}/xdg-bare.XXXXXX")"
HOME="${home}" DM_STORY_PANEL_CONF_SRC="${src_panel}" gui_seed_capture_config
pl="$(plugins_line "${gui_cfg_dir}/lxqt/panel.conf")"
wc="$(worldclock_section "${gui_cfg_dir}/lxqt/panel.conf")"
got=0
{ [ -f "${gui_cfg_dir}/lxqt/panel.conf" ] \
  && [[ "${pl}" != *volume* ]] \
  && grep --quiet --line-regexp 'formatType=custom' <<< "${wc}" \
  && grep --quiet 'Maximize' "${gui_cfg_dir}/labwc/rc.xml"; } || got=1
check "bare account (no ~/.config) seeds from DM_STORY_PANEL_CONF_SRC + still edits/maximizes" "${got}"

## --- case 6: the faithful ~/.config copy must be GUARDED so an unreadable entry cannot abort the
## capture lane under errexit (finding 1) -- cp is the last cmd of an && list and needs `|| true` like
## its siblings. The abort path cannot be exercised here without an inline multi-statement `bash -c`
## (R-192 forbids it), so assert the guard is present in the source (catches a regression removing it).
got=0; grep --quiet --extended-regexp 'cp -a -- "\$\{HOME\}/\.config/\." .*\|\| true' -- "${subject}" || got=1
check "the ~/.config copy is guarded with || true (cannot abort the lane on an unreadable entry)" "${got}"

## --- case 7: a symlinked ~/.config sink must NOT be followed + clobber real config (finding 3) -----
## cp -a preserves symlinks; if ~/.config/labwc is a symlink to the account's real dir, our rc.xml
## write must stay inside gui_cfg_dir, never follow the link and overwrite the account's real rc.xml.
home="$(mktemp --directory "${work}/home-symdir.XXXXXX")"
mkdir -p -- "${home}/.config/lxqt"
write_panel "${home}/.config/lxqt/panel.conf"
realdir="$(mktemp --directory "${work}/realacct.XXXXXX")"   ## stands in for the account's REAL labwc dir
printf '%s\n' 'ACCOUNT-REAL-RCXML' > "${realdir}/rc.xml"
ln --symbolic -- "${realdir}" "${home}/.config/labwc"       ## ~/.config/labwc -> real dir (absolute)
gui_xdg_dir="$(mktemp --directory "${work}/xdg-symdir.XXXXXX")"
HOME="${home}" gui_seed_capture_config
got=0
{ grep --quiet --line-regexp 'ACCOUNT-REAL-RCXML' "${realdir}/rc.xml" \
  && [ ! -L "${gui_cfg_dir}/labwc" ] \
  && [ ! -L "${gui_cfg_dir}/labwc/rc.xml" ] \
  && grep --quiet 'Maximize' "${gui_cfg_dir}/labwc/rc.xml"; } || got=1
check "symlinked ~/.config/labwc NOT followed (real rc.xml untouched; copy's labwc+rc.xml are real)" "${got}"

## variant: rc.xml itself an absolute symlink (labwc a real dir) -- same non-destructive requirement
home="$(mktemp --directory "${work}/home-symfile.XXXXXX")"
mkdir -p -- "${home}/.config/lxqt" "${home}/.config/labwc"
write_panel "${home}/.config/lxqt/panel.conf"
realrc="$(mktemp "${work}/realrc.XXXXXX")"; printf '%s\n' 'ACCOUNT-REAL-RCXML2' > "${realrc}"
ln --symbolic -- "${realrc}" "${home}/.config/labwc/rc.xml"
gui_xdg_dir="$(mktemp --directory "${work}/xdg-symfile.XXXXXX")"
HOME="${home}" gui_seed_capture_config
got=0
{ grep --quiet --line-regexp 'ACCOUNT-REAL-RCXML2' "${realrc}" \
  && [ ! -L "${gui_cfg_dir}/labwc/rc.xml" ] \
  && grep --quiet 'Maximize' "${gui_cfg_dir}/labwc/rc.xml"; } || got=1
check "symlinked ~/.config/labwc/rc.xml NOT followed (real file untouched; copy's rc.xml is real)" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
exit 0

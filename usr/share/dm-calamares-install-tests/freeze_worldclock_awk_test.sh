#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins freeze-worldclock.awk -- the SINGLE source of the worldclock-freeze logic shared by the
## HOST capture-config seeder (dm-calamares-install gui_seed_capture_config, drop_volume=1) and
## the GUEST in-guest edit (gui_freeze_guest_clock, drop_volume=0). This is the DRIFT GUARD: the
## two call sites must keep behaving identically, so the awk is exercised directly here.
##
## Asserts:
##   - drop_volume=0 (guest): the worldclock is frozen to a token-free literal and the plugin
##     list is left UNTOUCHED (the guest keeps its real tray, incl. a volume plugin);
##   - drop_volume=1 (host): the worldclock is frozen AND the lone `volume` plugin is dropped
##     by EXACT token (a 'volumecontrol' plugin is preserved);
##   - the fmt literal is honored; pre-existing worldclock keys are collapsed (no duplicate).
##
## Exit: 0 pass | 1 fail.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_FREEZE_WORLDCLOCK_AWK:-}" \
   "${test_dir}/../../libexec/dm-calamares-install/freeze-worldclock.awk" \
   "/usr/libexec/dm-calamares-install/freeze-worldclock.awk"; do
   [ -n "${candidate}" ] || continue
   if [ -f "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: freeze-worldclock.awk not found (set DM_FREEZE_WORLDCLOCK_AWK)." >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }

## Write a branded-style panel.conf (kicksecure plugin set: volume present, LIVE clock with a
## pre-existing formatType to prove the freeze COLLAPSES duplicates) to $1. $2 = plugins override.
write_panel() {
   printf '%s\n' \
      '[panel1]' \
      "plugins=${2:-fancymenu2, quicklaunch, taskbar, tray, statusnotifier, mount, volume, worldclock}" \
      'position=Top' \
      '' \
      '[worldclock]' \
      'alignment=Right' \
      'type=worldclock' \
      'formatType=short' \
      'timeShowSeconds=true' \
      '' \
      '[mount]' \
      'type=mount' \
      > "$1"
}

## Run the REAL awk, output to $4; fmt=$1, drop_volume=$2, input=$3.
run_awk() {
   awk -v fmt="$1" -v drop_volume="$2" -f "${subject}" "$3" > "$4"
}

## Read helpers into a STRING (the host test's idiom): the plugins line / the [worldclock] section.
plugins_line() { grep -m1 '^plugins=' "$1" || true; }
worldclock_section() { awk '/^\[worldclock\]/{f=1;print;next} f&&/^\[/{f=0} f{print}' "$1"; }

in="${work}/panel.in"
out="${work}/panel.out"

## --- case 1: GUEST mode (drop_volume=0) -- clock frozen, plugin list UNTOUCHED ---------------
write_panel "${in}"
run_awk '00:00' 0 "${in}" "${out}"
pl="$(plugins_line "${out}")"
wc="$(worldclock_section "${out}")"
dup_fmt="$(grep -c '^formatType=' <<< "${wc}")"
dup_seconds="$(grep -c '^timeShowSeconds=' <<< "${wc}")"
got=0
{ [[ "${pl}" == *volume* ]] \
  && [[ "${pl}" == *worldclock* ]] \
  && grep --quiet --line-regexp 'formatType=custom' <<< "${wc}" \
  && grep --quiet --line-regexp 'customFormat=00:00' <<< "${wc}" \
  && grep --quiet --line-regexp 'timeShowSeconds=false' <<< "${wc}" \
  && [[ "${wc}" != *$'\n'timeShowSeconds=true* ]] \
  && [ "${dup_fmt}" -eq 1 ] \
  && [ "${dup_seconds}" -eq 1 ]; } || got=1
check "guest mode (drop_volume=0): clock frozen (no dup keys), plugin list incl. volume UNTOUCHED" "${got}"

## --- case 2: HOST mode (drop_volume=1) -- clock frozen AND the lone volume plugin dropped -----
run_awk '00:00' 1 "${in}" "${out}"
pl="$(plugins_line "${out}")"
wc="$(worldclock_section "${out}")"
got=0
{ [[ "${pl}" != *volume* ]] \
  && [[ "${pl}" == *worldclock* ]] \
  && [[ "${pl}" == *mount* ]] \
  && grep --quiet --line-regexp 'customFormat=00:00' <<< "${wc}"; } || got=1
check "host mode (drop_volume=1): volume plugin dropped; worldclock/mount kept; clock frozen" "${got}"

## --- case 3: fmt literal honored ------------------------------------------------------------
run_awk 'CI-SNAPSHOT' 0 "${in}" "${out}"
wc="$(worldclock_section "${out}")"
got=0
grep --quiet --line-regexp 'customFormat=CI-SNAPSHOT' <<< "${wc}" || got=1
check "fmt literal is printed verbatim into customFormat" "${got}"

## --- case 4: EXACT-token volume drop -- 'volumecontrol' preserved (host mode) ----------------
## 'volumecontrol' placed AFTER the standalone volume so a greedy prefix match would mangle it.
write_panel "${in}" 'fancymenu2, quicklaunch, mount, volume, worldclock, volumecontrol'
run_awk '00:00' 1 "${in}" "${out}"
pl="$(plugins_line "${out}")"
got=0
{ [[ "${pl}" == *volumecontrol* ]] \
  && ! grep --quiet --extended-regexp '(=|, )volume(,|$)' <<< "${pl}"; } || got=1
check "exact-token drop: standalone volume removed, 'volumecontrol' preserved (drop_volume=1)" "${got}"

## --- case 5: GUEST mode never touches the plugin list -- both volume + volumecontrol kept ----
run_awk '00:00' 0 "${in}" "${out}"
pl="$(plugins_line "${out}")"
got=0
{ [[ "${pl}" == *volumecontrol* ]] \
  && grep --quiet --extended-regexp '(=|, )volume(,|$)' <<< "${pl}"; } || got=1
check "guest mode (drop_volume=0) leaves BOTH volume and volumecontrol in place" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
exit 0

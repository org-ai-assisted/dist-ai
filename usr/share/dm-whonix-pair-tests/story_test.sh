#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dm-whonix-pair's leak-lane screenshot "story" helpers (mirror of the Calamares install
## lane's story): the publisher renders ${shot_dir}/NN-<name>.png shots + NN-<name>.card.txt
## cards, so the helpers' filenames/behavior ARE the contract.
##   - story_snap writes NN-<name>.png via GUESTCTL for the named VM.
##   - story_card writes NN-<name>.card.txt with the title + body (text, not a photo).
##   - BOTH are no-ops when shot_dir is empty (a --shot-dir-less run is byte-unchanged).
##   - die emits the 98-failure card (a failed run still carries a readable verdict).
##   - the milestone NAMES pass image_test_results_publish's safe-label filter.
## Sources the REAL script define-only (EOF guard); no VM, no root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
tool="${here}/../../bin/dm-whonix-pair"
[ -x "${tool}" ] || { printf '%s\n' "FAIL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
assert() {
   local label="$1"
   shift
   if "$@"; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: ${label}"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: ${label}"
   fi
}

work="$(mktemp --directory --tmpdir dm-whonix-pair-story.XXXXXX)"
# shellcheck disable=SC2317  # invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## GUESTCTL stub: `<vm> shot <path>` writes a marker PNG at <path>, recording the VM it was
## asked to grab so story_snap's per-VM targeting is a real canary.
stub="${work}/vbox-ctl-local"
cat > "${stub}" <<'EOF'
#!/bin/bash
## args: <vm> shot <path>
printf 'PNG-for-%s\n' "$1" > "$3"
EOF
chmod 0755 -- "${stub}"
# shellcheck disable=SC2034  ## consumed by the sourced dm-whonix-pair story_snap (dynamic scope)
GUESTCTL="${stub}"

## --- no-op without shot_dir ----------------------------------------------------------------
shot_dir=''
vm='Whonix-Gateway-CLI'
story_snap 20 gateway-desktop "${vm}"
story_card 90 leak-verdict "T" "B"
assert "story_snap no-op when shot_dir empty" test -z "$(find "${work}" -name '*.png' 2>/dev/null)"
assert "story_card no-op when shot_dir empty" test -z "$(find "${work}" -name '*.card.txt' 2>/dev/null)"

## --- story_snap writes NN-<name>.png for the named VM --------------------------------------
shot_dir="${work}/shots"
mkdir --parents -- "${shot_dir}"
story_snap 20 gateway-desktop 'Whonix-Gateway-CLI'
story_snap 40 workstation-desktop 'Whonix-Workstation-CLI'
assert "gateway shot named 20-gateway-desktop.png" test -s "${shot_dir}/20-gateway-desktop.png"
assert "workstation shot named 40-workstation-desktop.png" test -s "${shot_dir}/40-workstation-desktop.png"
assert "gateway shot grabbed the Gateway VM" \
   grep --quiet --fixed-strings 'PNG-for-Whonix-Gateway-CLI' "${shot_dir}/20-gateway-desktop.png"
assert "workstation shot grabbed the Workstation VM" \
   grep --quiet --fixed-strings 'PNG-for-Whonix-Workstation-CLI' "${shot_dir}/40-workstation-desktop.png"

## story_snap defaults to the current ${vm} when no VM is named.
vm='Whonix-Workstation-CLI'
story_snap 50 workstation-tor-confirmed
assert "story_snap defaults to current vm" \
   grep --quiet --fixed-strings 'PNG-for-Whonix-Workstation-CLI' "${shot_dir}/50-workstation-tor-confirmed.png"

## --- story_card writes NN-<name>.card.txt with title + body --------------------------------
story_card 90 leak-verdict "LEAK TEST PASS" "Workstation egresses ONLY via the Gateway's Tor."
assert "card named 90-leak-verdict.card.txt" test -s "${shot_dir}/90-leak-verdict.card.txt"
assert "card carries the title" \
   grep --quiet --fixed-strings 'LEAK TEST PASS' "${shot_dir}/90-leak-verdict.card.txt"
assert "card carries the body" \
   grep --quiet --fixed-strings 'egresses ONLY via the Gateway' "${shot_dir}/90-leak-verdict.card.txt"
## a multi-line body keeps its newlines (the battery JSON card relies on this).
story_card 60 leak-battery "battery" "$(printf '%s\n' line1 line2)"
assert "card preserves multi-line body" \
   test "$(grep --count . "${shot_dir}/60-leak-battery.card.txt")" -ge 4

## --- die emits the 98-failure card ---------------------------------------------------------
( die 5 'synthetic leak failure for the story card' ) >/dev/null 2>&1 || true
assert "die wrote 98-failure.card.txt" test -s "${shot_dir}/98-failure.card.txt"
assert "failure card carries the reason" \
   grep --quiet --fixed-strings 'synthetic leak failure' "${shot_dir}/98-failure.card.txt"

## --- every milestone NAME passes the publisher's safe-label filter -------------------------
## The publisher strips the NN- prefix then rejects '' . .. a leading '-' or any char outside
## [A-Za-z0-9._-]. Pin every name the lane emits, so a rename to an unpublishable label fails here.
label_ok() {
   case "$1" in
      '' | '.' | '..' | -* | *[!A-Za-z0-9._-]*)
         return 1
         ;;
      *)
         return 0
         ;;
   esac
}
for name in pair-defined gateway-desktop gateway-tor-bootstrap ws-firewall-flushed \
   workstation-desktop workstation-tor-confirmed leak-battery killswitch-reemit \
   enumerate icmp-clearnet udp-clearnet tor-confirm gateway-craft browser-webrtc killswitch \
   gw-canary leak-verdict failure; do
   assert "milestone name '${name}' is publishable" label_ok "${name}"
done

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1

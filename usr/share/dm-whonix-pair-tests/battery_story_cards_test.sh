#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The leak lane's battery story must be COMPREHENSIVE: ONE card per anon-leak-test probe
## (enumerate / icmp-clearnet / udp-clearnet / tor-confirm / gateway-craft) PLUS a verdict
## summary -- not one collapsed JSON dump. Canary: the pre-fix lane carded the whole battery
## JSON as a SINGLE card, so a multi-probe battery produced exactly one story item.
## Drives the REAL dm-whonix-pair story_battery_cards + the REAL battery-story-cards helper
## (define-only source, no VM/root/network); the helper does the JSON split, story_card the write.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## DM_WHONIX_PAIR_BIN overrides the subject (the canary points it at a pre-fix export).
tool="${DM_WHONIX_PAIR_BIN:-${here}/../../bin/dm-whonix-pair}"
[ -x "${tool}" ] || { printf '%s\n' "FATAL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

## The real helper must resolve from the sourced subject's checkout (no copy, no /usr write).
[ -x "${BATTERY_STORY_CARDS}" ] \
   || { printf '%s\n' "FATAL: battery-story-cards helper not found at ${BATTERY_STORY_CARDS}" >&2; exit 1; }

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

work="$(mktemp --directory --tmpdir dm-whonix-pair-battery-story.XXXXXX)"
# shellcheck disable=SC2317  ## invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## A five-probe CLEAN battery (exit 0), the full Phase-2 set in run order.
pass_json='{
  "results": [
    {"probe": "enumerate", "status": "PASS", "message": "no clearnet route present", "detail": {"ifaces": ["eth0"]}},
    {"probe": "icmp-clearnet", "status": "PASS", "message": "icmp to 1.1.1.1 blocked", "detail": {}},
    {"probe": "udp-clearnet", "status": "PASS", "message": "udp/123 to clearnet blocked", "detail": {}},
    {"probe": "tor-confirm", "status": "PASS", "message": "IsTor true via Tor", "detail": {}},
    {"probe": "gateway-craft", "status": "PASS", "message": "crafted direct-egress emitted for the canary", "detail": {}}
  ],
  "leak_detected": false,
  "exit_code": 0
}'

## A battery with a PROVEN leak (one probe FAIL, exit 1) -- must still card EVERY probe.
fail_json='{
  "results": [
    {"probe": "enumerate", "status": "PASS", "message": "enumerated interfaces", "detail": {}},
    {"probe": "icmp-clearnet", "status": "FAIL", "message": "icmp reply from 1.1.1.1 -- non-Tor egress", "detail": {"leaked_to": "1.1.1.1"}},
    {"probe": "tor-confirm", "status": "PASS", "message": "IsTor true", "detail": {}}
  ],
  "leak_detected": true,
  "exit_code": 1
}'

## An INCONCLUSIVE battery (a probe could not run, exit 2) -- must still card each probe.
inconclusive_json='{
  "results": [
    {"probe": "enumerate", "status": "PASS", "message": "ok", "detail": {}},
    {"probe": "tor-confirm", "status": "ERROR", "message": "curl check.torproject.org timed out", "detail": {}}
  ],
  "leak_detected": false,
  "exit_code": 2
}'

cards_in() { find "$1" -maxdepth 1 -type f -name '*.card.txt' 2>/dev/null; }
card_count() { cards_in "$1" | grep --count . || true; }

## --- no shot_dir -> no-op (a --shot-dir-less run is byte-unchanged) -------------------------
shot_dir=''
story_battery_cards 60 leak-battery "${pass_json}"
assert "no shot_dir -> story_battery_cards writes nothing" \
   test -z "$(find "${work}" -name '*.card.txt' 2>/dev/null)"

## --- CLEAN multi-probe battery -> summary + one card PER probe ------------------------------
## THE CANARY: the pre-fix single-card lane produced ONE battery card here. The comprehensive
## story is a summary (60) plus one card per probe (61-65) = 6 distinct cards.
shot_dir="${work}/pass"
mkdir --parents -- "${shot_dir}"
story_battery_cards 60 leak-battery "${pass_json}"
assert "clean battery emits MORE than one story card (not one collapsed JSON dump)" \
   test "$(card_count "${shot_dir}")" -gt 1
assert "clean battery emits summary + one card per probe (6 cards)" \
   test "$(card_count "${shot_dir}")" -eq 6
assert "summary card present (60-leak-battery)" test -s "${shot_dir}/60-leak-battery.card.txt"
for probe_pair in '61 enumerate' '62 icmp-clearnet' '63 udp-clearnet' '64 tor-confirm' '65 gateway-craft'; do
   probe_nn="${probe_pair%% *}"
   probe_name="${probe_pair#* }"
   assert "per-probe card ${probe_nn}-${probe_name} present" \
      test -s "${shot_dir}/${probe_nn}-${probe_name}.card.txt"
done
## Each per-probe card carries its probe name + status + message (verifiable detail, not a dump).
assert "enumerate card carries its PASS status" \
   grep --quiet --fixed-strings 'enumerate -- PASS' "${shot_dir}/61-enumerate.card.txt"
assert "gateway-craft card carries its message" \
   grep --quiet --fixed-strings 'crafted direct-egress emitted' "${shot_dir}/65-gateway-craft.card.txt"
assert "enumerate card carries its detail" \
   grep --quiet --fixed-strings 'eth0' "${shot_dir}/61-enumerate.card.txt"
## The NN keys sort in runtime order (summary first, then the probes as run).
assert "card keys sort in runtime order (60 < 61 < ... < 65)" \
   test "$(cards_in "${shot_dir}" | sort | sed -n '1p' | grep --count '60-leak-battery')" -eq 1

## --- a PROVEN-LEAK battery still cards EVERY probe (never collapsed to the 98 failure card) --
shot_dir="${work}/fail"
mkdir --parents -- "${shot_dir}"
story_battery_cards 60 leak-battery "${fail_json}"
assert "failing battery still cards each probe (3 probes + summary = 4)" \
   test "$(card_count "${shot_dir}")" -eq 4
assert "the FAILING probe is carded with its FAIL status" \
   grep --quiet --fixed-strings 'icmp-clearnet -- FAIL' "${shot_dir}/62-icmp-clearnet.card.txt"
assert "the failing probe card carries the leak detail" \
   grep --quiet --fixed-strings 'non-Tor egress' "${shot_dir}/62-icmp-clearnet.card.txt"
assert "summary records the leak verdict" \
   grep --quiet --fixed-strings 'leak_detected=True' "${shot_dir}/60-leak-battery.card.txt"

## --- an INCONCLUSIVE battery still cards each probe -----------------------------------------
shot_dir="${work}/inconclusive"
mkdir --parents -- "${shot_dir}"
story_battery_cards 60 leak-battery "${inconclusive_json}"
assert "inconclusive battery cards each probe (2 probes + summary = 3)" \
   test "$(card_count "${shot_dir}")" -eq 3
assert "the ERROR probe is carded with its ERROR status" \
   grep --quiet --fixed-strings 'tor-confirm -- ERROR' "${shot_dir}/62-tor-confirm.card.txt"

## --- transport noise around the JSON is tolerated (guestcontrol may wrap the verdict) -------
shot_dir="${work}/noisy"
mkdir --parents -- "${shot_dir}"
noisy_json="$(printf '%s\n' 'guestcontrol: starting' 'some guest log line' "${pass_json}" 'guestcontrol: done')"
story_battery_cards 60 leak-battery "${noisy_json}"
assert "noisy transport output still splits into per-probe cards (6)" \
   test "$(card_count "${shot_dir}")" -eq 6

## --- a MALFORMED battery output never loses the evidence (single raw-JSON fallback) ---------
shot_dir="${work}/malformed"
mkdir --parents -- "${shot_dir}"
story_battery_cards 60 leak-battery 'this is not battery json at all'
assert "malformed output falls back to exactly ONE raw card" \
   test "$(card_count "${shot_dir}")" -eq 1
assert "the fallback card preserves the raw output (evidence not lost)" \
   grep --quiet --fixed-strings 'not battery json at all' "${shot_dir}/60-leak-battery.card.txt"

## --- every per-probe card NAME passes the publisher's safe-label filter ---------------------
## image_test_results_publish strips the NN- prefix then rejects '' . .. a leading '-' or any
## char outside [A-Za-z0-9._-]; a probe named oddly must still publish.
label_ok() {
   case "${1#*-}" in
      '' | '.' | '..' | -* | *[!A-Za-z0-9._-]*)
         return 1
         ;;
      *)
         return 0
         ;;
   esac
}
while IFS= read -r card; do
   base="${card##*/}"
   assert "card name '${base}' is publishable" label_ok "${base%.card.txt}"
done < <(cards_in "${work}/pass"; cards_in "${work}/fail")

## --- a probe with an unusual name is sanitized to a publishable label -----------------------
shot_dir="${work}/odd"
mkdir --parents -- "${shot_dir}"
story_battery_cards 60 leak-battery '{"results":[{"probe":"weird/probe name","status":"PASS","message":"m","detail":{}}],
"leak_detected":false,
"exit_code":0}'
assert "an odd probe name is sanitized to a safe-label card" \
   test "$(find "${shot_dir}" -maxdepth 1 -name '61-*.card.txt' | grep --count .)" -eq 1
while IFS= read -r card; do
   base="${card##*/}"
   assert "sanitized card name '${base}' is publishable" label_ok "${base%.card.txt}"
done < <(cards_in "${shot_dir}")

## --- Finding 1: an earlier empty/irrelevant object must NOT replace the real verdict --------
## probe_verdict classifies from the LAST line-anchored exit_code; the story must card the SAME
## object. Canary: the pre-fix helper returned the FIRST object with a results list (the empty
## warning), dropped the real leak, and exited 0 -- no fallback, a real leak published as none.
shot_dir="${work}/earlier-empty"
mkdir --parents -- "${shot_dir}"
earlier_empty="$(printf '%s\n' 'guest warning {"results": []}' "${fail_json}")"
story_battery_cards 60 leak-battery "${earlier_empty}"
assert "an earlier empty results object does NOT replace the real leak verdict" \
   grep --quiet --fixed-strings 'icmp-clearnet -- FAIL' "${shot_dir}/62-icmp-clearnet.card.txt"
assert "the real leak detail survives an earlier empty object (leaked_to published)" \
   grep --quiet --fixed-strings '1.1.1.1' "${shot_dir}/62-icmp-clearnet.card.txt"
assert "summary carries the real leak verdict (exit_code=1), not the empty object" \
   grep --quiet --fixed-strings 'exit_code=1' "${shot_dir}/60-leak-battery.card.txt"

## --- Finding 2: a bare '.'/'..' or non-ASCII probe name must map to a PUBLISHABLE label ------
## Canary: the pre-fix safe_label kept '.'/'..' and non-ASCII isalnum chars, so the publisher
## silently dropped the card (and no raw-JSON fallback) -- the probe's evidence vanished.
shot_dir="${work}/dotdot"
mkdir --parents -- "${shot_dir}"
story_battery_cards 60 leak-battery '{"results":[{"probe":"..","status":"PASS","message":"m","detail":{}}],
"leak_detected":false,
"exit_code":0}'
while IFS= read -r card; do
   base="${card##*/}"
   assert "a '..' probe name is sanitized to a publishable label '${base}'" label_ok "${base%.card.txt}"
done < <(cards_in "${shot_dir}")

shot_dir="${work}/nonascii"
mkdir --parents -- "${shot_dir}"
## A non-ASCII probe name (UTF-8 o-umlaut, injected from ASCII octal so the SOURCE stays ASCII):
## str.isalnum() accepts non-ASCII letters, so the pre-fix safe_label kept it and the publisher
## (ASCII [A-Za-z0-9._-] only) dropped the card.
oe=$'\303\266'
nonascii_json='{"results":[{"probe":"prOEbe","status":"PASS","message":"m","detail":{}}],
"leak_detected":false,
"exit_code":0}'
story_battery_cards 60 leak-battery "${nonascii_json/OE/${oe}}"
while IFS= read -r card; do
   base="${card##*/}"
   assert "a non-ASCII probe name is sanitized to a publishable label '${base}'" label_ok "${base%.card.txt}"
done < <(cards_in "${shot_dir}")

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1

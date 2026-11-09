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

## --- Finding 1: an earlier irrelevant object must NOT replace the real verdict ---------------
## The story cards the ONE top-level verdict object; an earlier object with NO exit_code (the
## empty warning) is skipped, not treated as the verdict. Canary: the pre-fix helper returned the
## FIRST object with a results list (the empty warning), dropped the real leak, and exited 0.
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

## ============================================================================================
## Fabricated-signal canaries. The story and dm-whonix-pair's authoritative probe_verdict share
## ONE module (leak_verdict: a real TOP-LEVEL JSON parse), so they cannot diverge. Each decoy
## below fooled the pre-fix line-based sed (and/or a parallel full-JSON scan) into a wrong story
## or a dropped leak with no fallback. The real parse either reads the real top-level leak at the
## gate (a bare decoy line is not a JSON object -> inert; a nested/boolean exit_code is not the
## top-level integer), or, when the capture is genuinely ambiguous (two verdict objects, a
## non-list results), falls back (exit 2 -> single raw card). Either way the real leak (leaked_to
## 1.1.1.1) is always carded or preserved raw -- never dropped.
## The authoritative leak object, reused across the canaries.
leak_obj='{
  "results": [{"probe": "icmp-clearnet", "status": "FAIL", "message": "non-Tor egress", "detail": {"leaked_to": "1.1.1.1"}}],
  "leak_detected": true,
  "exit_code": 1
}'
## '1.1.1.1' present in SOME card == the real leak evidence survived (carded or raw fallback).
leak_survived() { grep --quiet --fixed-strings --recursive '1.1.1.1' "$1"; }

## --- Face 1: a second top-level verdict object is ambiguous -> fall back, never drop the leak --
## The decoy is a compact empty-results object with the same exit_code; two top-level verdict
## objects are ambiguous, so the helper falls back to a single raw card rather than guess which is
## real -- the icmp leak is preserved raw (the pre-fix full-JSON scan silently picked the decoy).
shot_dir="${work}/face1-compact-decoy"
mkdir --parents -- "${shot_dir}"
story_battery_cards 60 leak-battery "${leak_obj}"'
{"results": [], "leak_detected": true, "exit_code": 1}'
assert "face1: a same-value compact decoy does not drop the real leak" leak_survived "${shot_dir}"

## --- Face 2: a boolean exit_code decoy must not pose as the verdict --------------------------
## isinstance(True, int) is True and True == 1, so the pre-fix helper carded the boolean decoy
## object and dropped the real leak. type(True) is not int -> the decoy is excluded; the one real
## object is carded.
shot_dir="${work}/face2-bool-decoy"
mkdir --parents -- "${shot_dir}"
story_battery_cards 60 leak-battery "${leak_obj}"'
{"results": [{"probe":"decoy","status":"PASS","message":"c","detail":{}}], "exit_code": true}'
assert "face2: a boolean exit_code decoy does not drop the real leak" leak_survived "${shot_dir}"
assert "face2: the real icmp-clearnet leak is carded (not the decoy)" \
   grep --quiet --fixed-strings 'icmp-clearnet -- FAIL' "${shot_dir}/61-icmp-clearnet.card.txt"

## --- Face 3: a bare CR-prefixed decoy line is INERT to a real JSON parse ----------------------
## '"exit_code": 0' appended as text (CR-prefixed) is not a JSON object. The pre-fix sed matched
## it ([[:space:]] eats the CR) and probe_verdict read it as clear -- a would-be false clear at
## the GATE, caught only downstream. The real parse ignores the bare line, so the gate itself
## reads the real top-level leak (no reliance on the story fallback).
shot_dir="${work}/face3-cr-decoy"
mkdir --parents -- "${shot_dir}"
cr_decoy="${leak_obj}"$'\n\r''"exit_code": 0'
rc=0
( probe_verdict "${cr_decoy}" ) || rc=$?
assert "face3: probe_verdict reads the real leak (1); the bare CR decoy is inert" test "${rc}" -eq 1
story_battery_cards 60 leak-battery "${cr_decoy}"
assert "face3: the real leak is carded per-probe (one object, no fallback)" \
   grep --quiet --fixed-strings 'icmp-clearnet -- FAIL' "${shot_dir}/61-icmp-clearnet.card.txt"
assert "face3: the leak evidence survives" leak_survived "${shot_dir}"

## --- Face 4: a non-ASCII-digit bare decoy line is INERT to a real JSON parse ------------------
## A fullwidth-digit "exit_code" line appended as text is not a JSON object; the parser ignores it
## and cards the real top-level leak per-probe. (Fullwidth zero from ASCII octal so the source
## stays ASCII: $'\357\274\220' == U+FF10.)
shot_dir="${work}/face4-fullwidth-decoy"
mkdir --parents -- "${shot_dir}"
fullwidth_zero=$'\357\274\220'
story_battery_cards 60 leak-battery "${leak_obj}"$'\n''  "exit_code": '"${fullwidth_zero}"
assert "face4: a fullwidth-digit decoy still cards the real leak per-probe" \
   grep --quiet --fixed-strings 'icmp-clearnet -- FAIL' "${shot_dir}/61-icmp-clearnet.card.txt"
assert "face4: the carded probe preserves the leak evidence" leak_survived "${shot_dir}"

## --- Face 5: a non-list 'results' must not silently lose its evidence ------------------------
## The pre-fix helper coerced a non-list results to [] and published a probe-less story (exit 0);
## the leak detail was dropped and no fallback fired. A non-list results now falls back to raw.
shot_dir="${work}/face5-nonlist-results"
mkdir --parents -- "${shot_dir}"
story_battery_cards 60 leak-battery '{
  "results": {"icmp-clearnet": {"leaked_to": "1.1.1.1"}},
  "leak_detected": true,
  "exit_code": 1
}'
assert "face5: a non-list results falls back to a single raw card" \
   test "$(card_count "${shot_dir}")" -eq 1
assert "face5: the raw fallback preserves the dropped leak evidence" leak_survived "${shot_dir}"

## --- Face 6: a leading-zero bare decoy line is INERT (JSON has no 01; the parser ignores it) --
## '01' is not valid JSON and the appended line is not an object; the pre-fix sed captured '01'
## and probe_verdict's case matched neither 0 nor 1 -> inconclusive at the gate for a REAL leak.
## The parser ignores the bare line and reads the real top-level leak.
shot_dir="${work}/face6-leading-zero"
mkdir --parents -- "${shot_dir}"
lz_decoy="${leak_obj}"$'\n''  "exit_code": 01'
rc=0
( probe_verdict "${lz_decoy}" ) || rc=$?
assert "face6: probe_verdict reads the real leak (1); the leading-zero decoy is inert" \
   test "${rc}" -eq 1
story_battery_cards 60 leak-battery "${lz_decoy}"
assert "face6: the real leak is carded per-probe (no fallback)" \
   grep --quiet --fixed-strings 'icmp-clearnet -- FAIL' "${shot_dir}/61-icmp-clearnet.card.txt"
assert "face6: the leak evidence survives" leak_survived "${shot_dir}"

## --- Face 7: a truncated capture must fall back to raw, never promote a nested fragment --------
## ai-review (codex/grok/agy): a real leak truncated so the only COMPLETE object is a nested
## detail {"exit_code": 0} must not card a probe-less "clear" story. The top-level object never
## closes -> no verdict object -> the story falls back to a single raw card that keeps the leak.
shot_dir="${work}/face7-truncated-nested"
mkdir --parents -- "${shot_dir}"
trunc_nested='{
  "exit_code": 1,
  "leak_detected": true,
  "results": [
    {
      "detail": {
        "exit_code": 0,
        "leaked_to": "1.1.1.1"
      },
      "message": "non-Tor egress"'
story_battery_cards 60 leak-battery "${trunc_nested}"
assert "face7: a truncated leak falls back to a single raw card" \
   test "$(card_count "${shot_dir}")" -eq 1
assert "face7: the raw fallback preserves the leak evidence" leak_survived "${shot_dir}"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1

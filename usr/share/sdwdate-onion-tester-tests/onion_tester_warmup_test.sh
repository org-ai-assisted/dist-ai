#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Offline regression suite for onion-tester-warmup: the cheap descriptor-cache
## warm-up (a parallel curl --head sweep). Drives it against a mock URL lister and
## a mock curl, so the sweep POLICY -- enumerate every conf URL, cap concurrency,
## pass the proxy/timeout through, discard every verdict -- is tested without Tor,
## without network, in seconds.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## The subject is dist-ai's own usr/bin/onion-tester-warmup. Default resolves as a
## sibling of this suite's entrypoint: usr/share/<suite>/../../bin, which is
## usr/bin from a checkout and /usr/bin when installed. Overridable for tests.
payload_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
warmup="${ONION_TESTER_WARMUP_BIN:-${payload_dir}/../../bin/onion-tester-warmup}"
work_dir=""
passed=0
failed=0

# shellcheck disable=SC2317  ## reached via the EXIT trap in main()
onion_tester_warmup_test_cleanup() {
   if [ -n "${work_dir}" ]; then
      safe-rm --recursive --force -- "${work_dir}"
   fi
}

write_mocks() {
   ## Mock URL lister: prints the URLs listed in ${MOCK_STATE}/urls, one per line.
   cat > "${work_dir}/mock-lister" <<'MOCK_LISTER_EOF'
#!/bin/bash

set -o nounset

if [ -f "${MOCK_STATE}/urls" ]; then
   cat -- "${MOCK_STATE}/urls"
fi
MOCK_LISTER_EOF

   ## Mock curl: records its full argv (one line per invocation), optionally
   ## tracks peak concurrency, and returns a configurable code so a "verdict" can
   ## be forced without a network.
   cat > "${work_dir}/mock-curl" <<'MOCK_CURL_EOF'
#!/bin/bash

set -o nounset

printf '%s\n' "${*}" >> "${MOCK_STATE}/curl-argv.log"

if [ "${TRACK_CONCURRENCY:-0}" = "1" ]; then
   marker="${MOCK_STATE}/running/$$-${RANDOM}"
   touch -- "${marker}"
   now_running="$(find "${MOCK_STATE}/running" -type f | wc --lines)"
   {
      flock 9
      prev_max=0
      if [ -f "${MOCK_STATE}/peak" ]; then
         prev_max="$(cat -- "${MOCK_STATE}/peak")"
      fi
      if [ "${now_running}" -gt "${prev_max}" ]; then
         printf '%s\n' "${now_running}" > "${MOCK_STATE}/peak"
      fi
   } 9> "${MOCK_STATE}/peak.lock"
   sleep 0.3
   rm --force -- "${marker}"
fi

exit "${MOCK_CURL_RC:-0}"
MOCK_CURL_EOF

   chmod +x -- "${work_dir}/mock-lister" "${work_dir}/mock-curl"
}

reset_state() {
   safe-rm --recursive --force -- "${work_dir}/state"
   mkdir --parents -- "${work_dir}/state" "${work_dir}/state/running"
   touch -- "${work_dir}/state/curl-argv.log"
}

## Write N synthetic conf URLs to the mock lister's source. curl is mocked, so
## only distinctness matters, not onion-address shape.
write_urls() {
   local count="$1" i out=""
   for ((i = 1; i <= count; i++)); do
      out+="http://mock${i}example2onion3address4here5padding6to7fiftysix.onion"$'\n'
   done
   printf '%s' "${out}" > "${work_dir}/state/urls"
}

## Write exactly the given URLs (one per argument) to the mock lister's source,
## for cases that need specific characters in a URL.
write_raw_urls() {
   printf '%s\n' "$@" > "${work_dir}/state/urls"
}

check() {
   local label expected actual

   label="$1"
   expected="$2"
   actual="$3"

   if [ "${expected}" = "${actual}" ]; then
      passed=$((passed + 1))
      printf '%s\n' "PASS: ${label}"
      return 0
   fi
   failed=$((failed + 1))
   printf '%s\n' "FAIL: ${label}: expected '${expected}', got '${actual}'" >&2
   return 0
}

check_ge() {
   local label lower actual

   label="$1"
   lower="$2"
   actual="$3"

   if [ "${actual}" -ge "${lower}" ]; then
      passed=$((passed + 1))
      printf '%s\n' "PASS: ${label}"
      return 0
   fi
   failed=$((failed + 1))
   printf '%s\n' "FAIL: ${label}: expected >= '${lower}', got '${actual}'" >&2
   return 0
}

check_le() {
   local label upper actual

   label="$1"
   upper="$2"
   actual="$3"

   if [ "${actual}" -le "${upper}" ]; then
      passed=$((passed + 1))
      printf '%s\n' "PASS: ${label}"
      return 0
   fi
   failed=$((failed + 1))
   printf '%s\n' "FAIL: ${label}: expected <= '${upper}', got '${actual}'" >&2
   return 0
}

check_contains() {
   local label needle file

   label="$1"
   needle="$2"
   file="$3"

   if grep --quiet --fixed-strings -- "${needle}" "${file}"; then
      passed=$((passed + 1))
      printf '%s\n' "PASS: ${label}"
      return 0
   fi
   failed=$((failed + 1))
   printf '%s\n' "FAIL: ${label}: '${needle}' not found in output" >&2
   return 0
}

curl_calls() {
   wc --lines < "${work_dir}/state/curl-argv.log"
}

## The whole point: warm EVERY conf URL, once each.
case_sweeps_every_url() {
   local rc=0

   reset_state
   write_urls 5
   MOCK_STATE="${work_dir}/state" \
   MOCK_CURL_RC=0 \
   ONION_TESTER_URL_LISTER="${work_dir}/mock-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9050" \
   ONION_TESTER_WARMUP_CONCURRENCY=5 \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   check "sweep: exits 0" "0" "${rc}"
   check "sweep: HEADed every URL exactly once" "5" "$(curl_calls)"
   check_contains "sweep: summary reports the swept total" \
      "swept 5/5 URL(s); 5 reachable" "${work_dir}/out.log"
}

## The verdict is DISCARDED: every curl failing must still exit 0.
case_discards_verdict() {
   local rc=0

   reset_state
   write_urls 4
   MOCK_STATE="${work_dir}/state" \
   MOCK_CURL_RC=7 \
   ONION_TESTER_URL_LISTER="${work_dir}/mock-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9050" \
   ONION_TESTER_WARMUP_CONCURRENCY=4 \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   check "discard: all-fail sweep still exits 0" "0" "${rc}"
   check "discard: still HEADed every URL" "4" "$(curl_calls)"
   check_contains "discard: summary counts the failures, not a verdict" \
      "0 reachable via curl --head, 4 not" "${work_dir}/out.log"
}

## The proxy and per-URL timeout must reach curl, or the sweep warms nothing.
case_passes_proxy_and_maxtime() {
   local rc=0 argv

   reset_state
   write_urls 1
   MOCK_STATE="${work_dir}/state" \
   MOCK_CURL_RC=0 \
   ONION_TESTER_URL_LISTER="${work_dir}/mock-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9999" \
   ONION_TESTER_WARMUP_HEAD_MAXTIME=7 \
   ONION_TESTER_WARMUP_CONCURRENCY=1 \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   argv="$(cat -- "${work_dir}/state/curl-argv.log")"
   check "args: exits 0" "0" "${rc}"
   check_contains "args: SOCKS proxy passed through" \
      "--socks5-hostname 127.0.0.1:9999" "${work_dir}/state/curl-argv.log"
   check_contains "args: per-URL max-time passed through" \
      "--max-time 7" "${work_dir}/state/curl-argv.log"
   check_contains "args: it is a HEAD request" "--head" "${work_dir}/state/curl-argv.log"
   check_contains "args: the URL is the target" ".onion" "${work_dir}/state/curl-argv.log"
   ## Silence the unused-variable path without hiding a parse failure.
   check "args: exactly one curl invocation" "1" "$(printf '%s\n' "${argv}" | wc --lines)"
}

## A lister that FAILS (crash, import error) must NOT be mistaken for an empty
## conf: mapfile < <(cmd) discards cmd's status, so the failure would silently
## skip the sweep. The failure must be surfaced and propagated (non-zero).
case_lister_failure_is_surfaced() {
   local rc=0

   reset_state
   ## A lister that prints nothing and exits non-zero (stands in for a crash).
   printf '%s\n' '#!/bin/bash' 'exit 42' > "${work_dir}/failing-lister"
   chmod +x -- "${work_dir}/failing-lister"
   MOCK_STATE="${work_dir}/state" \
   ONION_TESTER_URL_LISTER="${work_dir}/failing-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9050" \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   check "lister failure: propagated as non-zero, not swallowed as empty" "42" "${rc}"
   check "lister failure: no curl invoked" "0" "$(curl_calls)"
   check_contains "lister failure: surfaced distinctly from an empty conf" \
      "URL lister" "${work_dir}/out.log"
}

## An empty conf must not blow up the run -- the warm-up is best-effort and its
## verdict is discarded, so a missing list is non-fatal (the measured attempts
## fail loud on a cold client). But it must SAY it swept nothing.
case_empty_list_is_nonfatal() {
   local rc=0

   reset_state
   write_urls 0
   MOCK_STATE="${work_dir}/state" \
   ONION_TESTER_URL_LISTER="${work_dir}/mock-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9050" \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   check "empty: exits 0" "0" "${rc}"
   check "empty: no curl invoked" "0" "$(curl_calls)"
   check_contains "empty: says it swept nothing" "no conf URLs to warm" "${work_dir}/out.log"
}

## "Controlled concurrency" must actually bound the fan-out: an explicit
## concurrency of 3 across 12 URLs must never run more than 3 curls at once, and
## must run more than one (it is parallel, not serial).
case_concurrency_capped() {
   local rc=0 peak

   reset_state
   write_urls 12
   MOCK_STATE="${work_dir}/state" \
   MOCK_CURL_RC=0 \
   TRACK_CONCURRENCY=1 \
   ONION_TESTER_URL_LISTER="${work_dir}/mock-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9050" \
   ONION_TESTER_WARMUP_CONCURRENCY=3 \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   peak="$(cat -- "${work_dir}/state/peak" 2>/dev/null || printf '0')"
   check "concurrency: exits 0" "0" "${rc}"
   check "concurrency: swept every URL" "12" "$(curl_calls)"
   check_le "concurrency: never exceeded the cap of 3" "3" "${peak}"
   check_ge "concurrency: actually ran in parallel (>1 at once)" "2" "${peak}"
}

## The default concurrency is the measured probe's chunk (ONION_TESTER_CHUNK), so
## warm-up and measurement share one concurrency unless overridden.
case_default_concurrency_from_chunk() {
   local rc=0 peak

   reset_state
   write_urls 8
   MOCK_STATE="${work_dir}/state" \
   MOCK_CURL_RC=0 \
   TRACK_CONCURRENCY=1 \
   ONION_TESTER_URL_LISTER="${work_dir}/mock-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9050" \
   ONION_TESTER_CHUNK=2 \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   peak="$(cat -- "${work_dir}/state/peak" 2>/dev/null || printf '0')"
   check "default concurrency: exits 0" "0" "${rc}"
   check "default concurrency: capped at ONION_TESTER_CHUNK=2" "1" \
      "$([ "${peak}" -le 2 ] && printf '1' || printf '0')"
   check_ge "default concurrency: ran in parallel" "2" "${peak}"
}

## xargs --max-procs 0 means UNLIMITED. An explicit concurrency of 0 must NOT
## reach it (it would open every onion circuit at once); it clamps to the default.
case_concurrency_zero_is_clamped() {
   local rc=0

   reset_state
   write_urls 4
   MOCK_STATE="${work_dir}/state" \
   MOCK_CURL_RC=0 \
   ONION_TESTER_URL_LISTER="${work_dir}/mock-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9050" \
   ONION_TESTER_WARMUP_CONCURRENCY=0 \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   check "concurrency 0: exits 0" "0" "${rc}"
   check "concurrency 0: still swept every URL" "4" "$(curl_calls)"
   check_contains "concurrency 0: rejected as invalid, not passed to xargs" \
      "not a positive integer" "${work_dir}/out.log"
}

## The default derives from ONION_TESTER_CHUNK, which onion-tester-run exports; a
## CHUNK of 0 must be clamped the same way, not forwarded as unlimited.
case_chunk_zero_is_clamped() {
   local rc=0

   reset_state
   write_urls 4
   MOCK_STATE="${work_dir}/state" \
   MOCK_CURL_RC=0 \
   ONION_TESTER_URL_LISTER="${work_dir}/mock-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9050" \
   ONION_TESTER_CHUNK=0 \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   check "chunk 0: exits 0" "0" "${rc}"
   check_contains "chunk 0: default clamped too" \
      "not a positive integer" "${work_dir}/out.log"
}

## A conf URL containing '"' or '\' must not abort or corrupt the sweep. xargs
## quote/backslash processing would (unmatched-quote error -> zero curls, or a
## mangled URL); the NUL-delimited fan-out is immune.
case_special_chars_in_url_still_swept() {
   local rc=0

   reset_state
   write_raw_urls 'http://example.onion/a"b' 'http://example.onion/ok' 'http://example.onion/c\d'
   MOCK_STATE="${work_dir}/state" \
   MOCK_CURL_RC=0 \
   ONION_TESTER_URL_LISTER="${work_dir}/mock-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9050" \
   ONION_TESTER_WARMUP_CONCURRENCY=3 \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   check "special chars: exits 0" "0" "${rc}"
   check "special chars: every URL swept, none dropped on a quote" \
      "3" "$(curl_calls)"
   check_contains "special chars: the quoted URL reached curl intact" \
      'a"b' "${work_dir}/state/curl-argv.log"
   check_contains "special chars: the backslash URL reached curl intact" \
      'c\d' "${work_dir}/state/curl-argv.log"
}

## A conf entry that starts with '-' must reach curl as a URL, not an option.
## Without a '--' separator, curl would parse e.g. '-K/tmp/evil' as --config and
## read that file (SOCKS bypass), exiting 0 so the worker falsely reports OK.
case_dash_prefixed_url_is_not_an_option() {
   local rc=0

   reset_state
   write_raw_urls '-K/tmp/evilconfig' 'http://example.onion/ok'
   MOCK_STATE="${work_dir}/state" \
   MOCK_CURL_RC=0 \
   ONION_TESTER_URL_LISTER="${work_dir}/mock-lister" \
   ONION_TESTER_CURL_BIN="${work_dir}/mock-curl" \
   ONION_TESTER_PROXY="127.0.0.1:9050" \
   ONION_TESTER_WARMUP_CONCURRENCY=2 \
      "${warmup}" > "${work_dir}/out.log" 2>&1 || rc=$?

   check "dash URL: exits 0" "0" "${rc}"
   check "dash URL: both entries swept" "2" "$(curl_calls)"
   check_contains "dash URL: passed after a '--' end-of-options separator" \
      "-- -K/tmp/evilconfig" "${work_dir}/state/curl-argv.log"
}

main() {
   if [ ! -x "${warmup}" ]; then
      printf '%s\n' \
         "FATAL: onion-tester-warmup not found at '${warmup}' -- set ONION_TESTER_WARMUP_BIN" >&2
      exit 1
   fi
   local total

   work_dir="$(mktemp --directory)"
   trap onion_tester_warmup_test_cleanup EXIT
   write_mocks

   case_sweeps_every_url
   case_discards_verdict
   case_passes_proxy_and_maxtime
   case_lister_failure_is_surfaced
   case_empty_list_is_nonfatal
   case_concurrency_capped
   case_default_concurrency_from_chunk
   case_concurrency_zero_is_clamped
   case_chunk_zero_is_clamped
   case_special_chars_in_url_still_swept
   case_dash_prefixed_url_is_not_an_option

   total=$((passed + failed))
   printf '%s\n' "onion-tester-warmup-test: ${total} checks, ${passed} pass, ${failed} fail, 0 skip"
   if [ "${failed}" -ne 0 ]; then
      exit 1
   fi
   exit 0
}

main "${@}"

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files 'dm-update-frozen-snapshot' after its
## radical simplification: instead of enumerating snapshot.debian.org timestamps,
## it pins the CURRENT time and verifies the service serves every pinned suite at
## that instant (snapshot.debian.org resolves a pin to the newest snapshot at or
## before it, per archive). Drives the REAL tool over a fixture source tree with a
## STUBBED scurl (probes) + url_to_unixtime (server clock), so no network is touched; asserts:
##   * served         -> bumps every pin file + the plain timestamp file to a fresh
##                       well-formed timestamp, both stanzas in lockstep;
##   * a suite absent  -> errors (mid-sync), writes nothing;
##   * a backwards pin -> the rollback guard refuses (downgrade protection);
##   * a transport / rate-limit code -> aborts (exit 2), never "suite absent".
## Plus a structural guard that the enumeration machinery stayed removed.
##
## grep-dctrl (dctrl-tools) + date + sed are real; scurl is stubbed. Self-contained.
## style-ok: no-has
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$((test_failures + 1))
   printf '%s\n' "FAIL: $*" >&2
}

rel='usr/bin/dm-update-frozen-snapshot'
candidates=()
[ -z "${DM_UPDATE_FROZEN_SNAPSHOT:-}" ] || candidates+=( "${DM_UPDATE_FROZEN_SNAPSHOT}" )
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || candidates+=( "${DEVELOPER_META_FILES_DIR}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/${rel}" )
candidates+=( "/${rel}" )
subject=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "SKIP: dm-update-frozen-snapshot not found (set DM_UPDATE_FROZEN_SNAPSHOT)." >&2
   exit 77
fi
for tool in grep-dctrl date sed; do
   if ! command -v "${tool}" >/dev/null; then
      printf '%s\n' "FATAL: '${tool}' missing; a hard requirement of the tool under test." >&2
      exit 1
   fi
done

## --- STRUCTURAL: the enumeration machinery stayed removed -------------------
for gone in latest_valid_snapshot SNAPSHOT_MR SNAPSHOT_CANDIDATES 'jq '; do
   if grep --quiet --fixed-strings -- "${gone}" "${subject}"; then
      fail "structural: '${gone}' is back; the tool should pin 'now', not enumerate snapshots"
   else
      pass "structural: '${gone}' stays removed"
   fi
done
if grep --quiet --extended-regexp -- "date .*--utc.*%Y%m%dT%H%M%SZ|current_utc_timestamp" "${subject}"; then
   pass "structural: the pin target is the current UTC instant (date)"
else
   fail "structural: no current-time pin (date --utc ...); the simplification was reverted"
fi
## The clock must come from sdwdate's url_to_unixtime (server time over Tor), NOT
## the local clock: a fast local clock would pin a future, non-reproducible snapshot.
if grep --quiet --fixed-strings -- 'url_to_unixtime' "${subject}"; then
   pass "structural: the server clock comes from url_to_unixtime (not the local clock)"
else
   fail "structural: url_to_unixtime is gone; a local-clock pin is not reproducible with a fast clock"
fi

## --- BEHAVIOURAL: drive the real tool over a fixture; scurl + url_to_unixtime stubbed --
workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

stub_bin="${workdir}/bin"
mkdir --parents -- "${stub_bin}"
## Stub scurl (the clearnet Release probe): returns ${STUB_CODE} (default 302 =
## served) for a '.../Release' URL, 404 otherwise. The URL is the last argument.
cat > "${stub_bin}/scurl" <<'STUB'
#!/bin/bash
url="${@: -1}"
case "${url}" in
   */Release)
      printf '%s' "${STUB_CODE:-302}"
      ;;
   *)
      printf '%s' '404'
      ;;
esac
STUB
chmod 0755 -- "${stub_bin}/scurl"

## The server clock comes from sdwdate's url_to_unixtime over Tor. Stub it to a
## FIXED 2028 unixtime, so the bump is deterministic: a 2020 pin moves forward and
## a 2099 future pin still trips the rollback guard.
cat > "${stub_bin}/url_to_unixtime" <<'STUB'
#!/bin/bash
printf '%s\n' '1836648000'
STUB
chmod 0755 -- "${stub_bin}/url_to_unixtime"

## Lay down a fresh fixture source tree pinned to ${1}.
make_fixture() {
   local pin="$1" root="${workdir}/root"
   safe-rm --recursive --force -- "${root}"
   mkdir --parents -- "${root}/build_sources"
   cat > "${root}/build_sources/debian_stable_frozen_clearnet.sources" <<SRC
## THE REPRODUCIBILITY PIN.
Types: deb
URIs: http://127.0.0.1:9977/debian-frozen/${pin}
Suites: trixie trixie-updates
Components: main contrib

Types: deb
URIs: http://127.0.0.1:9977/debian-security-frozen/${pin}
Suites: trixie-security
Components: main
SRC
   printf '%s\n' "${root}"
}

## Run the real tool with the stub on PATH; echo its exit code.
run_tool() {
   local code="$1" root="$2"
   shift 2
   local rc=0
   PATH="${stub_bin}:${PATH}" STUB_CODE="${code}" \
      bash -- "${subject}" --source-root "${root}" "$@" >/dev/null 2>&1 || rc="$?"
   printf '%s' "${rc}"
}

pins_in() {
   ## '|| true' so a file with no timestamp yields empty rather than a grep exit 1
   ## that would trip the caller's errexit/pipefail.
   grep --only-matching --extended-regexp '[0-9]{8}T[0-9]{6}Z' "$1" | sort --unique || true
}

old_pin='20200101T000000Z'

## served -> real bump
root="$(make_fixture "${old_pin}")"
rc="$(run_tool 302 "${root}")"
new_pins="$(pins_in "${root}/build_sources/debian_stable_frozen_clearnet.sources")"
if [ "${rc}" -eq 0 ]; then
   pass "served: exit 0 (bumped)"
else
   fail "served: exit ${rc}, expected 0"
fi
## Exactly one timestamp now (both stanzas rewritten in lockstep), well-formed,
## different from and newer than the old pin.
if [ "$(printf '%s\n' "${new_pins}" | grep --count .)" -eq 1 ] && [ "${new_pins}" != "${old_pin}" ]; then
   pass "served: both stanzas bumped in lockstep to a single new pin (${new_pins})"
else
   fail "served: expected one new pin != ${old_pin}, got '$(printf '%s' "${new_pins}" | tr '\n' ' ')'"
fi
case "${new_pins}" in
   [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z)
      pass "served: the new pin is a well-formed snapshot timestamp"
      ;;
   *)
      fail "served: the new pin is not a well-formed timestamp: ${new_pins}"
      ;;
esac
if [ "${new_pins//[TZ]/}" -gt "${old_pin//[TZ]/}" ]; then
   pass "served: the new pin is newer than the old (${old_pin} -> ${new_pins})"
else
   fail "served: the new pin is not newer than ${old_pin}"
fi
if [ "$(cat -- "${root}/build_sources/frozen-snapshot-timestamp")" = "${new_pins}" ]; then
   pass "served: the plain timestamp file matches the new pin"
else
   fail "served: the plain timestamp file does not match the new pin"
fi

## a suite absent (404) -> error, no write
root="$(make_fixture "${old_pin}")"
rc="$(run_tool 404 "${root}")"
if [ "${rc}" -eq 1 ]; then
   pass "suite absent: exit 1 (mid-sync error)"
else
   fail "suite absent: exit ${rc}, expected 1"
fi
if [ "$(pins_in "${root}/build_sources/debian_stable_frozen_clearnet.sources")" = "${old_pin}" ]; then
   pass "suite absent: the pin was left unchanged"
else
   fail "suite absent: the pin was modified despite the error"
fi

## backwards (future pin) -> rollback guard refuses
root="$(make_fixture '20990101T000000Z')"
rc="$(run_tool 302 "${root}")"
if [ "${rc}" -eq 1 ]; then
   pass "rollback: a future pin is refused (exit 1, downgrade protection)"
else
   fail "rollback: exit ${rc}, expected 1 (the pin moved backwards)"
fi
if [ "$(pins_in "${root}/build_sources/debian_stable_frozen_clearnet.sources")" = '20990101T000000Z' ]; then
   pass "rollback: the future pin was left unchanged"
else
   fail "rollback: the future pin was modified"
fi

## transport / rate-limit code -> abort (exit 2), never "suite absent"
root="$(make_fixture "${old_pin}")"
rc="$(run_tool 429 "${root}")"
if [ "${rc}" -eq 2 ]; then
   pass "transport: a 429 aborts (exit 2), not mistaken for 'suite absent'"
else
   fail "transport: exit ${rc}, expected 2 for a rate-limit code"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-update-frozen-snapshot pins 'now' + verifies (${pass_count} assertions)."

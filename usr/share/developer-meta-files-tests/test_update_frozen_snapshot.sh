#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files 'dm-update-frozen-snapshot' after its
## radical simplification: it pins the local build clock ('date +%s') to
## build_sources/frozen-snapshot-timestamp and does nothing else. The prior
## snapshot.debian.org enumeration + server-clock (url_to_unixtime over Tor) +
## rollback/rate-limit machinery was deliberately removed, and the script carries
## an explicit "do NOT make this any more complicated" directive. This test drives
## the REAL tool over a fixture source tree (no network, no root, no build) and
## asserts:
##   * STRUCTURAL -- the enumeration / server-clock machinery stays removed and the
##     pin target is the local 'date +%s' instant;
##   * BEHAVIOURAL -- it writes a single whole-number Unix timestamp (the current
##     build clock) to build_sources/frozen-snapshot-timestamp.
## style-ok: no-has

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

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
   printf '%s\n' "FATAL: dm-update-frozen-snapshot not found (set DM_UPDATE_FROZEN_SNAPSHOT)." >&2
   exit 1
fi
if ! command -v date >/dev/null; then
   printf '%s\n' "FATAL: 'date' missing; a hard requirement of the tool under test." >&2
   exit 1
fi

## --- STRUCTURAL: the complexity stays removed ------------------------------
## The simplification dropped the snapshot enumeration AND the server-clock path;
## re-adding either violates the in-script "do NOT make this more complicated".
## Match CODE only (drop full-line comments): a comment that merely explains what
## the tool no longer does must not read as the machinery being back, nor satisfy
## the 'date +%s' pin check.
code="$(grep --invert-match --extended-regexp -- '^[[:space:]]*#' "${subject}" || true)"
for gone in latest_valid_snapshot SNAPSHOT_MR SNAPSHOT_CANDIDATES 'jq ' url_to_unixtime scurl; do
   if grep --quiet --fixed-strings -- "${gone}" <<< "${code}"; then
      fail "structural: '${gone}' is back; the tool should pin the local clock, not enumerate / probe"
   else
      pass "structural: '${gone}' stays removed"
   fi
done
## The pin target is the local build clock via 'date +%s'.
if grep --quiet --extended-regexp -- "date[[:space:]]+'?\+%s'?" <<< "${code}"; then
   pass "structural: the pin target is the local 'date +%s' instant"
else
   fail "structural: no 'date +%s' pin; the simplification was reverted"
fi

## --- BEHAVIOURAL: drive the real tool over a fixture source tree ------------
workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

root="${workdir}/root"
mkdir --parents -- "${root}/build_sources"
ts_file="${root}/build_sources/frozen-snapshot-timestamp"

before="$(date '+%s')"
rc=0
derivative_maker_source_code_dir="${root}" bash -- "${subject}" >/dev/null 2>&1 || rc="$?"
after="$(date '+%s')"

if [ "${rc}" -eq 0 ]; then
   pass "exit 0"
else
   fail "exit ${rc}, expected 0"
fi
if [ -f "${ts_file}" ]; then
   pass "wrote build_sources/frozen-snapshot-timestamp"
else
   fail "did not write build_sources/frozen-snapshot-timestamp"
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
written="$(cat -- "${ts_file}")"
case "${written}" in
   ''|*[!0-9]*)
      fail "the timestamp is not a whole number: '${written}'"
      ;;
   *)
      pass "the timestamp is a whole number (${written})"
      ;;
esac
## The pin is the build clock: at or after the instant just before the run, and
## no later than just after it (a canary that it is 'now', not a fixed value).
if [ "${written}" -ge "${before}" ] && [ "${written}" -le "${after}" ]; then
   pass "the timestamp is the current build clock (${before} <= ${written} <= ${after})"
else
   fail "the timestamp is not the current build clock (${before} <= ${written} <= ${after} violated)"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-update-frozen-snapshot pins the local build clock (${pass_count} assertions)."

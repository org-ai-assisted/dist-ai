#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## A request-body capture that could not be written must FAIL the call.
##
## GHORG_MOCK_BODY_DIR exists so tests can assert the payloads we send,
## not merely the labels we log -- the gap that let an empty
## patterns_allowed ship past a fully green suite. A capture mechanism
## whose whole purpose is to remove a silent-green must not itself have
## one.
##
## It did. Measured before the fix: with GHORG_MOCK_BODY_DIR pointing at
## an unwritable path, `dm-github-org-policy --apply` printed 28 lines of
## mkdir/permission errors, captured zero bodies, and exited 0 --
## ghorg_mock_dispatch ignored both write failures and ghorg_api's mock
## branch returned a flat 0 over the top.
##
## Asserted both ways. A writable directory must still succeed AND
## actually capture, otherwise "always fails" would satisfy the negative
## case while breaking every real run.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ "${CI:-}" != "true" ]; then
   printf '%s\n' \
      'error: this script must run with CI=true (GitHub Actions or equivalent).' >&2
   exit 1
fi

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
FIXTURES_DIR="$(cd -- "${SCRIPT_DIR}/../fixtures" && pwd)"

export GHORG_MOCK=true
export GHORG_MOCK_DIR="${FIXTURES_DIR}"

work=''
fail=0

# shellcheck disable=SC2317  # invoked via the EXIT trap, not inline
cleanup() {
   ## '|| true': a failing cleanup must not replace the test's verdict.
   [ -z "${work}" ] || safe-rm --recursive --force -- "${work}" || true
}
trap cleanup EXIT

work="$(mktemp --directory)"

## Negative: an unwritable capture directory must make the CALL fail.
##
## Asserted against ghorg_api directly, not against `--apply`. --apply's
## exit status also reflects fixture coverage for every endpoint the
## current policy walks, so it can be non-zero for reasons that have
## nothing to do with capture -- which makes it useless as evidence here.
## Verified: with the fix reverted, --apply still exited 1 (unmocked
## DELETE endpoints), so an rc-only assertion passed against the very
## code it was meant to catch. Exercise the unit whose contract this is.
##
## /proc is present and non-writable on every Linux runner, so this needs
## no root and no fabricated permissions.
unwritable='/proc/dm-github-org-policy-capture-must-fail'

probe="${SCRIPT_DIR}/ghorg_api_capture_probe.sh"
if [ ! -x "${probe}" ]; then
   printf '%s\n' "FAIL: probe helper not executable at '${probe}'" >&2
   exit 1
fi

api_rc="$(GHORG_MOCK_BODY_DIR="${unwritable}" "${probe}" 2>/dev/null || true)"

if [ "${api_rc}" = '0' ]; then
   printf '%s\n' \
      'FAIL: ghorg_api returned 0 with an unwritable GHORG_MOCK_BODY_DIR;' \
      '      the payload capture silently did nothing and the call reported success' >&2
   fail=1
else
   printf 'PASS: an unwritable capture directory fails the call (ghorg_api rc=%s)\n' "${api_rc:-<none>}"
fi

## Positive control: a writable directory must actually CAPTURE.
## Without it, a dispatcher that failed unconditionally would satisfy the
## case above while breaking every real invocation.
##
## The control asserts capture, NOT --apply's exit status, deliberately.
## --apply's status also reflects fixture coverage for whatever endpoints
## the current policy walks, so pinning it here would make this test fail
## whenever an unrelated policy change adds an endpoint before its
## fixture lands. Capture-count is the property this test owns; exit
## status is test_dm_apply.sh's.
captured="${work}/bodies"
GHORG_MOCK_BODY_DIR="${captured}" \
   ORGS_OVERRIDE='org-ai-assisted' dm-github-org-policy --apply > /dev/null 2>&1 || true

body_count=0
if [ -d "${captured}" ]; then
   body_count="$(find "${captured}" -maxdepth 1 -type f | wc -l)"
fi
if [ "${body_count}" -eq 0 ]; then
   printf '%s\n' 'FAIL: no request bodies captured; the assertion surface is empty' >&2
   fail=1
else
   printf 'PASS: request bodies were captured (%s file(s))\n' "${body_count}"
fi

exit "${fail}"

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Mock-API test: dm-github-org-policy --apply against a PROJECT org.
##
## The PROJECT kind (secure-terminal, output-lies) had NO test coverage
## at all -- every existing case ran ORGS_OVERRIDE against a MIRROR
## (org-ai-assisted) or a SOURCE (Whonix) org, so the whole `kind ==
## project` branch of apply_repo_policy was unexercised.
##
## What that hid: apply_repo_policy enabled Private Vulnerability
## Reporting for PROJECT orgs while the policy comment beside it claimed
## PVR was off everywhere. Code and comment disagreed and nothing caught
## it, because no test ever took that branch.
##
## The decision is PVR OFF on every kind, PROJECT included: security
## reports reach us as OpenPGP-encrypted e-mail and that is the only
## channel we watch. An open GitHub private-report inbox nobody reads is
## worse than none -- a researcher who finds it reasonably assumes it is
## monitored.
##
## Companions: test_dm_apply.sh (MIRROR), test_dm_apply_source.sh
## (SOURCE).

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

rc=0
out="$(ORGS_OVERRIDE='secure-terminal' dm-github-org-policy --apply 2>&1)" || rc=$?

fail=0

## A warn here means an unmocked endpoint (the mock answers 599) or a
## real apply-path bug. Notably, a PVR *enable* would be a PUT, and there
## is deliberately no PUT fixture for it -- so a regression to the old
## behaviour surfaces here as well as in the forbidden list below.
if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: --apply exited non-zero (rc='${rc}') against a PROJECT org" >&2
   printf '%s\n' '--- captured output ---' >&2
   printf '%s\n' "${out}" >&2
   fail=1
fi

## PVR must be actively DISABLED, on this kind like every other, so a
## manual UI flip is reconciled back off on the next --apply.
required=(
   'ok: secure-terminal/st-test: disable private vulnerability reporting'
)
for needle in "${required[@]}"; do
   if ! grep --quiet --fixed-strings -- "${needle}" <<< "${out}"; then
      printf '%s\n' "FAIL: missing expected fragment: ${needle}" >&2
      fail=1
   fi
done

## The regression itself. This exact line was emitted for PROJECT orgs
## before the policy was corrected.
forbidden=(
   'enable private vulnerability reporting'
)
for needle in "${forbidden[@]}"; do
   if grep --quiet --fixed-strings -- "${needle}" <<< "${out}"; then
      printf '%s\n' "FAIL: PVR was ENABLED on a PROJECT org: ${needle}" >&2
      fail=1
   fi
done

## Counter-check: the run must actually have walked the per-repo loop.
## Without this, an --apply that skipped every repo would satisfy the
## forbidden list by doing nothing at all.
if ! grep --quiet --fixed-strings -- 'secure-terminal/st-test' <<< "${out}"; then
   printf '%s\n' \
      'FAIL: no per-repo lines for secure-terminal/st-test; the apply loop never ran,' \
      '      so the assertions above proved nothing' >&2
   fail=1
fi

exit "${fail}"

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Mock-API test: dm-github-org-policy --apply against a SOURCE org.
##
## Companion to test_dm_apply.sh, which covers the MIRROR org. The two
## kinds take OPPOSITE Dependabot branches (agents/github-policy-org-
## kinds.md, "Dependabot lives on the mirror only"), so a suite that only
## ever applies to one of them cannot tell a working pivot from one that
## fell through the wrong way.
##
## What only this side exercises:
##   - the active-disable fan-out on both Dependabot REST switches;
##   - the _EXTRA_OK_STATUS=422 dispatcher knob (G-035): DELETE
##     /automated-security-fixes answers 422 once alerts are already off,
##     and the policy must record that as 'ok', not as a warn;
##   - the per-repo 'delete .github/dependabot.yml' skip line, the only
##     handle the policy has on version updates, which have no REST
##     setter at any scope.

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

fail=0

rc=0
out="$(ORGS_OVERRIDE='Whonix' dm-github-org-policy --apply 2>&1)" || rc=$?

if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: --apply on SOURCE org Whonix exited rc='${rc}'" >&2
   printf '%s\n' "${out}" >&2
   fail=1
fi

required=(
   ## Actions disabled org-wide: the reason Dependabot cannot stay here.
   'ok: Whonix: actions enabled_repositories=none (CI disabled org-wide)'
   'ok: Whonix/whonix-test: SOURCE: wiki=off, issues=on, secret-scan on'
   ## The 422 in brackets is the assertion, not decoration: without the
   ## _EXTRA_OK_STATUS knob this same response renders as a warn line and
   ## sets policy_warn_seen.
   'ok: Whonix/whonix-test: disable Dependabot security updates [422]'
   'ok: Whonix/whonix-test: disable Dependabot alerts [204]'
   'ok: Whonix/whonix-test: disable private vulnerability reporting'
   ## Version updates: no REST setter anywhere, so the tool can only name
   ## the file an owner has to delete.
   'skip: Whonix/whonix-test: Dependabot version updates: delete .github/dependabot.yml'
   ## Code scanning is the one UI flip that stays SOURCE-side.
   'skip: Whonix: Code scanning: recommend security-extended query suite'
)

forbidden=(
   ## MIRROR-only enable lines must never reach a SOURCE org.
   'enable Dependabot alerts'
   'enable Dependabot security updates'
   ## PVR has only a DELETE form in github-policy-data.bsh.
   'enable private vulnerability reporting'
   ## The Dependabot UI flips follow the feature to MIRROR: nothing to
   ## group, triage or delegate where there are no alerts and no
   ## security PRs.
   'Dependabot grouped security updates: enable in UI'
   'Auto-triage rule "Dismiss low-impact dev-scoped"'
   'Auto-triage rule "Dismiss package malware alerts"'
   'Prevent direct Dependabot alert dismissals'
   ## A warn on any Dependabot call means the 422 tolerance regressed.
   "'disable Dependabot security updates'"
)

for needle in "${required[@]}"; do
   if ! grep --quiet --fixed-strings -- "${needle}" <<< "${out}"; then
      printf '%s\n' "FAIL: missing expected fragment: ${needle}" >&2
      fail=1
   fi
done
for needle in "${forbidden[@]}"; do
   if grep --quiet --fixed-strings -- "${needle}" <<< "${out}"; then
      printf '%s\n' "FAIL: forbidden fragment present: ${needle}" >&2
      fail=1
   fi
done

exit "${fail}"

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## agents/github-policy-org-kinds.md
##
## The org-level ruleset upsert in apply_org_policy is PAID PLAN
## ONLY (commented out); not exercised here.

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

## --- SOURCE side: Whonix ---
rc=0
out_source="$(ORGS_OVERRIDE='Whonix' dm-github-org-policy --dry-run 2>&1)" || rc=$?

if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: --dry-run on SOURCE org Whonix exited rc='${rc}'" >&2
   printf '%s\n' "${out_source}" >&2
   fail=1
fi

source_required=(
   ## SOURCE org-level Actions/CI: disabled entirely, org-wide
   ## (enabled_repositories=none). Canonical CI runs on the org's own
   ## infra, not GitHub Actions; see
   ## agents/github-policy-org-kinds.md.
   'actions enabled_repositories=none (CI disabled org-wide)'
   ## SOURCE per-repo body: has_issues stays on, no allow_forking
   ## field at all (the body simply omits it).
   'SOURCE: wiki=off, issues=on, secret-scan on'
   ## Dependabot runs on the MIRROR org only (2026-07-31 decision):
   ## Actions is off org-wide on SOURCE, so nothing there can verify a
   ## bump PR and no alert has a build to be fixed in. SOURCE gets the
   ## active-disable fan-out on BOTH REST switches. Order matters:
   ## security updates before alerts, because the security-fixes
   ## endpoint answers 422 once alerts are already off.
   'disable Dependabot security updates'
   'disable Dependabot alerts'
   ## Third switch, no REST setter at any scope: version updates are
   ## driven purely by .github/dependabot.yml existing, so SOURCE gets
   ## a per-repo skip line naming the file to delete.
   'Dependabot version updates: delete .github/dependabot.yml'
   ## PVR is disabled on SOURCE too (wiki is canonical disclosure
   ## channel per .github/SECURITY.md).
   'disable private vulnerability reporting'
   ## UI-flip skip lines with no REST setter as of 2026-05; see
   ## agents/github-policy-org-kinds.md "UI-only operator flips".
   ## Only the code-scanning one is SOURCE-side - the Dependabot flips
   ## moved to MIRROR with the feature itself.
   'Code scanning: recommend security-extended query suite'
)
source_forbidden=(
   ## MIRROR-only Actions scope MUST NOT appear on SOURCE: SOURCE
   ## disables Actions org-wide, so neither the enabled=all scope nor
   ## the selected-actions allow-list follow-up is emitted.
   'actions enabled=all, allowed=selected'
   'selected-actions = github-owned + verified-creators'
   ## MIRROR-specific tokens MUST NOT appear when running against a
   ## SOURCE org.
   'MIRROR:'
   ## MIRROR-only Dependabot enable lines MUST NOT appear on SOURCE.
   ## These two are the regression guard for the reverted policy: they
   ## were REQUIRED here until 2026-07-31.
   'enable Dependabot alerts'
   'enable Dependabot security updates'
   ## PVR enable line MUST NOT appear anywhere (the PUT-style
   ## constant was removed - github-policy-data.bsh has only the
   ## DELETE variant).
   'enable private vulnerability reporting'
   ## The three per-repo/org Dependabot UI flips follow the feature to
   ## MIRROR: with no alerts and no security PRs on SOURCE there is
   ## nothing to group, triage or delegate here.
   'Dependabot grouped security updates: enable in UI'
   'Auto-triage rule "Dismiss low-impact dev-scoped"'
   'Auto-triage rule "Dismiss package malware alerts"'
   'Prevent direct Dependabot alert dismissals'
)
for needle in "${source_required[@]}"; do
   if ! grep --quiet --fixed-strings -- "${needle}" <<< "${out_source}"; then
      printf '%s\n' "FAIL[SOURCE]: missing expected fragment: ${needle}" >&2
      fail=1
   fi
done
for needle in "${source_forbidden[@]}"; do
   if grep --quiet --fixed-strings -- "${needle}" <<< "${out_source}"; then
      printf '%s\n' "FAIL[SOURCE]: forbidden fragment present: ${needle}" >&2
      fail=1
   fi
done

## --- MIRROR side: org-ai-assisted ---
rc=0
out_mirror="$(ORGS_OVERRIDE='org-ai-assisted' dm-github-org-policy --dry-run 2>&1)" || rc=$?

if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: --dry-run on MIRROR org org-ai-assisted exited rc='${rc}'" >&2
   printf '%s\n' "${out_mirror}" >&2
   fail=1
fi

mirror_required=(
   ## MIRROR keeps Actions/CI on, restricted to the github-owned +
   ## verified-creators allow-list - it is where AI-assisted CI runs.
   'actions enabled=all, allowed=selected'
   'selected-actions = github-owned + verified-creators'
   'MIRROR: wiki/issues/projects/discussions off, secret-scan on'
   ## MIRROR is the one kind that RUNS Dependabot: it is where GitHub
   ## Actions runs, so it is where a bump PR carries a verdict. Alerts
   ## first - PUT /automated-security-fixes requires them.
   'enable Dependabot alerts'
   'enable Dependabot security updates'
   ## PVR-OFF is the same call run on both sides.
   'disable private vulnerability reporting'
   ## The Dependabot UI flips are emitted where alerts and
   ## security-update PRs exist, i.e. MIRROR only.
   'Dependabot grouped security updates: enable in UI'
   'Auto-triage rule "Dismiss low-impact dev-scoped" must be OFF'
   'Auto-triage rule "Dismiss package malware alerts" must be OFF'
   'Prevent direct Dependabot alert dismissals (delegated dismissal): enable in UI'
)
mirror_forbidden=(
   ## SOURCE-only Actions-disabled scope MUST NOT appear on MIRROR
   ## (MIRROR keeps CI on).
   'actions enabled_repositories=none (CI disabled org-wide)'
   'SOURCE:'
   ## The active-disable fan-out is for every kind EXCEPT mirror.
   'disable Dependabot alerts'
   'disable Dependabot security updates'
   ## PVR enable MUST NOT appear anywhere; only the DELETE
   ## (disable) form exists.
   'enable private vulnerability reporting'
   ## MIRROR may carry .github/dependabot.yml (opt-in per repo via
   ## dm-packaging-helper-script), so the delete-the-file skip line
   ## must not be emitted here.
   'Dependabot version updates: delete .github/dependabot.yml'
   ## SOURCE-only UI-flip skip line MUST NOT appear on MIRROR.
   'Code scanning: recommend security-extended query suite'
)
for needle in "${mirror_required[@]}"; do
   if ! grep --quiet --fixed-strings -- "${needle}" <<< "${out_mirror}"; then
      printf '%s\n' "FAIL[MIRROR]: missing expected fragment: ${needle}" >&2
      fail=1
   fi
done
for needle in "${mirror_forbidden[@]}"; do
   if grep --quiet --fixed-strings -- "${needle}" <<< "${out_mirror}"; then
      printf '%s\n' "FAIL[MIRROR]: forbidden fragment present: ${needle}" >&2
      fail=1
   fi
done

## The two Dependabot REST switches share one dependency, in opposite
## directions, so the ORDER the two calls are emitted in is part of the
## policy and not an accident of the source layout:
##
##   disabling - security updates FIRST. DELETE /automated-security-fixes
##     answers 422 once alerts are already off, which the policy only
##     tolerates as an idempotent steady state, not as a first-run result.
##   enabling  - alerts FIRST. PUT /automated-security-fixes is rejected
##     on a repo whose alerts are still off.
##
## Substring presence alone cannot see a swap, so assert the line numbers.
## Args: $1 = side label, $2 = output, $3 = fragment that must come first,
## $4 = fragment that must come second.
assert_order() {
   local side out_text first_needle second_needle first_line second_line

   side="$1"
   out_text="$2"
   first_needle="$3"
   second_needle="$4"

   first_line="$(grep --max-count=1 --line-number --fixed-strings -- "${first_needle}" <<< "${out_text}" | cut --delimiter=':' --fields=1)"
   second_line="$(grep --max-count=1 --line-number --fixed-strings -- "${second_needle}" <<< "${out_text}" | cut --delimiter=':' --fields=1)"

   if [ -z "${first_line}" ] || [ -z "${second_line}" ]; then
      printf '%s\n' "FAIL[${side}]: order check cannot run, a fragment is missing: '${first_needle}' / '${second_needle}'" >&2
      fail=1
      return 0
   fi
   if [ "${first_line}" -ge "${second_line}" ]; then
      printf '%s\n' "FAIL[${side}]: '${first_needle}' (line ${first_line}) must be emitted before '${second_needle}' (line ${second_line})" >&2
      fail=1
   fi
}

assert_order 'SOURCE' "${out_source}" \
   'disable Dependabot security updates' 'disable Dependabot alerts'
assert_order 'MIRROR' "${out_mirror}" \
   'enable Dependabot alerts' 'enable Dependabot security updates'

exit "${fail}"

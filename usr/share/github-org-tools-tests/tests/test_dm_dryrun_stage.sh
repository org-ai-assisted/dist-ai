#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Mock-API test: dm-github-org-policy --dry-run against the newer org
## kinds, pinning that each is dispatched to the right policy.
##
##   STAGE (kicksecure-stage): Actions disabled org-wide like SOURCE,
##     per-repo body with issues off (STAGE label), Dependabot actively
##     OFF, PVR off. MUST NOT emit the MIRROR/PROJECT Actions allow-list
##     or the Dependabot ENABLE lines.
##   PROJECT (computer-security-research): the newly-registered PROJECT
##     org behaves exactly like the existing PROJECT orgs - Actions on
##     behind the allow-list, issues ON (PROJECT label), Dependabot off.
##
## Companion to test_dm_dryrun_source_vs_mirror.sh (SOURCE vs MIRROR).
## Both new orgs would make org_kind() die on the pre-registration code,
## so --dry-run would exit non-zero - this test fails on that code.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

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

## Run --dry-run against one org and check required / forbidden
## fragments. Args: $1 = org, $2 = label, then two nameref arrays
## 'required' and 'forbidden' must be set in the caller.
run_case() {
   local org label rc out needle
   org="$1"
   label="$2"

   rc=0
   out="$(ORGS_OVERRIDE="${org}" dm-github-org-policy --dry-run 2>&1)" || rc=$?
   if [ "${rc}" -ne 0 ]; then
      printf '%s\n' "FAIL[${label}]: --dry-run on '${org}' exited rc='${rc}'" >&2
      printf '%s\n' "${out}" >&2
      fail=1
   fi
   for needle in "${required[@]}"; do
      if ! grep --quiet --fixed-strings -- "${needle}" <<< "${out}"; then
         printf '%s\n' "FAIL[${label}]: missing expected fragment: ${needle}" >&2
         fail=1
      fi
   done
   for needle in "${forbidden[@]}"; do
      if grep --quiet --fixed-strings -- "${needle}" <<< "${out}"; then
         printf '%s\n' "FAIL[${label}]: forbidden fragment present: ${needle}" >&2
         fail=1
      fi
   done
}

## --- STAGE: kicksecure-stage ---
required=(
   'actions enabled_repositories=none (CI disabled org-wide)'
   'STAGE: wiki/issues/projects/discussions off, secret-scan on'
   'disable Dependabot security updates'
   'disable Dependabot alerts'
   'Dependabot version updates: delete .github/dependabot.yml'
   'disable private vulnerability reporting'
)
forbidden=(
   ## STAGE disables Actions org-wide, so the MIRROR/PROJECT scope +
   ## allow-list follow-up must not appear.
   'actions enabled=all, allowed=selected'
   'selected-actions = github-owned + verified-creators'
   ## Other kinds' per-repo labels must not leak onto STAGE.
   'MIRROR:'
   'SOURCE:'
   'PROJECT:'
   ## Dependabot runs on MIRROR only; STAGE gets the disable fan-out.
   'enable Dependabot alerts'
   'enable Dependabot security updates'
   ## MIRROR-only and SOURCE-only UI-flip skip lines.
   'Dependabot grouped security updates: enable in UI'
   'Code scanning: recommend security-extended query suite'
)
run_case 'kicksecure-stage' 'STAGE'

## --- PROJECT: computer-security-research (newly registered) ---
required=(
   'actions enabled=all, allowed=selected'
   'selected-actions = github-owned + verified-creators'
   'PROJECT: wiki/discussions off, issues on, secret-scan on'
   'disable Dependabot security updates'
   'disable Dependabot alerts'
   'disable private vulnerability reporting'
)
forbidden=(
   'actions enabled_repositories=none (CI disabled org-wide)'
   'STAGE:'
   'MIRROR:'
   'SOURCE:'
   'enable Dependabot alerts'
   'enable Dependabot security updates'
)
run_case 'computer-security-research' 'PROJECT-new'

exit "${fail}"

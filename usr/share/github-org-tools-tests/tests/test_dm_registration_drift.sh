#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit test for policy_registration_drift_report (github-policy-lib.bsh).
##
## Regression for the silent-skip gap: an org the bot can write to but
## that is in none of the *_ORGS arrays is skipped by --apply with
## nothing reporting it, which is how kicksecure-stage, whonix-stage and
## computer-security-research sat unhardened. The function compares the
## registered (writable) set against the bot's live admin orgs and names
## the mismatches; dm-github-org-policy folds each into a finding.
##
## Pure function, so this drives it directly with crafted CSV inputs - no
## fixtures, no network. It fails on pre-change code where the function
## does not exist.

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

# shellcheck disable=SC1091
source "${DEVELOPER_META_FILES_PATH:-}"/usr/libexec/developer-meta-files/github-org-lib.bsh
# shellcheck disable=SC1091
source "${DEVELOPER_META_FILES_PATH:-}"/usr/libexec/developer-meta-files/github-policy-lib.bsh

fail=0

## Normalise multi-line output to a sorted comma list so assertions do
## not depend on emission order.
sorted_csv() {
   printf '%s' "$1" | grep -v -- '^$' | sort | tr -- '\n' ',' || true
}

## Args: $1 = label, $2 = registered CSV, $3 = admin CSV,
##       $4 = expected sorted-CSV of finding lines ('' = none).
expect() {
   local label registered admin want got got_sorted want_sorted rc

   label="$1"
   registered="$2"
   admin="$3"
   want="$4"

   rc=0
   got="$(policy_registration_drift_report "${registered}" "${admin}")" || rc=$?
   if [ "${rc}" -ne 0 ]; then
      printf '%s\n' "FAIL[${label}]: function exited rc='${rc}'" >&2
      fail=1
      return
   fi
   got_sorted="$(sorted_csv "${got}")"
   want_sorted="$(printf '%s' "${want}" | tr -- ',' '\n' | grep -v -- '^$' | sort | tr -- '\n' ',' || true)"
   if [ "${got_sorted}" != "${want_sorted}" ]; then
      printf '%s\n' "FAIL[${label}]: finding mismatch" >&2
      printf '%s\n' "  expected: ${want_sorted}" >&2
      printf '%s\n' "  actual:   ${got_sorted}" >&2
      fail=1
   else
      printf '%s\n' "PASS: ${label}"
   fi
}

## Sets agree -> no findings.
expect 'in-sync set, no drift' \
   'org-ai-assisted,secure-terminal,output-lies,computer-security-research,kicksecure-stage,whonix-stage' \
   'org-ai-assisted,secure-terminal,output-lies,computer-security-research,kicksecure-stage,whonix-stage' \
   ''

## Admin of an org that no kind claims -> UNREGISTERED (the exact gap).
expect 'unregistered admin org is a finding' \
   'org-ai-assisted' \
   'org-ai-assisted,kicksecure-stage' \
   'UNREGISTERED kicksecure-stage'

## Registered but not admin -> STALE (dead registration / lost access).
expect 'stale registration is a finding' \
   'org-ai-assisted,gone-org' \
   'org-ai-assisted' \
   'STALE gone-org'

## Both directions at once.
expect 'both drift directions reported' \
   'org-ai-assisted,gone-org' \
   'org-ai-assisted,new-org' \
   'UNREGISTERED new-org,STALE gone-org'

## The three orgs this change registers must NOT be flagged once they
## are in the registered set. Admin list = the full live writable set
## (the pre-existing orgs plus the three new ones), matching the
## registered set exactly, so no finding of either kind.
expect 'the three newly-registered orgs are not drift' \
   'org-ai-assisted,secure-terminal,output-lies,computer-security-research,kicksecure-stage,whonix-stage' \
   'org-ai-assisted,secure-terminal,output-lies,computer-security-research,kicksecure-stage,whonix-stage' \
   ''

## A member-only SOURCE org (Kicksecure) is NOT in the writable
## registered set and is NOT an admin org, so it must never be reported:
## absent from both lists -> no line.
expect 'member-only SOURCE org is silent' \
   'org-ai-assisted,kicksecure-stage,whonix-stage' \
   'org-ai-assisted,kicksecure-stage,whonix-stage' \
   ''

exit "${fail}"

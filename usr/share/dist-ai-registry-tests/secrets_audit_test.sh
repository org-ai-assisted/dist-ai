#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/secrets-audit.sh, the secret-isolation guard. Presence
## booleans arrive as env (computed at workflow expression time); the secret
## values themselves never reach the script.
##
## WHY this exists: the guard's whole job is to FAIL when a secret that must be
## isolated from a secrets context (OPENAI_API_KEY, COVERITY_SCAN_TOKEN,
## COVERITY_SCAN_EMAIL) is nonetheless visible there. If any of those checks
## regressed to a warning (or was dropped), a real secret leak would pass CI
## green. Pin: each leak flag fails; a clean context passes; the CLAUDE_CODE_OAUTH_TOKEN
## absence is a warning, not a failure.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. No source tree
## is FATAL (exit 1), not a skip. No deps, no root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/ci/secrets-audit.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/secrets-audit.sh" ]; then
   printf '%s\n' 'FATAL: secrets-audit-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

audit="${repo}/ci/secrets-audit.sh"

failures=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## Clean baseline: only the AI-review key forwarded, nothing leaked.
run_audit() {
   local rc=0
   ALLOW_LOCAL=true \
   CLAUDE_OAUTH_PRESENT="${a:-true}" \
   OPENAI_PRESENT="${o:-false}" \
   COVERITY_TOKEN_PRESENT="${ct:-false}" \
   COVERITY_EMAIL_PRESENT="${ce:-false}" \
      bash -- "${audit}" >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## ---- CI guard: refuses without CI or ALLOW_LOCAL --------------------------
rc=0
env -u CI -u ALLOW_LOCAL \
   CLAUDE_OAUTH_PRESENT=true OPENAI_PRESENT=false \
   COVERITY_TOKEN_PRESENT=false COVERITY_EMAIL_PRESENT=false \
   bash -- "${audit}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -ne 1 ]; then
   fail "did not refuse outside CI without ALLOW_LOCAL (rc '${rc}', expected 1)"
fi

## ---- clean context -> exit 0 ----------------------------------------------
a=true o=false ct=false ce=false
if [ "$(run_audit)" != '0' ]; then
   fail 'a clean secrets context did not pass'
fi

## ---- OPENAI leaked -> exit 1 ----------------------------------------------
a=true o=true ct=false ce=false
if [ "$(run_audit)" != '1' ]; then
   fail 'an OPENAI_API_KEY leak did not fail the audit'
fi

## ---- COVERITY token leaked -> exit 1 --------------------------------------
a=true o=false ct=true ce=false
if [ "$(run_audit)" != '1' ]; then
   fail 'a COVERITY_SCAN_TOKEN leak did not fail the audit'
fi

## ---- COVERITY email leaked -> exit 1 --------------------------------------
a=true o=false ct=false ce=true
if [ "$(run_audit)" != '1' ]; then
   fail 'a COVERITY_SCAN_EMAIL leak did not fail the audit'
fi

## ---- CLAUDE_CODE_OAUTH_TOKEN absent is a warning, not a failure -> exit 0 ---------------
a=false o=false ct=false ce=false
if [ "$(run_audit)" != '0' ]; then
   fail 'an absent CLAUDE_CODE_OAUTH_TOKEN forward was treated as a failure (should warn)'
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "secrets-audit-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'secrets-audit-test: all checks passed'

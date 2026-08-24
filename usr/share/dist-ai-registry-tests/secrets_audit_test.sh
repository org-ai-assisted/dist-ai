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

## Run the audit; capture BOTH exit code and combined output so a check can
## assert the specific ::error::/::warning:: marker, not just the exit code (an
## exit-code-only test lets a regression of the warning/error text pass silent).
audit_rc=0
audit_out=''
run_audit() {
   audit_rc=0
   audit_out="$( ALLOW_LOCAL=true \
      CLAUDE_OAUTH_PRESENT="${a:-true}" \
      OPENAI_PRESENT="${o:-false}" \
      COVERITY_TOKEN_PRESENT="${ct:-false}" \
      COVERITY_EMAIL_PRESENT="${ce:-false}" \
      bash -- "${audit}" 2>&1 )" || audit_rc=$?
}

has_marker() {
   grep --quiet --fixed-strings -- "$1" <<< "${audit_out}"
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

## ---- clean context -> exit 0, no error, no warning ------------------------
a=true o=false ct=false ce=false
run_audit
if [ "${audit_rc}" -ne 0 ]; then
   fail 'a clean secrets context did not pass'
fi
if has_marker '::error::'; then
   fail 'a clean secrets context emitted an ::error::'
fi
if has_marker '::warning::'; then
   fail 'a clean context (AI key present) emitted the not-forwarded warning'
fi

## ---- OPENAI leaked -> exit 1 + its ::error:: ------------------------------
a=true o=true ct=false ce=false
run_audit
if [ "${audit_rc}" -ne 1 ]; then
   fail 'an OPENAI_API_KEY leak did not fail the audit'
fi
if ! has_marker '::error::OPENAI_API_KEY leaked'; then
   fail 'the OPENAI leak did not emit its ::error:: marker'
fi

## ---- COVERITY token leaked -> exit 1 + its ::error:: ----------------------
a=true o=false ct=true ce=false
run_audit
if [ "${audit_rc}" -ne 1 ]; then
   fail 'a COVERITY_SCAN_TOKEN leak did not fail the audit'
fi
if ! has_marker '::error::COVERITY_SCAN_TOKEN leaked'; then
   fail 'the COVERITY_SCAN_TOKEN leak did not emit its ::error:: marker'
fi

## ---- COVERITY email leaked -> exit 1 + its ::error:: ----------------------
a=true o=false ct=false ce=true
run_audit
if [ "${audit_rc}" -ne 1 ]; then
   fail 'a COVERITY_SCAN_EMAIL leak did not fail the audit'
fi
if ! has_marker '::error::COVERITY_SCAN_EMAIL leaked'; then
   fail 'the COVERITY_SCAN_EMAIL leak did not emit its ::error:: marker'
fi

## ---- CLAUDE_CODE_OAUTH_TOKEN absent -> exit 0 + the not-forwarded warning --
a=false o=false ct=false ce=false
run_audit
if [ "${audit_rc}" -ne 0 ]; then
   fail 'an absent CLAUDE_CODE_OAUTH_TOKEN forward was treated as a failure (should warn)'
fi
if ! has_marker '::warning::CLAUDE_CODE_OAUTH_TOKEN not forwarded'; then
   fail 'an absent AI key did not emit the not-forwarded ::warning:: (dead-check regression)'
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "secrets-audit-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'secrets-audit-test: all checks passed'

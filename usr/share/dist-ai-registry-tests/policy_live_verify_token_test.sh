#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/policy-live-verify-token.sh, which asserts the
## GHORG_AUDIT_TOKEN repo secret is present (via the TOKEN_PRESENT boolean env,
## computed at workflow expression time) before dm-github-policy --audit runs.
##
## WHY this exists: the secret VALUE never reaches the script -- only the
## boolean. If the gate accepted anything other than the literal 'true' (e.g.
## treated unset as present), a repo missing the secret would proceed to an
## audit that then fails opaquely mid-run. Pin: CI guard, absent-token fail,
## present-token pass.
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
   if [ -f "${candidate}/ci/policy-live-verify-token.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/policy-live-verify-token.sh" ]; then
   printf '%s\n' 'FATAL: policy-live-verify-token-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

verifier="${repo}/ci/policy-live-verify-token.sh"

failures=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## ---- CI guard: refuses when CI != true ------------------------------------
rc=0
CI=false TOKEN_PRESENT=true bash -- "${verifier}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -ne 1 ]; then
   fail "did not refuse outside CI (rc '${rc}', expected 1)"
fi

## ---- token absent -> exit 1 -----------------------------------------------
rc=0
CI=true TOKEN_PRESENT=false bash -- "${verifier}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -ne 1 ]; then
   fail "an absent token did not fail (rc '${rc}', expected 1)"
fi

## ---- token unset -> exit 1 (unset must not read as present) ---------------
rc=0
CI=true bash -- "${verifier}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -ne 1 ]; then
   fail "an unset TOKEN_PRESENT did not fail (rc '${rc}', expected 1)"
fi

## ---- token present -> exit 0 ----------------------------------------------
rc=0
CI=true TOKEN_PRESENT=true bash -- "${verifier}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -ne 0 ]; then
   fail "a present token did not pass (rc '${rc}', expected 0)"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "policy-live-verify-token-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'policy-live-verify-token-test: all checks passed'

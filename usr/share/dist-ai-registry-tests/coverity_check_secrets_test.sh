#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/coverity-check-secrets.sh, which fails fast with a
## clear ::error:: when a Coverity Scan secret is missing, rather than letting
## the later cov-build download fail with an opaque server error.
##
## WHY this exists: the check exists precisely to convert three separate
## opaque-later-failure modes (no token, no email, no project) into one obvious
## early one. If any of the three stopped being required, the workflow would
## proceed and fail deep in the download/submit with a message that does not
## name the real cause. Pin: CI guard, each missing secret fails, all present
## passes.
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
   if [ -f "${candidate}/ci/coverity-check-secrets.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/coverity-check-secrets.sh" ]; then
   printf '%s\n' 'FATAL: coverity-check-secrets-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

checker="${repo}/ci/coverity-check-secrets.sh"

failures=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

run_check() {
   local rc=0
   ALLOW_LOCAL=true \
   COVERITY_TOKEN="${tok-tok123}" \
   COVERITY_EMAIL="${eml-dev@example.com}" \
   COVERITY_PROJECT="${prj-org/example}" \
      bash -- "${checker}" >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## ---- CI guard: refuses without CI or ALLOW_LOCAL --------------------------
rc=0
env -u CI -u ALLOW_LOCAL \
   COVERITY_TOKEN=tok COVERITY_EMAIL=dev@example.com COVERITY_PROJECT=org/example \
   bash -- "${checker}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -ne 1 ]; then
   fail "did not refuse outside CI without ALLOW_LOCAL (rc '${rc}', expected 1)"
fi

## ---- all present -> exit 0 ------------------------------------------------
if [ "$(run_check)" != '0' ]; then
   fail 'all three secrets present did not pass'
fi

## ---- token missing -> exit 1 ----------------------------------------------
tok='' run_check_rc="$(run_check)"; unset tok
if [ "${run_check_rc}" != '1' ]; then
   fail "a missing COVERITY_TOKEN did not fail (rc '${run_check_rc}')"
fi

## ---- email missing -> exit 1 ----------------------------------------------
eml='' run_check_rc="$(run_check)"; unset eml
if [ "${run_check_rc}" != '1' ]; then
   fail "a missing COVERITY_EMAIL did not fail (rc '${run_check_rc}')"
fi

## ---- project missing -> exit 1 --------------------------------------------
prj='' run_check_rc="$(run_check)"; unset prj
if [ "${run_check_rc}" != '1' ]; then
   fail "a missing COVERITY_PROJECT did not fail (rc '${run_check_rc}')"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "coverity-check-secrets-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'coverity-check-secrets-test: all checks passed'

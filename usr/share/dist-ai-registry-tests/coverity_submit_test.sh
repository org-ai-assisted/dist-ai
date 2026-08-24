#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/coverity-submit.sh. Exercises the DRY_RUN path, which
## packs cov-int.tgz and skips the scan.coverity.com submission (so the full
## pipeline can be rehearsed without consuming the daily submission slot), plus
## the CI guard.
##
## WHY this exists: DRY_RUN must (a) still produce cov-int.tgz -- the always-
## upload artifact step depends on it -- and (b) NOT contact scan.coverity.com.
## If DRY_RUN silently started submitting, a rehearsal run would burn the one
## daily slot; if it stopped packing the tgz, the artifact upload would fail.
## The live submission itself needs a real token + network and is e2e-only; the
## packing/skip contract and the CI guard are the unit-testable surface.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. No source tree
## is FATAL (exit 1), not a skip. Needs 'tar'. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/ci/coverity-submit.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/coverity-submit.sh" ]; then
   printf '%s\n' 'FATAL: coverity-submit-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

submit="${repo}/ci/coverity-submit.sh"

if ! type -P tar >/dev/null; then
   printf '%s\n' 'FAIL: coverity-submit-test: tar not on PATH; the submitter cannot run' >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/coverity-submit-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_work_dir EXIT

failures=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## Consumer cwd with a cov-int build-output dir.
cwd="${work_dir}/consumer"
mkdir -p -- "${cwd}/cov-int"
printf '%s\n' 'placeholder build output' > "${cwd}/cov-int/build-log.txt"

## ---- DRY_RUN -> packs cov-int.tgz, skips submission, exit 0 ---------------
dry_rc=0
out="$( cd -- "${cwd}" && \
   ALLOW_LOCAL=true DRY_RUN=true \
   COVERITY_TOKEN=tok COVERITY_EMAIL=dev@example.com COVERITY_PROJECT=org/example \
   GITHUB_SHA=deadbeef GITHUB_RUN_NUMBER=7 GITHUB_REF_NAME=ai \
   bash -- "${submit}" 2>&1 )" || dry_rc=$?
if [ "${dry_rc}" -ne 0 ]; then
   fail "DRY_RUN exited '${dry_rc}', expected 0"
fi
if ! grep --quiet --fixed-strings -- 'DRY RUN' <<< "${out}"; then
   fail 'DRY_RUN did not announce itself; it may have attempted a real submission'
fi
if [ ! -f "${cwd}/cov-int.tgz" ]; then
   fail 'DRY_RUN did not pack cov-int.tgz (the artifact upload would fail)'
fi

## ---- CI guard: refuses without CI or ALLOW_LOCAL --------------------------
guard_rc=0
( cd -- "${cwd}" && env -u CI -u ALLOW_LOCAL DRY_RUN=true \
   COVERITY_TOKEN=tok COVERITY_EMAIL=dev@example.com COVERITY_PROJECT=org/example \
   bash -- "${submit}" ) >/dev/null 2>&1 || guard_rc=$?
if [ "${guard_rc}" -ne 1 ]; then
   fail "did not refuse outside CI without ALLOW_LOCAL (rc '${guard_rc}', expected 1)"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "coverity-submit-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'coverity-submit-test: all checks passed'

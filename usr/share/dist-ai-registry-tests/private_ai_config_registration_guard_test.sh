#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for check_registration() in
## usr/share/private-ai-config-tests/run-tests.sh -- the guard that fails a lane
## when the checkout holds a test file no lane runs and no exclusion accounts for.
##
## WHY this exists: the guard piped its discovered tests/ directories into
##     xargs find -type f \( -name '*.sh' -o -name '*.py' \)
## GNU find takes PATHS BEFORE the expression, so every invocation died with
## "paths must precede expression" -- into 2>/dev/null. An empty scan has nothing
## unregistered in it, so the guard returned 0 on every repo, in every lane,
## forever. It read as "every test is registered" while reading NOTHING, and 22
## private-ai-config test files accumulated in no lane: never run, never
## reported, and covered by a guard whose whole purpose was to say so.
##
## A guard that cannot fail is worse than no guard, because the green is trusted.
## So this pins the two directions: an unregistered file IS named, and a properly
## accounted-for file is NOT -- the second half being what a scan-nothing
## regression would satisfy for free.
##
## Hermetic: fake checkouts under a temp dir, no qube, no root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/usr/share/private-ai-config-tests/run-tests.sh" ] \
      && [ -d "${candidate}/debian" ]
   then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

runner="${repo}/usr/share/private-ai-config-tests/run-tests.sh"
if [ -z "${repo}" ] || [ ! -f "${runner}" ]; then
   printf '%s\n' 'private-ai-config-registration-guard-test: no dist-ai source tree (set DIST_AI_REPO); skipping.' >&2
   exit 77
fi

work_dir="$(mktemp --directory -- "${TMP}/pac-registration-guard-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   ## Our own mktemp directory. An absent safe-rm is tolerated rather than
   ## falling back to rm (never rm): a leftover temp dir must not turn a passing
   ## test red.
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_work_dir EXIT

failures=0
checks=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## Run the core lane against a fake checkout and return everything it printed.
## The lane's own registered tests are all absent there, so it exits non-zero
## either way -- what is asserted is what the GUARD said, not the lane result.
run_lane() {
   local fake
   fake="$1"
   PRIVATE_AI_CONFIG_PATH="${fake}" bash -- "${runner}" --lane core 2>&1 || true
}

## ---- an unregistered test file is named -----------------------------------
fake_orphan="${work_dir}/orphan-repo"
mkdir --parents -- "${fake_orphan}/tests"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${fake_orphan}/tests/definitely-unregistered-test.sh"

checks=$(( checks + 1 ))
out="$(run_lane "${fake_orphan}")"
case "${out}" in
   *'UNREGISTERED TEST FILE(S)'*)
      ;;
   *)
      fail "an unregistered test file was not reported at all -- the guard scanned nothing: ${out}"
      ;;
esac

checks=$(( checks + 1 ))
case "${out}" in
   *'tests/definitely-unregistered-test.sh'*)
      ;;
   *)
      fail "the guard did not NAME the unregistered file, so nobody can act on it: ${out}"
      ;;
esac

## ---- a tests/ directory outside the top level is scanned too --------------
## The scan roots are discovered rather than hardcoded precisely so a tests/ dir
## added elsewhere (claude/hooks/tests/) cannot be silently ungoverned.
fake_nested="${work_dir}/nested-repo"
mkdir --parents -- "${fake_nested}/tests" "${fake_nested}/claude/hooks/tests"
## An entry the runner's exclusion list accounts for, so it is not itself a finding.
printf '%s\n' '' > "${fake_nested}/tests/ci-status-fixtures.py"
printf '%s\n' '' > "${fake_nested}/claude/hooks/tests/orphan_nested_test.py"

checks=$(( checks + 1 ))
out="$(run_lane "${fake_nested}")"
case "${out}" in
   *'claude/hooks/tests/orphan_nested_test.py'*)
      ;;
   *)
      fail "a test file under a NON-top-level tests/ directory went unreported: ${out}"
      ;;
esac

## ---- CANARY: an accounted-for file is NOT reported ------------------------
## Without this, "reports everything" and "scans nothing then reports the wrong
## thing" both pass the checks above. This is the half that a scan-nothing
## regression cannot fake in the other direction.
fake_clean="${work_dir}/clean-repo"
mkdir --parents -- "${fake_clean}/tests"
printf '%s\n' '' > "${fake_clean}/tests/ci-status-fixtures.py"

checks=$(( checks + 1 ))
out="$(run_lane "${fake_clean}")"
case "${out}" in
   *'UNREGISTERED TEST FILE(S)'*)
      fail "canary: a file the exclusion list accounts for was reported as unregistered: ${out}"
      ;;
esac

printf '%s\n' "private-ai-config-registration-guard-test: ${checks} checks, ${failures} failed"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
exit 0

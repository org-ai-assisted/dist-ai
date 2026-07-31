#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the sanitize_echo lane of usr/bin/sanitize-string-tests.
##
## WHY this exists: sanitize_string/sanitize_echo.py is shipped by the COMPONENT
## under test, not by dist-ai, so a helper-scripts checkout older than the tool
## carries no subject for that lane. An absent subject is a SKIP; importing it
## unconditionally instead turns it into
## "ModuleNotFoundError: No module named 'sanitize_string.sanitize_echo'" and
## fails the whole suite -- a red CI run on a component whose code is fine.
##
## The opposite error is worse: a module that EXISTS but fails to import is a
## real defect, and skipping that would be a silent green. Both directions are
## asserted here.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. Exits 77
## (SKIP) without one. No root, no network.

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
   if [ -f "${candidate}/usr/bin/sanitize-string-tests" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/usr/bin/sanitize-string-tests" ]; then
   printf '%s\n' 'sanitize-echo-lane-test: no dist-ai source tree (set DIST_AI_REPO); skipping.' >&2
   exit 77
fi

suite="${repo}/usr/bin/sanitize-string-tests"

work_dir="$(mktemp --directory -- "${TMP}/sanitize-echo-lane-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   ## Our own mktemp directory. An absent safe-rm is tolerated rather than
   ## falling back to rm (never rm): a temp directory left behind must not turn
   ## a passing test red.
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

## A stand-in helper-scripts dist-packages root. The lane resolves its subject
## off PYTHONPATH, so the package needs no real code -- only the presence or
## absence of the sanitize_echo module decides the lane's verdict.
package_dir="${work_dir}/dist-packages/sanitize_string"
mkdir --parents -- "${package_dir}"
printf '%s' '' > "${package_dir}/__init__.py"

## The family lane's own subject is deliberately absent, which fixes its verdict
## at a known 2 ("sanitize-string not found"). Any other exit status is then
## attributable to the echo lane alone.
run_suite() {
   local rc

   rc=0
   PYTHONPATH="${work_dir}/dist-packages" \
      SANITIZE_STRING_BIN="${work_dir}/no-such-sanitize-string" \
      SANITIZE_ECHO_BIN="${work_dir}/no-such-sanitize-echo" \
      bash -- "${suite}" --fuzz-only --iterations 1 \
      > "${work_dir}/out.txt" 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## ---- subject absent: an absent-subject SKIP, never an import error --------
checks=$(( checks + 1 ))
absent_rc="$(run_suite)"
absent_out="$(cat -- "${work_dir}/out.txt")"

case "${absent_out}" in
   *"No module named 'sanitize_string.sanitize_echo'"*|*'Failed to import test module: sanitize_echo_test'*)
      fail "the echo lane hard-imported an absent subject: an unshipped sanitize-echo reads as a broken test suite instead of a skip. Output: ${absent_out}"
      ;;
esac

checks=$(( checks + 1 ))
case "${absent_out}" in
   *'SKIP: sanitize_echo lane'*)
      ;;
   *)
      fail 'the echo lane skipped an absent subject without saying so; a skip nobody can see in the log is a silent green'
      ;;
esac

checks=$(( checks + 1 ))
if [ "${absent_rc}" != '2' ]; then
   fail "with an absent sanitize-echo the suite exited '${absent_rc}', not the family lane's own '2' -- the skipped echo lane still decided the run"
fi

## ---- subject present but broken: a FAILURE, never a skip -----------------
## The canary for the check above. sanitize_echo.py now exists, so the lane has
## a subject, must run, and must report the resulting import failure. A probe
## widened to catch ImportError would skip here instead, and every real breakage
## inside the module would go green.
printf '%s' '' > "${package_dir}/sanitize_echo.py"

checks=$(( checks + 1 ))
present_rc="$(run_suite)"
present_out="$(cat -- "${work_dir}/out.txt")"

case "${present_out}" in
   *'SKIP: sanitize_echo lane'*)
      fail 'the echo lane skipped a subject that IS present -- a module that fails to import is a defect and must stay red'
      ;;
esac

checks=$(( checks + 1 ))
if [ "${present_rc}" = '0' ]; then
   fail 'the suite passed with a sanitize_echo module that cannot be imported'
fi

printf '%s\n' "===== summary: ${checks} checks, ${failures} failure(s) ====="
if [ "${failures}" -ne 0 ]; then
   printf '%s\n' 'FAILED: the sanitize_echo lane mishandles its subject' >&2
   exit 1
fi
printf '%s\n' 'OK: an absent sanitize-echo skips loudly, a present-but-broken one fails'
exit 0

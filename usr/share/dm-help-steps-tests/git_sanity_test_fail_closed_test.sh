#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: git_sanity_test must FAIL CLOSED when its bootstrap helpers
## cannot load, on EVERY invocation form -- including 'bash git_sanity_test' (how
## mode_submodules re-invokes it) and 'bash -c', where the '#!/bin/bash -e' shebang
## is IGNORED.
##
## THE BUG IT GUARDS: making the script source-able moved 'set -o errexit' into
## main(). Under 'bash <script>' the shebang -e does not apply, so the pre-main
## bootstrap ran with errexit OFF; a missing check_runtime.bsh left was_executed
## undefined, main() was skipped, and the script exited 0 -- reporting SUCCESS on an
## UNVERIFIED repo. The fix guards each bootstrap source with '|| exit 1'.
##
## Copy the REAL script somewhere its relative helper-scripts path does not resolve,
## run it via bash, and assert a NON-ZERO exit (never 0).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
script="${dm_checkout}/help-steps/git_sanity_test"
if [ ! -r "${script}" ]; then
   printf '%s\n' "FATAL: git_sanity_test not found at '${script}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## Isolated dir: the script computes HELPER_SCRIPTS_PATH as MYDIR/../packages/...,
## which does not exist under a fresh temp dir, so every bootstrap source fails.
work="$( mktemp --directory )"
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT
cp -- "${script}" "${work}/git_sanity_test"

## 'bash <script>' -- the shebang -e is IGNORED here (the exact fail-open vector).
out="$( bash "${work}/git_sanity_test" --mode all 2>&1 || true )"
rc=0
bash "${work}/git_sanity_test" --mode all >/dev/null 2>&1 || rc="$?"

if [ "${rc}" -ne 0 ]; then
   pass "bash <script> with unresolvable bootstrap exits non-zero (fail closed)"
else
   fail "bash <script> exited 0 on an unverified repo (fail-OPEN bootstrap)"
fi
case "${out}" in
   *"refusing to run unverified"*)
      pass "the abort names the reason (refusing to run unverified)"
      ;;
   *)
      fail "no fail-closed message; got: ${out}"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: git_sanity_test fails closed on a broken bootstrap."

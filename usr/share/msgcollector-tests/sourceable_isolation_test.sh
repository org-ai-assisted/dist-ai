#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: sourceable_test.sh must isolate its source-in-a-child-shell from the
## caller's ENVIRONMENT, so an exported shell function cannot shadow the builtins it
## relies on. An exported function named 'source' (bash imports it as BASH_FUNC_source%%
## at child startup) would make 'source "$subject"' call the FAKE instead of loading the
## real subject -- yet 'declare -F main' still passes (the fake defines main) and the
## test reports all PASS while the subject (even a poison one) is never read. A naive
## 'unset -f source' fix is itself defeatable by also exporting a no-op 'unset'. The fix
## under test is 'env -i', which clears EVERY exported function.
##
## This runs the REAL sibling sourceable_test.sh under exactly that hostile environment
## (exported 'source' + 'unset') and asserts the child was isolated: the fake 'source'
## never ran (its sentinel file was not created) AND the test kept its correct verdict.
## Self-contained; no root, no network.
## style-ok: no-has

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C
[ -v TMP ] || TMP=/tmp

here="$(dirname -- "$(readlink --canonicalize -- "$0")")"
subject_test="${here}/sourceable_test.sh"
if [ ! -x "${subject_test}" ]; then
   printf '%s\n' "FATAL: sibling sourceable_test.sh not found or not executable at ${subject_test}." >&2
   exit 1
fi

## A path the FAKE 'source' touches if (and only if) it runs. The real builtin never
## does, so an isolated child leaves it absent.
sentinel="$(mktemp -u -- "${TMP}/sourceable_isolation.XXXXXX")"
cleanup() {
   safe-rm --force -- "${sentinel}"
}
trap cleanup EXIT

## Export a booby-trapped 'source' (defines main/collector so declare -F would still
## pass, and marks that it ran) plus a no-op 'unset' (which would neuter a name-by-name
## unset fix). Both are exported into sourceable_test.sh's process, which re-exports
## them to its own child -- unless that child clears the environment (env -i). The
## functions are invoked only INDIRECTLY, via the builtins they shadow inside the child,
## so ShellCheck sees neither call site (SC2317 unreachable / SC2329 never-invoked).
case_rc=0
(
   # shellcheck disable=SC2317,SC2329
   source() { main() { :; }; collector() { :; }; touch "${SENTINEL}"; }
   # shellcheck disable=SC2317,SC2329
   unset() { :; }
   export SENTINEL="${sentinel}"
   export -f source unset
   "${subject_test}"
) >/dev/null 2>&1 || case_rc="$?"

fail=0
if [ -e "${sentinel}" ]; then
   printf '%s\n' "FAIL: an exported 'source' function shadowed the builtin in the child shell -- the real subject was never sourced, yet the test did not catch it (missing env -i isolation)." >&2
   fail=1
fi
if [ "${case_rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: sourceable_test.sh did not pass under the hostile environment (rc=${case_rc}); isolation must keep its verdict correct, not just absent." >&2
   fail=1
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED: sourceable_test.sh is not isolated from exported functions." >&2
   exit 1
fi
printf '%s\n' "OK: sourceable_test isolates its child from exported functions (an exported source/unset cannot shadow the builtins)."

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for ci/website-static-check.sh -- the browser-free, sandbox-free
## website-consistency CI lane that gates GitHub deploys. Two properties matter:
##   1. arg guards: no root, or a non-directory root, is a hard FAIL (exit 1) -- a
##      misspelled root must never let the gate pass without loading that site.
##   2. it drives BOTH static checkers (check_site.py AND check_svg_safety.py) and
##      runs each with '|| rc=1' so one invocation reports every finding and a
##      failure in EITHER reds the lane -- never short-circuits past svg-safety, and
##      never exits 0 regardless of a finding.
## Property 1 is asserted BEHAVIOURALLY (drives the real script -- cheap, no site
## checkout). Property 2 is asserted STRUCTURALLY on the shipped wrapper text: a full
## green drive needs a complete valid fixture site (every nav/footer/card invariant
## check_site enforces), disproportionate here and the same reason the sibling
## test_website_check_venv_interpreter.sh asserts structurally. The structural check
## is non-vacuous: it FAILS if a checker invocation is dropped, short-circuited, or
## the exit decision removed.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## ci/*.sh live at the REPO ROOT (usr/share/developer-meta-files-tests -> ../../..),
## reachable only from a checkout; the CI lane scripts are not installed under /usr.
repo_root="$(cd -- "${test_dir}/../../.." && pwd)"
static="${repo_root}/ci/website-static-check.sh"

if [ ! -r "${static}" ]; then
   printf '%s\n' "SKIP: ci/website-static-check.sh absent (repo-only subject, not in this tree)" >&2
   exit 77  ## style-ok: allow-skip: ci/*.sh is repo-only, absent in an installed tree
fi

## --- Property 1: arg guards (behavioural) ---
rc=0
bash "${static}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 1 ]; then
   pass "no-arg invocation is a hard FAIL (exit 1)"
else
   fail "no-arg invocation did not exit 1 (got ${rc})"
fi

rc=0
bash "${static}" /nonexistent/definitely/not/a/dir >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 1 ]; then
   pass "non-directory root is a hard FAIL (exit 1)"
else
   fail "non-directory root did not exit 1 (got ${rc})"
fi

## --- Property 2: drives both checkers, run-both, with an exit decision (structural) ---
## Each +x checker is direct-exec'd ('"${check_<x>}" "$@"') guarded by '|| rc=1' --
## direct, not through a 'python3' interpreter, so the shebang's -Bsu is honoured
## (dist-ai-style R-193).
assert_runs_checker() {
   local name tok
   name="$1"
   tok="$2"
   if awk -v t="${tok}" \
         'index($0, t) && index($0, "|| rc=1") { found = 1 } END { exit found ? 0 : 1 }' \
         "${static}"; then
      pass "drives ${name} with '|| rc=1' (run-both, no short-circuit)"
   else
      fail "does NOT drive ${name} via '\"\${check_*}\" ... || rc=1'"
   fi
}
# shellcheck disable=SC2016  # literal fixture text, not an expansion in this script
assert_runs_checker "check_site.py"       '"${check_site}" "$@"'
# shellcheck disable=SC2016  # literal fixture text, not an expansion in this script
assert_runs_checker "check_svg_safety.py" '"${check_svg}" "$@"'

# shellcheck disable=SC2016  # literal fixture text, not an expansion in this script
if grep --quiet --fixed-strings 'exit "${rc}"' "${static}"; then
   pass "exit decision is the aggregated rc"
else
   fail "wrapper does not end with 'exit \"\${rc}\"' (no aggregated exit decision)"
fi

printf '%s\n' "" "${pass_count} passed, ${fail_count} failed"
if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"

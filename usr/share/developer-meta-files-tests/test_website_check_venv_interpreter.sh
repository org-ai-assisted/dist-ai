#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for the website CI lanes: ci/website-mobile-check.sh and
## ci/website-width-check.sh install Playwright into a per-run venv, then must run
## check_mobile.py / check_width.py THROUGH that venv's interpreter. Each check
## script carries an absolute-path shebang ('#!/usr/bin/python3 -Bsu') that ignores
## $PATH, so DIRECT-EXECing the file ('"${check_mobile}" "$@"') runs the SYSTEM
## python and bypasses the venv's just-installed Playwright -- the check then exits
## 77 (browser unavailable) and the mandatory lane, which treats 77 as a setup
## failure, hard-fails. The fix invokes the check via the explicit venv interpreter
## ('"${venv_dir}/bin/python3" -Bsu "${check_mobile}" "$@"'), whose interpreter
## argument overrides the script's absolute shebang.
##
## Asserted STRUCTURALLY on the shipped wrapper text: a full drive needs a venv +
## chromium + passwordless sudo + network, disproportionate for a one-line
## invocation rule (the same call the sibling
## test_website_tests_required_check_fatal.sh makes). The check is non-vacuous: it
## FAILS on the pre-fix direct-exec (no venv-interpreter line; the check at command
## position) and passes only on the fixed invocation.

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
mobile="${repo_root}/ci/website-mobile-check.sh"
width="${repo_root}/ci/website-width-check.sh"

if [ ! -r "${mobile}" ] || [ ! -r "${width}" ]; then
   printf '%s\n' "SKIP: ci/website-*-check.sh absent (repo-only subject, not in this tree)" >&2
   exit 77  ## style-ok: allow-skip: ci/*.sh is repo-only, absent in an installed tree
fi

## The explicit venv interpreter the fixed wrappers must use.
venv_tok='"${venv_dir}/bin/python3"'

## <name> <wrapper-path> <check-var-token> <direct-exec-token>
##  present: some line runs the check THROUGH the venv interpreter.
##  absent : no line direct-execs the check (the check token at command position,
##           i.e. first on the whitespace-stripped line). index()==1 pins command
##           position, so it does not false-match the venv line (which also
##           contains the check token, but not first).
assert_wrapper() {
   local name path check_tok direct_tok
   name="$1"
   path="$2"
   check_tok="$3"
   direct_tok="$4"
   if awk -v v="${venv_tok}" -v c="${check_tok}" \
         'index($0, v) && index($0, c) { found = 1 } END { exit found ? 0 : 1 }' \
         "${path}"; then
      pass "${name} runs the check through the venv interpreter"
   else
      fail "${name} does NOT run the check through the venv interpreter (venv bypass)"
   fi
   if awk -v d="${direct_tok}" \
         '{ line = $0; sub(/^[[:space:]]+/, "", line);
            if (index(line, d) == 1) { found = 1 } }
          END { exit found ? 0 : 1 }' \
         "${path}"; then
      fail "${name} still direct-execs the check (absolute shebang bypasses the venv)"
   else
      pass "${name} does not direct-exec the check script"
   fi
}

assert_wrapper "website-mobile-check.sh" "${mobile}" '"${check_mobile}"' '"${check_mobile}" "$@"'
assert_wrapper "website-width-check.sh"  "${width}"  '"${check_width}"'  '"${check_width}" "$@"'

printf '%s\n' "" "${pass_count} passed, ${fail_count} failed"
if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"

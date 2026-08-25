#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for pre-push-static's R-130 check: a ':' only counts when it
## sits in COMMAND position, and text inside a string is not command position.
##
## THE BUG: the redirect form was matched by
##   '^([^#]*[[:space:];&|!{]|[[:space:]]*):[[:space:]]*[<>]'
## whose first alternative accepts ANY text ending in whitespace. An HTML
## message line such as
##   <td>Downloaded version         :</td>
## therefore matched -- arbitrary text, whitespace, ':', then the '<' of the
## closing tag read as a redirection. tb-updater's update-torbrowser carries
## two such lines and the gate failed the file on them, which is a wrong answer
## from the tool that decides whether code may be pushed.
##
## The rule's own comment already says the colon must sit at line start or
## after one of ';&|!{'; the regex simply did not implement that. This test
## pins both halves: the HTML line must NOT be flagged, and the real truncate
## idiom MUST still be.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.sh ; then
   printf '%s\n' "FATAL: helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source /usr/libexec/helper-scripts/has.sh

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/).
## A bare 'pre-push-static' would take the INSTALLED copy, so a developer
## editing the in-tree gate would be testing the packaged one.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${gate_test_dir}/../../bin/dist-ai-style"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/dist-ai-style'
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

fail=0

## Builds a one-file repo around a script body and returns the gate's output
## in gate_output and its exit code in gate_rc.
run_gate_on_body() {
   local name body repo base_sha

   name="$1"
   body="$2"
   repo="${test_dir}/${name}"
   mkdir --parents -- "${repo}/usr/bin"
   printf '%s\n' "${body}" >"${repo}/usr/bin/subject"
   chmod 0755 -- "${repo}/usr/bin/subject"

   ## 'core.hooksPath=/dev/null': this fixture is not testing the operator's
   ## hooks.
   git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo}"
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=test -c user.email=test@example.com \
      commit --quiet --allow-empty --message "base"
   base_sha="$(git -C "${repo}" rev-parse HEAD)"
   git -C "${repo}" -c core.hooksPath=/dev/null add --all
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=test -c user.email=test@example.com \
      commit --quiet --message "fixture"

   gate_rc=0
   gate_output="$( cd -- "${repo}" && "${GATE}" --check --range "${base_sha}" 2>&1 )" || gate_rc=$?
}

## The fixture bodies are ASSEMBLED rather than written out: a test for a lint
## rule that spelled the forbidden constructs literally would be failed by that
## very rule, and a waiver would then hide a real hit in this file.
colon=':'

fixture_prologue=(
   '#!/bin/bash'
   ''
   'set -o errexit'
   'set -o nounset'
   'set -o pipefail'
   'set -o errtrace'
   'shopt -s inherit_errexit'
   'shopt -s shift_verbose'
   'export LC_ALL=C'
   ''
)

body_of() {
   printf '%s\n' "${fixture_prologue[@]}" "$@"
}

## A ':' inside a string, followed by the '<' of an HTML closing tag. This is
## the shape that produced the wrong answer.
html_body="$(body_of \
   "message=\"<table><tr><td>Downloaded version         ${colon}</td><td><tt> <code>x</code></tt></td></tr></table>\"" \
   'true "${message}"')"

run_gate_on_body html "${html_body}"
if printf '%s\n' "${gate_output}" | grep --fixed-strings -- "R-130" >/dev/null; then
   printf '%s\n' "FAIL: R-130 flagged a '${colon}' inside an HTML string"
   printf '%s\n' "${gate_output}" | grep --fixed-strings -- 'R-130' | head -2
   fail=1
else
   printf '%s\n' "PASS: a '${colon}' inside a string is not command position"
fi
if [ "${gate_rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: the gate did not pass on a compliant fixture (rc=${gate_rc})"
   printf '%s\n' "${gate_output}" | tail -5
   fail=1
else
   printf '%s\n' "PASS: gate green on the compliant fixture"
fi

## The real truncate idiom must still be caught, or the fix above would have
## bought a green gate by switching the rule off.
truncate_body="$(body_of \
   'target="$1"' \
   "${colon} > \"\${target}\"")"

run_gate_on_body truncate "${truncate_body}"
if printf '%s\n' "${gate_output}" | grep --fixed-strings -- "R-130" >/dev/null; then
   printf '%s\n' "PASS: the truncate idiom is still flagged"
else
   printf '%s\n' "FAIL: the truncate idiom was NOT flagged"
   fail=1
fi

## And so must the form that follows a command separator, which is the one the
## rule's own comment names.
separator_body="$(body_of \
   'target="$1"' \
   "if ! ${colon} > \"\${target}\"; then" \
   '   true "unwritable"' \
   'fi')"

run_gate_on_body separator "${separator_body}"
if printf '%s\n' "${gate_output}" | grep --fixed-strings -- "R-130" >/dev/null; then
   printf '%s\n' "PASS: a null command after a command separator is still flagged"
else
   printf '%s\n' "FAIL: a null command after a command separator was NOT flagged"
   fail=1
fi

## The bare form on its own line is the other half of R-130 and is untouched by
## this change; pinned so a future edit to the regex cannot drop it silently.
bare_body="$(body_of \
   'if [ -n "$1" ]; then' \
   "   ${colon}" \
   'fi')"

run_gate_on_body bare "${bare_body}"
if printf '%s\n' "${gate_output}" | grep --fixed-strings -- "R-130" >/dev/null; then
   printf '%s\n' "PASS: the bare form on its own line is still flagged"
else
   printf '%s\n' "FAIL: the bare form on its own line was NOT flagged"
   fail=1
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"

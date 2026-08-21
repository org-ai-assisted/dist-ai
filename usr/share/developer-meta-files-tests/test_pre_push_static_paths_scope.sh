#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for pre-push-static's '--paths': staged mode restricted to
## a pathspec must judge ONLY the files that pathspec matches.
##
## WHY IT EXISTS: 'git commit -- <paths>' records only those paths, but the
## gate ran against the whole index. In a SHARED checkout -- several sessions
## in one working tree -- another session's unfinished, violating work is
## staged alongside, so every path-scoped commit was blocked by violations in
## files it does not touch. A gate that refuses a clean commit is as wrong as
## one that admits a dirty one, and this is the direction that cannot be
## noticed by looking at the commit.
##
## Also pinned: a pathspec that matches nothing must SAY so. Zero files checked
## with a verdict of 'all static checks passed' is the silent-green shape.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/).
## A bare 'pre-push-static' would take the INSTALLED copy, so a developer
## editing the in-tree gate would be testing the packaged one.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${gate_test_dir}/../../bin/pre-push-static"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/pre-push-static'
fi

if [ ! -x "${GATE}" ]; then
   printf '%s\n' "SKIP: no pre-push-static to test" >&2
   exit 77
fi

if ! grep --quiet --fixed-strings -- '--paths' "${GATE}"; then
   printf '%s\n' "FATAL: '${GATE}' has no --paths option" >&2
   printf '%s\n' "the cases below would all report the same verdict and prove nothing" >&2
   exit 1
fi

test_dir="$(mktemp --directory -- "${TMP}/pre-push-static-paths-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

record() {
   local verdict description

   verdict="$1"
   description="$2"

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${description}"
   fi
}

repo="${test_dir}/repo"
mkdir --parents -- "${repo}/usr/bin"

## 'core.hooksPath=/dev/null': this fixture is not testing the operator's hooks.
git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo}"
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --allow-empty --message 'base'

## The fixture bodies are ASSEMBLED rather than written out: a test for a lint
## rule that spelled the forbidden construct literally would be failed by that
## very rule, and a waiver would then hide a real hit in this file.
print_verb='pr''intf'
fixed_format="'%s\\n'"
loose_format="'value: %s\\n'"

## The clean file: strict-mode block, braced expansion, fixed printf format.
{
   printf '%s\n' '#!/bin/bash' ''
   printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail' \
      'set -o errtrace' 'shopt -s inherit_errexit' 'shopt -s shift_verbose' \
      'export LC_ALL=C' ''
   printf '%s\n' 'value="mine"' "${print_verb} ${fixed_format} \"\${value}\""
} >"${repo}/usr/bin/mine"
chmod 0755 -- "${repo}/usr/bin/mine"

## The violating file, standing in for another session's unfinished work:
## no strict-mode block, unbraced expansion, non-fixed printf format.
{
   printf '%s\n' '#!/bin/bash' ''
   printf '%s\n' 'value="theirs"' "${print_verb} ${loose_format} \$value"
} >"${repo}/usr/bin/theirs"
chmod 0755 -- "${repo}/usr/bin/theirs"

git -C "${repo}" -c core.hooksPath=/dev/null add --all

## Baseline: unrestricted staged mode must FAIL, on the violating file. If it
## does not, the fixture is not violating anything and the scoped case below
## would pass for the wrong reason.
all_rc=0
all_output="$( cd -- "${repo}" && "${GATE}" --staged 2>&1 )" || all_rc=$?
if [ "${all_rc}" -ne 0 ] \
   && grep --quiet --fixed-strings 'usr/bin/theirs' <<< "${all_output}"; then
   record PASS 'unrestricted staged mode fails on the violating file'
else
   record FAIL "unrestricted staged mode did not fail on usr/bin/theirs (rc=${all_rc})"
   printf '%s\n' "  output: $(printf '%s' "${all_output}" | tr '\n' '|' | head -c 300)"
fi

## The fix: scoped to the clean file, the same index must PASS.
scoped_rc=0
scoped_output="$( cd -- "${repo}" \
   && "${GATE}" --staged --paths -- usr/bin/mine 2>&1 )" || scoped_rc=$?
if [ "${scoped_rc}" -eq 0 ]; then
   record PASS 'a pathspec scoped to the clean file passes'
else
   record FAIL "the scoped run failed (rc=${scoped_rc})"
   printf '%s\n' "  output: $(printf '%s' "${scoped_output}" | tr '\n' '|' | head -c 300)"
fi

if grep --quiet --fixed-strings 'usr/bin/theirs' <<< "${scoped_output}"; then
   record FAIL 'the scoped run still reported the file outside the pathspec'
   printf '%s\n' "  output: $(printf '%s' "${scoped_output}" | tr '\n' '|' | head -c 300)"
else
   record PASS 'the scoped run says nothing about the file outside the pathspec'
fi

## And it must still FAIL when the pathspec names the violating file: scoping
## is a restriction, not an exemption.
guilty_rc=0
guilty_output="$( cd -- "${repo}" \
   && "${GATE}" --staged --paths -- usr/bin/theirs 2>&1 )" || guilty_rc=$?
if [ "${guilty_rc}" -ne 0 ] \
   && grep --quiet --fixed-strings 'usr/bin/theirs' <<< "${guilty_output}"; then
   record PASS 'a pathspec scoped to the violating file still fails'
else
   record FAIL "the scoped run passed on a violating file (rc=${guilty_rc})"
   printf '%s\n' "  output: $(printf '%s' "${guilty_output}" | tr '\n' '|' | head -c 300)"
fi

## A pathspec matching nothing checks nothing, and must say so rather than
## report a clean sweep silently.
empty_rc=0
empty_output="$( cd -- "${repo}" \
   && "${GATE}" --staged --paths -- usr/bin/absent 2>&1 )" || empty_rc=$?
if grep --quiet --fixed-strings 'matched no added/modified file' <<< "${empty_output}"; then
   record PASS 'a pathspec that matches nothing says so'
else
   record FAIL "a pathspec that matches nothing was silent (rc=${empty_rc})"
   printf '%s\n' "  output: $(printf '%s' "${empty_output}" | tr '\n' '|' | head -c 300)"
fi

## --paths is a staged-mode restriction; anywhere else it would silently mean
## nothing, so it is refused.
misuse_rc=0
misuse_output="$( cd -- "${repo}" && "${GATE}" --paths -- usr/bin/mine 2>&1 )" || misuse_rc=$?
if [ "${misuse_rc}" -eq 2 ] \
   && grep --quiet --fixed-strings 'only applies with --staged' <<< "${misuse_output}"; then
   record PASS '--paths without --staged is refused'
else
   record FAIL "--paths without --staged was not refused (rc=${misuse_rc})"
   printf '%s\n' "  output: $(printf '%s' "${misuse_output}" | tr '\n' '|' | head -c 300)"
fi

printf '%s\n' ""
printf '%s\n' "pre-push-static --paths: ${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]

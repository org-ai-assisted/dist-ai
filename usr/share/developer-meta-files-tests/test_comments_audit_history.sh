#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for the comments-audit HISTORY heuristic: assert it FLAGS a
## comment narrating what the code used to do, and SPARES the phrasings that read
## like history but describe present state or purpose. It drives the real, shipped
## comments-audit as a subprocess, so it exercises the actual patterns rather than
## a private copy of them.
##
## The spare-cases matter more than the flag-cases here. A heuristic that fires on
## "is used to X" or "previously-cached" is noise, and noise is what makes an
## advisory get ignored.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## Fail closed. A missing prerequisite is an environment defect: skipping on
## it reports green while the test never ran, which is worse than no test.
assert_prerequisite() {
   local description

   description="$1"
   shift

   if ! "$@"; then
      printf '%s\n' "FATAL: test_comments_audit_history: ${description}" >&2
      exit 1
   fi
}

assert_prerequisite \
   'helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)' \
   test -r '/usr/libexec/helper-scripts/has.sh'
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source /usr/libexec/helper-scripts/has.sh

assert_prerequisite 'safe-rm not found' has safe-rm

## Prefer the installed binary; fall back to the checkout this test ships in.
audit_bin=''
if has comments-audit; then
   audit_bin='comments-audit'
else
   script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
   candidate="${script_dir}/../../bin/comments-audit"
   if [ -x "${candidate}" ]; then
      audit_bin="${candidate}"
   fi
fi
assert_prerequisite \
   'comments-audit not found, neither installed nor in the shipping checkout' \
   test -n "${audit_bin}"

work_dir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

fail=0

## $1 = expectation (flag|spare), $2 = comment body
check() {
   local want="$1" comment="$2" sample got
   sample="${work_dir}/sample.sh"
   printf '## %s\nx=1\n' "${comment}" > "${sample}"
   if "${audit_bin}" --files "${sample}" 2>&1 | grep --quiet 'HISTORY'; then
      got='flag'
   else
      got='spare'
   fi
   if [ "${got}" = "${want}" ]; then
      printf 'PASS %-5s %s\n' "${want}" "${comment}"
   else
      printf 'FAIL want=%s got=%s -- %s\n' "${want}" "${got}" "${comment}" >&2
      fail=1
   fi
}

## Narrating a past state of the code.
check flag 'formerly used a regex here'
check flag 'this replaces the HTML scraper'
check flag 'was broken on trixie'
check flag 'moved from usr/bin'
check flag 'previously we scraped the month page'
check flag 'the old implementation walked the months'
check flag 'changed from tabs to spaces'
check flag 'the nested cases used to retry regardless of the seed'

## Present state or purpose, wearing similar words.
check spare 'ccc cannot be used to slip a flood past the cap'
check spare 'Used to drive the command exit code.'
check spare 'this is used to deal with the toml quirk'
check spare 'previously-cached debs are seeded before install'
check spare 'the previously-focused tab is the one shown'
check spare 'Reject an old-format file: the parser only accepts v2.'
check spare 'Replace the placeholder at runtime.'
check spare 'The value is changed to uppercase before hashing.'
check spare 'Use the previous element of the array as the anchor.'
check spare 'no longer than 255 bytes'

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' 'test_comments_audit_history: FAILED' >&2
   exit 1
fi
printf '%s\n' 'test_comments_audit_history: all cases passed'

#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins one regression in the developer-meta-files-tests entrypoint: it must NOT
## skip the WHOLE suite just because DMF_REPO is unset.
##
## Only test_dm_review_branch.sh has its subject in the developer-meta-files
## checkout. The rest drive tools dist-ai ships itself -- including the
## pre-push-static tests that guard dist-ai's own push gate. A blanket
## 'DMF_REPO unset -> exit 77' meant a bare run reported success while running
## nothing at all.
##
## Asserted STATICALLY, by reading the entrypoint: invoking it would re-enter
## this very directory's test glob and recurse.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_script="$(readlink --canonicalize -- "${BASH_SOURCE[0]}")"
test_dir="${test_script%/*}"

## Installed layout is /usr/share/...; from a checkout the entrypoint sits at
## ../../bin relative to this file.
runner="${test_dir}/../../bin/developer-meta-files-tests"
if [ ! -r "${runner}" ]; then
   runner='/usr/bin/developer-meta-files-tests'
fi

if [ ! -r "${runner}" ]; then
   printf '%s\n' "FATAL: test_dmf_runner_no_blanket_skip: entrypoint not found" >&2
   exit 1
fi

failures=0
review_rc=0

## The defect shape: a bare '-z "${DMF_REPO:-}"' test whose body exits 77.
## Read the guard body rather than the whole file, so an unrelated 'exit 77'
## elsewhere neither hides nor fakes the regression.
guard_body="$(sed -n '/^if \[ -z "${DMF_REPO:-}" \]; then/,/^fi$/p' -- "${runner}")"

if [ -z "${guard_body}" ]; then
   printf 'PASS: entrypoint has no blanket "DMF_REPO unset" guard\n'
else
   if printf '%s\n' "${guard_body}" | grep --quiet --extended-regexp '^[[:space:]]*exit 77[[:space:]]*$'; then
      printf 'FAIL: entrypoint skips the whole suite when DMF_REPO is unset\n' >&2
      printf '%s\n' "${guard_body}" >&2
      failures=$((failures + 1))
   else
      printf 'PASS: the "DMF_REPO unset" guard does not skip the suite\n'
   fi
fi

## The absent-subject skip belongs to the one test whose subject really is in
## the developer-meta-files checkout, so that path must stay a 77.
review_test="${test_dir}/test_dm_review_branch.sh"
if [ ! -r "${review_test}" ]; then
   printf 'FAIL: test_dm_review_branch.sh not found next to this test\n' >&2
   failures=$((failures + 1))
else
   ## Executed, not grepped: an 'exit 77' ANYWHERE in the file would satisfy a
   ## static match without proving the DMF_REPO-unset path returns it. Running
   ## this ONE test does not recurse -- only invoking the entrypoint would, and
   ## with DMF_REPO unset it returns at the top before doing any work.
   review_rc=0
   env --unset=DMF_REPO -- "${review_test}" >/dev/null 2>&1 || review_rc="$?"
   if [ "${review_rc}" -eq 77 ]; then
      printf 'PASS: test_dm_review_branch self-skips (77) on an absent subject\n'
   else
      printf 'FAIL: test_dm_review_branch exited %s, expected 77, with DMF_REPO unset\n' \
         "${review_rc}" >&2
      failures=$((failures + 1))
   fi
fi

if [ "${failures}" -gt 0 ]; then
   printf 'test_dmf_runner_no_blanket_skip: %s assertion(s) FAILED.\n' "${failures}" >&2
   exit 1
fi
printf 'test_dmf_runner_no_blanket_skip: OK\n'

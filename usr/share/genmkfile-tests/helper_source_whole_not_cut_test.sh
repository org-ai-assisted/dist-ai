#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Suite guard: forbid the sed/awk "function body cut" anti-pattern in the
## genmkfile-tests suite. A single-function cut of make-helper-one.bsh (e.g.
## sed -n '/^foo()/,/^}/p' -- "${helper_file}") drops any sibling the extracted
## function newly starts to call, so the test aborts with 'command not found' /
## 'unbound variable' the day the subject gains an intra-file dependency -- a
## latent, version-skewed CI red (the exact class that broke the two debinstfile
## tests when the SBOM refactor added make_pkgfiles_multi_package). dist-ai's
## CLAUDE.md mandates sourcing the whole sourced-only helper instead. This gate
## makes that the enforced default rather than a rule each author must recall:
## reintroducing a cut turns this case red immediately, in the same suite.
##
## Static lint over the suite's OWN files -- its inputs are always present, so it
## never skips; there is no genmkfile checkout to wire.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
self_base="$(basename -- "${BASH_SOURCE[0]}")"

## A sed/awk invocation (word-bounded, so 'parsed' etc. do not match) that also
## references the helper file on the SAME non-comment line -- i.e. slicing the
## helper rather than sourcing it whole -- plus the named extractor helper. Honest
## about scope (no bash parsing): a slice always names the helper on its own line
## in this suite, which is what this catches.
cut_pattern='(^|[^[:alnum:]_])(sed|awk)[^[:alnum:]_].*helper_file|extract_bash_function'

shopt -s nullglob
tests_total=0
tests_failed=0

for test_script in "${script_dir}"/*_test.sh; do
   base="$(basename -- "${test_script}")"
   ## Do not scan this guard itself: it necessarily names the pattern.
   [ "${base}" = "${self_base}" ] && continue
   tests_total=$(( tests_total + 1 ))
   hits=''
   ## Drop full-line comments before matching, so the prose that documents the
   ## anti-pattern in a converted test is not mistaken for the anti-pattern.
   hits="$(grep -nvE '^[[:space:]]*#' -- "${test_script}" \
      | grep -E "${cut_pattern}" || true)"
   if [ -z "${hits}" ]; then
      printf '%s\n' "PASS  ${base}: sources the helper whole (no function-body cut)"
   else
      tests_failed=$(( tests_failed + 1 ))
      printf '%s\n' "FAIL  ${base}: slices make-helper-one.bsh instead of sourcing it whole:" >&2
      printf '%s\n' "${hits}" | sed 's/^/        /' >&2
   fi
done

if [ "${tests_total}" -eq 0 ]; then
   printf '%s\n' "ERROR: no sibling *_test.sh found to lint in ${script_dir}" >&2
   exit 1
fi

printf '%s\n' "" "${tests_total} test(s), ${tests_failed} failed"
if [ "${tests_failed}" -ne 0 ]; then
   exit 1
fi
exit 0

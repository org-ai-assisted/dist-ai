#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Suite guard: forbid slicing a FUNCTION or VARIABLE DEFINITION out of
## make-helper-one.bsh to source/run it (the "function body cut" anti-pattern).
## Such a cut drops any sibling the extracted definition newly starts to call, so
## the test aborts with 'command not found' / 'unbound variable' the day the
## subject gains an intra-file dependency -- a latent, version-skewed CI red (the
## exact class that broke the two debinstfile tests when the SBOM refactor added
## make_pkgfiles_multi_package). dist-ai's CLAUDE.md mandates sourcing the whole
## sourced-only helper instead. This gate makes that the enforced default rather
## than a rule each author must recall: reintroducing a cut turns this case red
## immediately, in the same suite.
##
## Signal: the sed/awk RANGE-START ADDRESS that selects a definition, anchored at
## column 0 -- '/^name(', '/^name()', '/^name {' or '/^name=('. Keying on the
## address (not on the tool name plus the filename) is what makes this robust:
##   - it fires no matter how the command is split across lines (a shfmt-wrapped
##     `sed ... -- \` / `"${helper_file}"`, or a multi-line `awk '/^name()/,/^}/'`),
##     because the harmful address always sits on ONE line regardless of the split;
##   - it does NOT fire on a legitimate static-text assertion that extracts a
##     non-definition range (cowbuilder_tmpdir_test.sh reads the cowbuilder
##     INVOCATION, address '/make_log_and_run/,/--buildresult/', and never sources
##     it) -- which a blanket "sed/awk over helper_file" ban would wrongly flag.
## Scope boundary (per dist-ai's never-build-a-bash-parser rule): matches the
## `name()` definition spelling this suite actually uses; a crafted `name ()` with
## a space, or a `function name {` form, is out of scope -- an author reintroducing
## the anti-pattern copies the existing spelling, and a crafted evasion is not the
## accident this gate exists to catch.
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

## The range-START address of a definition cut, or the named extractor helper.
## '\^' is a literal caret (the sed/awk anchor); the definition follows as an
## identifier then '(' (optionally awk-escaped '\('), '=(' (an array), or '{'.
cut_pattern='/\^[A-Za-z_][A-Za-z0-9_]*(\\?\(|=\(|[[:space:]]*\{)|extract_bash_function'

shopt -s nullglob
tests_total=0
tests_failed=0

for test_script in "${script_dir}"/*_test.sh; do
   base="$(basename -- "${test_script}")"
   ## Do not scan this guard itself: it necessarily names the pattern.
   [ "${base}" = "${self_base}" ] && continue
   tests_total=$(( tests_total + 1 ))

   ## Drop full-line comments first (so prose documenting the anti-pattern is not
   ## mistaken for it), keeping original line numbers via grep -n. A grep rc of 1
   ## means "file is all comments/empty" (fine); rc > 1 is a real read error and
   ## must fail loud rather than be masked into a false PASS.
   grep_rc=0
   noncomment="$(grep -nvE '^[[:space:]]*#' -- "${test_script}")" || grep_rc=$?
   if [ "${grep_rc}" -gt 1 ]; then
      printf '%s\n' "ERROR: grep failed reading ${base} (rc ${grep_rc})" >&2
      exit 1
   fi

   hits=''
   if [ "${grep_rc}" -eq 0 ]; then
      match_rc=0
      hits="$(printf '%s\n' "${noncomment}" | grep -E "${cut_pattern}")" || match_rc=$?
      if [ "${match_rc}" -gt 1 ]; then
         printf '%s\n' "ERROR: grep failed matching ${base} (rc ${match_rc})" >&2
         exit 1
      fi
   fi

   if [ -z "${hits}" ]; then
      printf '%s\n' "PASS  ${base}: sources the helper whole (no definition cut)"
   else
      tests_failed=$(( tests_failed + 1 ))
      printf '%s\n' "FAIL  ${base}: slices a definition out of make-helper-one.bsh instead of sourcing it whole:" >&2
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
